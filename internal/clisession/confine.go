package clisession

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

// Jail paths for a CLI proxy. The socket file inside ProxyDir is proxy.sock.
const (
	cliPreloadJail   = "/lgb-proxy/preload.so"
	cliProxySockJail = "/lgb-proxy/run/proxy.sock"
)

// launch is one confined CLI process.
type launch struct {
	Policy policy.Policy
	Dial   func(context.Context, string, string) (net.Conn, error)
	// NetLog receives each allowlist decision. Nil discards it.
	NetLog func(sandbox.Event)
	// BindLog receives each read-only CLI bind after the jail command is built.
	BindLog func(sandbox.Event)
}

// confinePlan is the network and extra environment for one CLI jail.
type confinePlan struct {
	UnshareNet bool
	PreloadSrc string
	ProxyDir   string
	ProxySock  string
	ExtraEnv   []string
	ROBinds    []string
}

func (l launch) command(ctx context.Context, bin string, args []string, workspace string) (*exec.Cmd, func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	plan, cleanup, err := prepareCLINet(ctx, l.Policy, l.Dial, l.NetLog)
	if err != nil {
		return nil, nil, err
	}
	cmd, extra, err := applyLaunch(bin, args, workspace, plan)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	if l.BindLog != nil {
		for _, path := range plan.ROBinds {
			l.BindLog(sandbox.Event{
				Kind:   "grant_use",
				Grant:  "cli_ro_bind",
				Detail: filepath.Clean(path) + " read-only",
			})
		}
	}
	return cmd, func() {
		if extra != nil {
			extra()
		}
		cleanup()
	}, nil
}

func prepareCLINet(ctx context.Context, pol policy.Policy, dial func(context.Context, string, string) (net.Conn, error), onEvent func(sandbox.Event)) (confinePlan, func(), error) {
	extra, err := pol.ExtraEnv(os.LookupEnv)
	if err != nil {
		return confinePlan{}, nil, err
	}
	mode := strings.ToLower(strings.TrimSpace(pol.CLINetwork))
	if mode == "" {
		mode = policy.NetOpen
	}
	plan := confinePlan{ExtraEnv: extra, ROBinds: append([]string{}, pol.CLIROBinds...)}
	noop := func() {}
	switch mode {
	case policy.NetOpen:
		return plan, noop, nil
	case policy.NetNone:
		plan.UnshareNet = true
		return plan, noop, nil
	case policy.NetProxy, policy.NetExplicit:
		if mode == policy.NetExplicit && strings.TrimSpace(pol.HTTPProxy) == "" && strings.TrimSpace(pol.HTTPSProxy) == "" {
			return confinePlan{}, nil, fmt.Errorf("explicit-proxy requires http_proxy or https_proxy")
		}
		dir, err := os.MkdirTemp("", "lgb-cli-proxy-")
		if err != nil {
			return confinePlan{}, nil, err
		}
		preload, sock, closeProxy, err := sandbox.OpenCLIProxy(ctx, dir, pol.CLINetAllow, dial, sandbox.Upstream{
			HTTPProxy:  pol.HTTPProxy,
			HTTPSProxy: pol.HTTPSProxy,
			NoProxy:    pol.NoProxy,
		}, onEvent)
		if err != nil {
			_ = os.RemoveAll(dir)
			return confinePlan{}, nil, err
		}
		plan.UnshareNet = true
		plan.PreloadSrc = preload
		plan.ProxyDir = dir
		plan.ProxySock = sock
		return plan, func() {
			closeProxy()
			_ = os.RemoveAll(dir)
		}, nil
	default:
		return confinePlan{}, nil, fmt.Errorf("cli network %q is not supported", mode)
	}
}

// cliHome is the only home directory inside the CLI jail.
const cliHome = "/lgb-home"

// confineArgs builds the bwrap argv after argv0 for the default open network.
func confineArgs(bin string, args []string, workspace string) ([]string, error) {
	return confineArgsPlan(bin, args, workspace, confinePlan{})
}

// confineArgsPlan builds the bwrap argv after argv0.
func confineArgsPlan(bin string, args []string, workspace string, plan confinePlan) ([]string, error) {
	ws, home, err := absWorkspace(workspace)
	if err != nil {
		return nil, err
	}
	absBin, err := filepath.Abs(bin)
	if err != nil {
		return nil, err
	}
	argv0, extra, err := placeBinary(absBin, ws, home)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var b []string
	b = append(b, "--unshare-user")
	if plan.UnshareNet {
		b = append(b, "--unshare-net")
	}
	b = append(b, "--unshare-pid", "--die-with-parent", "--clearenv",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/bin", "/bin",
		"--ro-bind", "/lib", "/lib",
	)
	seen["/usr"] = true
	seen["/bin"] = true
	seen["/lib"] = true
	if dirExists("/lib64") {
		b = append(b, "--ro-bind", "/lib64", "/lib64")
		seen["/lib64"] = true
	}
	b = append(b, "--dir", "/etc", "--tmpfs", "/tmp", "--proc", "/proc", "--dev", "/dev")
	seen["/etc"] = true
	seen["/tmp"] = true
	seen["/proc"] = true
	seen["/dev"] = true

	b = appendEtc(b, seen)
	b = append(b, "--dir", cliHome)
	seen[cliHome] = true
	b = appendCLIState(b, seen, home)
	b, err = appendCLIROBinds(b, seen, plan.ROBinds)
	if err != nil {
		return nil, err
	}

	b = appendParents(b, seen, ws)
	b = append(b, "--bind", ws, ws, "--chdir", ws)

	for _, m := range extra {
		b = appendParents(b, seen, m.dst)
		flag := "--ro-bind"
		if !m.ro {
			flag = "--bind"
		}
		b = append(b, flag, m.src, m.dst)
	}
	if plan.PreloadSrc != "" {
		if plan.ProxyDir == "" {
			return nil, fmt.Errorf("cli network proxy socket is missing")
		}
		b = appendParents(b, seen, "/lgb-proxy/run")
		b = append(b, "--bind", plan.ProxyDir, "/lgb-proxy/run")
		seen["/lgb-proxy/run"] = true
		b = append(b, "--ro-bind", plan.PreloadSrc, cliPreloadJail)
	}

	b = append(b, "--setenv", "PATH", cliPATH(), "--setenv", "HOME", cliHome)
	if name := currentName(); name != "" {
		b = append(b, "--setenv", "USER", name, "--setenv", "LOGNAME", name)
	}
	for _, key := range []string{"LANG", "LC_ALL", "TERM", "TZ"} {
		b = appendLocale(b, key)
	}
	for _, entry := range plan.ExtraEnv {
		key, val, ok := strings.Cut(entry, "=")
		if !ok || policy.BlockedEnv(key) {
			return nil, fmt.Errorf("env %s is not permitted", key)
		}
		b = append(b, "--setenv", key, val)
	}
	if plan.PreloadSrc != "" {
		b = append(b,
			"--setenv", "LD_PRELOAD", cliPreloadJail,
			"--setenv", "LGB_PROXY_SOCK", cliProxySockJail,
		)
	}
	b = append(b, "--", argv0)
	b = append(b, args...)
	return b, nil
}

// absWorkspace checks the CLI working directory. home is empty when it
// cannot be resolved. The workspace must not be / and must not contain home.
func absWorkspace(workspace string) (string, string, error) {
	ws, err := filepath.Abs(workspace)
	if err != nil || strings.TrimSpace(workspace) == "" {
		return "", "", fmt.Errorf("cli workspace is required")
	}
	if ws == "/" {
		return "", "", fmt.Errorf("cli workspace must not be /")
	}
	st, err := os.Stat(ws)
	if err != nil {
		return "", "", fmt.Errorf("cli workspace: %w", err)
	}
	if !st.IsDir() {
		return "", "", fmt.Errorf("cli workspace is not a directory")
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		home, _ = filepath.Abs(home)
	}
	if home != "" && (ws == home || inside(home, ws)) {
		return "", "", fmt.Errorf("cli workspace must not contain the home directory")
	}
	return ws, home, nil
}

type bindMount struct {
	src string
	dst string
	ro  bool
}

func placeBinary(bin, workspace, home string) (string, []bindMount, error) {
	real := bin
	if resolved, err := filepath.EvalSymlinks(bin); err == nil {
		real = resolved
	}
	if inside(bin, workspace) || inside(real, workspace) {
		return bin, nil, nil
	}
	if home != "" {
		for _, sub := range []string{".grok", ".claude"} {
			root := filepath.Join(home, sub)
			if inside(bin, root) || inside(real, root) {
				rel, relErr := filepath.Rel(home, bin)
				if relErr != nil || strings.HasPrefix(rel, "..") {
					rel, relErr = filepath.Rel(home, real)
				}
				if relErr != nil || strings.HasPrefix(rel, "..") {
					return "", nil, fmt.Errorf("cli binary %s is outside its login directory", bin)
				}
				argv0 := filepath.Join(cliHome, rel)
				var extra []bindMount
				if !binaryCovered(real, workspace) && !inside(real, root) {
					extra = append(extra, bindMount{src: filepath.Dir(real), dst: filepath.Dir(real), ro: true})
				}
				return argv0, extra, nil
			}
		}
	}
	if binaryCovered(real, workspace) {
		return real, nil, nil
	}
	dir := filepath.Dir(real)
	return real, []bindMount{{src: dir, dst: dir, ro: true}}, nil
}

func binaryCovered(path, workspace string) bool {
	if inside(path, workspace) {
		return true
	}
	for _, root := range []string{"/usr", "/bin", "/lib", "/lib64"} {
		if path == root || inside(path, root) {
			return true
		}
	}
	return false
}

func appendCLIState(args []string, seen map[string]bool, home string) []string {
	if home == "" {
		return args
	}
	for _, name := range []string{".grok", ".claude"} {
		src := filepath.Join(home, name)
		dst := filepath.Join(cliHome, name)
		st, err := os.Stat(src)
		if err != nil || !st.IsDir() {
			args = append(args, "--dir", dst)
			seen[dst] = true
			continue
		}
		args = append(args, "--bind", src, dst)
		seen[dst] = true
	}
	// Claude Code keeps some account state beside the .claude directory.
	for _, name := range []string{".claude.json"} {
		src := filepath.Join(home, name)
		real, ok := hostFile(src)
		if !ok {
			continue
		}
		dst := filepath.Join(cliHome, name)
		args = append(args, "--bind", real, dst)
		seen[dst] = true
	}
	return args
}

func appendEtc(args []string, seen map[string]bool) []string {
	for _, path := range []string{"/etc/nsswitch.conf", "/etc/hosts", "/etc/resolv.conf", "/etc/localtime"} {
		real, ok := hostFile(path)
		if !ok {
			continue
		}
		args = append(args, "--ro-bind", real, path)
		seen[path] = true
	}
	if dirExists("/etc/ssl") {
		args = append(args, "--ro-bind", "/etc/ssl", "/etc/ssl")
		seen["/etc/ssl"] = true
	}
	return args
}

func hostFile(path string) (string, bool) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	st, err := os.Stat(real)
	if err != nil || st.IsDir() {
		return "", false
	}
	return real, true
}

func appendCLIROBinds(args []string, seen map[string]bool, binds []string) ([]string, error) {
	for _, raw := range binds {
		raw = filepath.Clean(strings.TrimSpace(raw))
		if raw == "" || raw == "." || !filepath.IsAbs(raw) {
			return nil, fmt.Errorf("cli ro bind %q must be an absolute path", raw)
		}
		if seen[raw] {
			return nil, fmt.Errorf("cli ro bind %q conflicts with a jail mount", raw)
		}
		args = appendParents(args, seen, raw)
		args = append(args, "--ro-bind", raw, raw)
		seen[raw] = true
	}
	return args, nil
}

func appendParents(args []string, seen map[string]bool, dst string) []string {
	dst = filepath.Clean(dst)
	var parents []string
	for p := filepath.Dir(dst); len(p) > 1; p = filepath.Dir(p) {
		if seen[p] {
			break
		}
		parents = append(parents, p)
	}
	for i := len(parents) - 1; i >= 0; i-- {
		args = append(args, "--dir", parents[i])
		seen[parents[i]] = true
	}
	return args
}

func appendLocale(args []string, key string) []string {
	v, ok := localeValue(key)
	if !ok {
		return args
	}
	return append(args, "--setenv", key, v)
}

func localePairs() []string {
	var out []string
	for _, key := range []string{"LANG", "LC_ALL", "TERM", "TZ"} {
		v, ok := localeValue(key)
		if !ok {
			continue
		}
		out = append(out, key+"="+v)
	}
	return out
}

func localeValue(key string) (string, bool) {
	v := os.Getenv(key)
	if v == "" || len(v) > 128 || strings.ContainsAny(v, "\n\r\x00=") {
		return "", false
	}
	for _, r := range v {
		if r < 0x20 || r > 0x7e {
			return "", false
		}
	}
	return v, true
}

func cliPATH() string {
	candidates := []string{
		"/opt/homebrew/bin",
		"/opt/homebrew/sbin",
		"/usr/local/go/bin",
		"/usr/lib/go/bin",
		"/usr/local/sbin",
		"/usr/local/bin",
		"/usr/sbin",
		"/usr/bin",
		"/sbin",
		"/bin",
	}
	var dirs []string
	for _, dir := range candidates {
		if dirExists(dir) {
			dirs = append(dirs, dir)
		}
	}
	if len(dirs) == 0 {
		return "/usr/bin:/bin"
	}
	return strings.Join(dirs, ":")
}

func currentName() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	name := u.Username
	if name == "" || name == "root" || len(name) > 32 {
		return ""
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' && r != '.' {
			return ""
		}
	}
	return name
}

func dirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func inside(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	if path == root {
		return true
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
