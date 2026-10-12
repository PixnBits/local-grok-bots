package clisession

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

// cliHome is the only home directory inside the CLI jail.
const cliHome = "/lgb-home"

// confinedCommand runs bin under bubblewrap. The workspace is bind-mounted
// at its host path. The daemon user's CLI login directories are the only
// home paths mounted. The child environment is cleared.
func confinedCommand(bin string, args []string, workspace string) (*exec.Cmd, error) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("cli confinement unavailable: bwrap not on PATH")
	}
	wrapArgs, err := confineArgs(bin, args, workspace)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bwrap, wrapArgs...)
	// Absolute bwrap path. A minimal env so the wrapper itself does not
	// carry API keys or an SSH agent socket in its own environ.
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	return cmd, nil
}

// confineArgs builds the bwrap argv after argv0.
func confineArgs(bin string, args []string, workspace string) ([]string, error) {
	ws, err := filepath.Abs(workspace)
	if err != nil || strings.TrimSpace(workspace) == "" {
		return nil, fmt.Errorf("cli workspace is required")
	}
	if ws == "/" {
		return nil, fmt.Errorf("cli workspace must not be /")
	}
	st, err := os.Stat(ws)
	if err != nil {
		return nil, fmt.Errorf("cli workspace: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("cli workspace is not a directory")
	}
	absBin, err := filepath.Abs(bin)
	if err != nil {
		return nil, err
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		home, _ = filepath.Abs(home)
	}
	if home != "" && (ws == home || inside(home, ws)) {
		return nil, fmt.Errorf("cli workspace must not contain the home directory")
	}
	argv0, extra, err := placeBinary(absBin, ws, home)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var b []string
	b = append(b,
		"--unshare-user", "--unshare-pid", "--die-with-parent", "--clearenv",
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

	b = append(b, "--setenv", "PATH", cliPATH(), "--setenv", "HOME", cliHome)
	if name := currentName(); name != "" {
		b = append(b, "--setenv", "USER", name, "--setenv", "LOGNAME", name)
	}
	for _, key := range []string{"LANG", "LC_ALL", "TERM", "TZ"} {
		b = appendLocale(b, key)
	}
	b = append(b, "--", argv0)
	b = append(b, args...)
	return b, nil
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
	v := os.Getenv(key)
	if v == "" || len(v) > 128 || strings.ContainsAny(v, "\n\r\x00=") {
		return args
	}
	for _, r := range v {
		if r < 0x20 || r > 0x7e {
			return args
		}
	}
	return append(args, "--setenv", key, v)
}

func cliPATH() string {
	candidates := []string{
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
