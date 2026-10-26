package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/PixnBits/local-grok-bots/internal/github"
)

// Request is one jailed shell command.
type Request struct {
	Workspace  string
	Command    string
	Grants     []string
	NetAllow   []string
	SSHAllow   []string
	BuildBinds []string
	// Protect is the daemon's current protected set, raw and resolved.
	// A build bind that overlaps it, or that cannot be resolved, is not mounted.
	Protect []string
	SSHKey  string
	// GitHubSock is the host credential-proxy socket. Empty leaves GitHub
	// fetch unavailable. GitHubRepos is the allowlist copied into the wrapper.
	GitHubSock      string
	GitHubRepos     []string
	GitAuthor       string
	GitAuthorEmail  string
	GitAuthorRefuse bool
	// OnPush answers a git push while the shell is still running. Nil denies.
	// The string is the shell's logical directory relative to /work.
	// OnPushStart runs after the request is read and before OnPush.
	OnPush      func(context.Context, string, []string) PushResult
	OnPushStart func()
	// Dial, when set, is the proxy's outbound TCP dial. Tests use it.
	Dial func(context.Context, string, string) (net.Conn, error)
}

// Result is the captured output and the grant events for this command.
type Result struct {
	Stdout string
	Stderr string
	Events []Event
}

type mount struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
	RO  bool   `json:"ro"`
}

type stage2File struct {
	Workspace string   `json:"workspace"`
	Command   string   `json:"command"`
	Env       []string `json:"env"`
	Mounts    []mount  `json:"mounts"`
}

type prepared struct {
	workspace string
	command   string
	dir       string
	env       []string
	mounts    []mount
	events    string
	proxy     *proxy
	push      *pushSrv
	before    *treeSnap
	extra     []Event
	grants    map[string]bool
}

func (p *prepared) close() {
	if p == nil {
		return
	}
	if p.proxy != nil {
		p.proxy.close()
	}
	if p.push != nil {
		p.push.close()
	}
	if p.dir != "" {
		_ = os.RemoveAll(p.dir)
	}
}

// Run executes command in the workspace jail.
// Bubblewrap is used when it is installed. Otherwise the unshare jail is used.
// Both paths keep the host filesystem outside the workspace hidden and start
// with no network. A root daemon without bubblewrap fails closed. A missing
// bwrap and a missing unshare fails closed.
func Run(ctx context.Context, req Request) (Result, error) {
	if err := refuseUnsandboxedRoot(); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(req.Command) == "" {
		return Result{}, fmt.Errorf("command required")
	}
	if strings.ContainsRune(req.Command, 0) {
		return Result{}, fmt.Errorf("invalid command")
	}
	ws, err := filepath.Abs(req.Workspace)
	if err != nil {
		return Result{}, err
	}
	if st, err := os.Stat(ws); err != nil || !st.IsDir() {
		return Result{}, fmt.Errorf("workspace unavailable")
	}
	p, err := prepare(ctx, req, ws)
	if err != nil {
		return Result{}, err
	}
	defer p.close()

	stdout, stderr, runErr := launch(ctx, p)
	blockErr := p.before.restore()
	events := append([]Event{}, p.extra...)
	if p.proxy != nil {
		events = append(events, p.proxy.drain()...)
	}
	if p.push != nil {
		events = append(events, p.push.drain()...)
	}
	events = append(events, parseEventFile(p.events)...)
	if blockErr != nil {
		events = append(events, Event{Kind: "sandbox_block", Detail: blockErr.Error()})
		if runErr == nil {
			runErr = blockErr
		} else {
			runErr = fmt.Errorf("%v; %w", blockErr, runErr)
		}
	}
	return Result{Stdout: stdout, Stderr: stderr, Events: events}, runErr
}

func prepare(ctx context.Context, req Request, ws string) (*prepared, error) {
	dir, err := os.MkdirTemp("", "lgb-prep-")
	if err != nil {
		return nil, err
	}
	p := &prepared{workspace: ws, command: req.Command, dir: dir, before: takeSnap(ws)}
	ok := false
	defer func() {
		if !ok {
			p.close()
		}
	}()
	rw := filepath.Join(dir, "rw")
	ro := filepath.Join(dir, "ro")
	for _, sub := range []string{filepath.Join(rw, "sock"), filepath.Join(rw, "events"), ro} {
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return nil, err
		}
	}
	p.events = filepath.Join(rw, "events", "log")
	if err := os.WriteFile(p.events, nil, 0o666); err != nil {
		return nil, err
	}
	empty := filepath.Join(ro, "empty-hooks")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		return nil, err
	}

	p.mounts = append(p.mounts, mount{Src: rw, Dst: "/lgb", RO: false})
	grants := map[string]bool{}
	p.grants = grants
	for _, g := range req.Grants {
		grants[strings.ToLower(strings.TrimSpace(g))] = true
	}

	if path, err := ensurePreload(); err != nil {
		if grants["net"] {
			p.extra = append(p.extra, Event{Kind: "grant_denied", Grant: "net", Detail: "network proxy unavailable"})
		}
		if grants["ssh"] {
			p.extra = append(p.extra, Event{Kind: "grant_denied", Grant: "ssh", Detail: "network proxy unavailable"})
		}
	} else {
		if err := overlayFile(ro, "preload.so", mustRead(path), 0o755); err != nil {
			return nil, err
		}
		touch(filepath.Join(rw, "preload.so"))
		p.mounts = append(p.mounts, mount{Src: filepath.Join(ro, "preload.so"), Dst: "/lgb/preload.so", RO: true})
		px, err := startProxy(ctx, filepath.Join(rw, "sock", "proxy.sock"), req.Grants, req.NetAllow, req.SSHAllow, req.Dial)
		if err != nil {
			return nil, err
		}
		p.proxy = px
	}

	if err := os.MkdirAll(filepath.Join(rw, "bin"), 0o755); err != nil {
		return nil, err
	}
	ghSock := ""
	bridgeBin := ""
	if b, err := ensureBridge(); err == nil {
		bridgeBin = b
	}
	if githubSockOK(req.GitHubSock) {
		if bridgeBin == "" {
			p.extra = append(p.extra, Event{Kind: "grant_denied", Grant: "github", Detail: GitHubProxyDenied})
		} else {
			if err := overlayFile(ro, "ghbridge", mustRead(bridgeBin), 0o755); err != nil {
				return nil, err
			}
			touch(filepath.Join(rw, "bin", "ghbridge"))
			touch(filepath.Join(rw, "sock", "github.sock"))
			p.mounts = append(p.mounts,
				mount{Src: filepath.Join(ro, "ghbridge"), Dst: "/lgb/bin/ghbridge", RO: true},
				mount{Src: req.GitHubSock, Dst: "/lgb/sock/github.sock", RO: true},
			)
			ghSock = req.GitHubSock
		}
	}
	if path, err := exec.LookPath("git"); err == nil {
		if err := writeExec(filepath.Join(ro, "gitwrap"), gitWrap(gitWrapOpts{
			Grant:        grants["git"],
			Repos:        req.GitHubRepos,
			Bridge:       ghSock != "",
			Name:         req.GitAuthor,
			Email:        req.GitAuthorEmail,
			RefuseAuthor: req.GitAuthorRefuse,
		})); err != nil {
			return nil, err
		}
		touch(filepath.Join(rw, "bin", "git"))
		p.mounts = append(p.mounts,
			mount{Src: path, Dst: "/lgb/bin/git", RO: true},
			mount{Src: filepath.Join(ro, "gitwrap"), Dst: "/usr/bin/git", RO: true},
		)
		if bridgeBin != "" && ghSock == "" {
			if err := overlayFile(ro, "ghbridge", mustRead(bridgeBin), 0o755); err != nil {
				return nil, err
			}
			touch(filepath.Join(rw, "bin", "ghbridge"))
			p.mounts = append(p.mounts, mount{Src: filepath.Join(ro, "ghbridge"), Dst: "/lgb/bin/ghbridge", RO: true})
		}
		ps, perr := startPush(ctx, filepath.Join(dir, "push.sock"), req.OnPush, req.OnPushStart)
		if perr != nil {
			p.extra = append(p.extra, Event{Kind: "grant_denied", Grant: "git", Detail: "push socket unavailable"})
		} else {
			p.push = ps
			touch(filepath.Join(rw, "sock", "push.sock"))
			p.mounts = append(p.mounts, mount{Src: filepath.Join(dir, "push.sock"), Dst: "/lgb/sock/push.sock", RO: true})
		}
	}
	if path, err := exec.LookPath("ssh"); err == nil {
		if err := writeExec(filepath.Join(ro, "sshwrap"), sshWrap(grants["ssh"], normalizeHosts(req.SSHAllow))); err != nil {
			return nil, err
		}
		touch(filepath.Join(rw, "bin", "ssh"))
		p.mounts = append(p.mounts,
			mount{Src: path, Dst: "/lgb/bin/ssh", RO: true},
			mount{Src: filepath.Join(ro, "sshwrap"), Dst: "/usr/bin/ssh", RO: true},
		)
	}
	if grants["ssh"] {
		key := req.SSHKey
		if key == "" {
			key = filepath.Join(ro, "id_ed25519")
		}
		if got, err := EnsureKey(key); err != nil {
			p.extra = append(p.extra, Event{Kind: "grant_denied", Grant: "ssh", Detail: "ssh key unavailable"})
		} else {
			touch(filepath.Join(rw, "id_ed25519"))
			p.mounts = append(p.mounts, mount{Src: got, Dst: "/lgb/id_ed25519", RO: true})
		}
	}
	for _, name := range []string{"apt-get", "apt", "dnf", "pacman", "apk"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		wrapName := name + "wrap"
		realDst := "/lgb/bin/" + name
		if err := writeExec(filepath.Join(ro, wrapName), pkgWrap(realDst)); err != nil {
			return nil, err
		}
		touch(filepath.Join(rw, "bin", name))
		p.mounts = append(p.mounts,
			mount{Src: path, Dst: realDst, RO: true},
			mount{Src: filepath.Join(ro, wrapName), Dst: "/usr/bin/" + name, RO: true},
		)
	}

	_ = filepath.WalkDir(ws, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil || !d.IsDir() || d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.Name() != "hooks" || filepath.Base(filepath.Dir(path)) != ".git" {
			return nil
		}
		rel, err := filepath.Rel(ws, path)
		if err != nil || escapes(rel) {
			return nil
		}
		p.mounts = append(p.mounts, mount{Src: empty, Dst: "/work/" + filepath.ToSlash(rel), RO: true})
		return nil
	})

	if grants["build"] {
		mounts, events, applied := selectBuildBinds(ws, req.BuildBinds, req.Protect)
		p.mounts = append(p.mounts, mounts...)
		p.extra = append(p.extra, events...)
		if len(applied) > 0 {
			p.extra = append(p.extra, Event{Kind: "grant_use", Grant: "build", Detail: strings.Join(applied, ",")})
		}
	}

	p.env = []string{
		"PATH=" + jailPATH(),
		"HOME=/work",
		"TMPDIR=/tmp",
		"PWD=/work",
		"LANG=C.UTF-8",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
	}
	if p.proxy != nil {
		p.env = append(p.env,
			"LD_PRELOAD=/lgb/preload.so",
			"LGB_PROXY_SOCK=/lgb/sock/proxy.sock",
		)
	}
	ok = true
	return p, nil
}

// jailPATH names binaries that are already on the read-only /usr and /bin mounts.
// Home directories and /snap are not included.
func jailPATH() string {
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
		st, err := os.Stat(dir)
		if err != nil || !st.IsDir() {
			continue
		}
		dirs = append(dirs, dir)
	}
	if len(dirs) == 0 {
		return "/usr/bin:/bin"
	}
	return strings.Join(dirs, ":")
}

func mustRead(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

func overlayFile(dir, name string, data []byte, mode os.FileMode) error {
	if data == nil {
		return fmt.Errorf("missing %s", name)
	}
	return os.WriteFile(filepath.Join(dir, name), data, mode)
}

func writeExec(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o755)
}

func touch(path string) {
	_ = os.WriteFile(path, nil, 0o644)
}

func normalizeHosts(hosts []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(h, ".")))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// selectBuildBinds decides which SANDBOX_BUILD_BINDS entries are mounted.
// Each absolute path is resolved with EvalSymlinks. A path that is not
// absolute, is a refused toolchain path, cannot be resolved, or overlaps
// protected (raw or resolved) is not mounted. The turn continues and a
// sandbox_block names the bind path. A path inside the workspace is skipped
// with no event. Mounts use the resolved path so the bind does not follow
// a symlink again.
func selectBuildBinds(ws string, binds, protected []string) (mounts []mount, events []Event, applied []string) {
	ws = filepath.Clean(ws)
	var roots []string
	roots = append(roots, ws)
	if real, err := filepath.EvalSymlinks(ws); err == nil {
		real = filepath.Clean(real)
		if real != ws {
			roots = append(roots, real)
		}
	}
	for _, raw := range binds {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !filepath.IsAbs(raw) || refusedBind(raw) {
			events = append(events, Event{Kind: "sandbox_block", Detail: "refused bind " + raw})
			continue
		}
		resolved, err := filepath.EvalSymlinks(raw)
		if err != nil {
			events = append(events, Event{Kind: "sandbox_block", Detail: "refused bind " + raw})
			continue
		}
		resolved = filepath.Clean(resolved)
		clean := filepath.Clean(raw)
		if bindOverlapsProtected(clean, resolved, protected) {
			events = append(events, Event{Kind: "sandbox_block", Detail: "refused bind " + raw})
			continue
		}
		skip := false
		for _, root := range roots {
			if sameTree(root, clean) || sameTree(root, resolved) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		mounts = append(mounts, mount{Src: resolved, Dst: resolved, RO: true})
		applied = append(applied, raw)
	}
	return mounts, events, applied
}

// bindOverlapsProtected reports whether the raw or resolved bind is the same
// path as a protected path or one contains the other.
func bindOverlapsProtected(raw, resolved string, protected []string) bool {
	forms := []string{filepath.Clean(raw)}
	if resolved != "" && filepath.Clean(resolved) != forms[0] {
		forms = append(forms, filepath.Clean(resolved))
	}
	for _, bind := range forms {
		for _, secret := range protected {
			secret = filepath.Clean(strings.TrimSpace(secret))
			if secret == "" || secret == "." {
				continue
			}
			if pathHolds(bind, secret) || pathHolds(secret, bind) {
				return true
			}
		}
	}
	return false
}

// pathHolds reports whether path is root or a descendant of root.
func pathHolds(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if root == "" || path == "" || root == "." || path == "." {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// mountArgs is the bwrap bind list for mounts. Read-only mounts use --ro-bind.
func mountArgs(mounts []mount) []string {
	var args []string
	for _, m := range mounts {
		flag := "--bind"
		if m.RO {
			flag = "--ro-bind"
		}
		args = append(args, flag, m.Src, m.Dst)
	}
	return args
}

func sameTree(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && !escapes(rel)
}

func capture(ctx context.Context, cmd *exec.Cmd) (string, string, error) {
	return captureReady(ctx, cmd, nil)
}

// captureReady runs cmd. ready, when set, runs after start and before the
// command is expected to finish. A ready error kills the process group.
func captureReady(ctx context.Context, cmd *exec.Cmd, ready func() error) (string, string, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var outBuf, errBuf bytes.Buffer
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", "", err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return "", "", err
	}
	if err := cmd.Start(); err != nil {
		return "", "", fmt.Errorf("shell sandbox: %w", err)
	}
	doneOut := make(chan struct{})
	doneErr := make(chan struct{})
	go func() {
		_, _ = io.Copy(&outBuf, io.LimitReader(stdoutPipe, maxCapture+1))
		doneOut <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(&errBuf, io.LimitReader(stderrPipe, maxCapture+1))
		doneErr <- struct{}{}
	}()
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	if ready != nil {
		if err := ready(); err != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Process.Kill()
			<-waitErr
			<-doneOut
			<-doneErr
			return "", "", err
		}
	}

	var runErr error
	select {
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Kill()
		<-waitErr
		runErr = fmt.Errorf("shell timed out")
	case err := <-waitErr:
		runErr = err
	}
	<-doneOut
	<-doneErr
	stdout := truncate(outBuf.String())
	stderr := truncate(errBuf.String())
	if runErr != nil {
		if runErr.Error() == "shell timed out" {
			return stdout, stderr, runErr
		}
		return stdout, stderr, fmt.Errorf("exit %s", exitCode(runErr))
	}
	return stdout, stderr, nil
}

func allowlistEvent(raw string) Event {
	ev := Event{Kind: "grant_denied", Grant: "github", Detail: GitHubAllowlistDenied}
	raw = strings.TrimSpace(raw)
	if owner, repo, err := github.ParseGitHubRemote(raw); err == nil {
		ev.Owner, ev.Repo = owner, repo
		return ev
	}
	if owner, repo, ok := gitHubSSHRepo(raw); ok {
		ev.Owner, ev.Repo = owner, repo
	}
	return ev
}

func gitHubSSHRepo(raw string) (string, string, bool) {
	const prefix = "git@github.com:"
	if len(raw) < len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) {
		return "", "", false
	}
	rest := raw[len(prefix):]
	rest = strings.TrimSuffix(rest, "/")
	if len(rest) >= 4 && strings.EqualFold(rest[len(rest)-4:], ".git") {
		rest = rest[:len(rest)-4]
	}
	rest = strings.TrimSuffix(rest, "/")
	name, err := github.NormalizeRepo(rest)
	if err != nil {
		return "", "", false
	}
	owner, repo, _ := strings.Cut(name, "/")
	return owner, repo, true
}

func parseEventFile(path string) []Event {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []Event
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			continue
		case line == "push":
			out = append(out, Event{Kind: "grant_denied", Grant: "git", Detail: "push not sent"})
		case line == "pkg":
			out = append(out, Event{Kind: "grant_use", Detail: "package install", Notice: "Package install"})
		case strings.HasPrefix(line, "deny github allowlist "):
			out = append(out, allowlistEvent(strings.TrimPrefix(line, "deny github allowlist ")))
		case strings.HasPrefix(line, "deny git "):
			out = append(out, Event{Kind: "grant_denied", Grant: "git", Detail: strings.TrimPrefix(line, "deny git ")})
		case strings.HasPrefix(line, "use git "):
			out = append(out, Event{Kind: "grant_use", Grant: "git", Detail: strings.TrimPrefix(line, "use git ")})
		case strings.HasPrefix(line, "deny ssh "):
			out = append(out, Event{Kind: "grant_denied", Grant: "ssh", Host: strings.TrimPrefix(line, "deny ssh ")})
		case strings.HasPrefix(line, "block "):
			out = append(out, Event{Kind: "sandbox_block", Detail: strings.TrimPrefix(line, "block ")})
		}
	}
	return out
}
