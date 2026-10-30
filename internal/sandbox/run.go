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
	"strconv"
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
	// ProtectInodes is the startup snapshot of protected paths and their
	// ancestor directories. An empty snapshot refuses every build bind.
	// A protected directory that is missing, no longer a directory, or whose
	// device or inode changed refuses every build bind for the turn.
	// A regular file in the snapshot does not.
	ProtectInodes []ProtectInode
	// ProtectTripped, when set, refuses every build bind for this turn.
	// The daemon latches it until restart. The text is the refusal suffix,
	// for example "protected path changed (restart required)".
	ProtectTripped string
	SSHKey         string
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
	// CleanBash runs the command with bash --norc --noprofile and without
	// BASH_ENV or ENV. The broker sets it only after an allow. Other
	// shells stay on /bin/sh.
	CleanBash bool
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
	// file is a Linux build-bind fd (O_PATH|O_CLOEXEC). Nil mounts use Src.
	// It is not serialized. The unshare fallback does not mount it by path:
	// it refuses the bind. Bubblewrap mounts it with --ro-bind-fd.
	file *os.File
}

type stage2File struct {
	Workspace string   `json:"workspace"`
	Command   string   `json:"command"`
	Env       []string `json:"env"`
	Mounts    []mount  `json:"mounts"`
	CleanBash bool     `json:"clean_bash,omitempty"`
}

type prepared struct {
	workspace string
	command   string
	dir       string
	env       []string
	mounts    []mount
	events    string
	// eventsDir is the daemon-created prep/rw/events directory, opened
	// O_PATH|O_DIRECTORY|O_CLOEXEC. It is not passed to child processes.
	// The jail can replace /lgb/events; this fd still names the original inode.
	eventsDir *os.File
	cleanBash bool
	proxy     *proxy
	push      *pushSrv
	before    *treeSnap
	extra     []Event
	grants    map[string]bool
}

// refuseUnshareBuildBinds reports that this turn will use the unshare jail.
// That jail cannot bind-mount an O_PATH fd (mount of /proc/self/fd/N returns
// EINVAL from the new user namespace), and a path bind would race. Linux
// sets this. A true result refuses every build bind and does not mount it.
var refuseUnshareBuildBinds func() bool

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
	closeMountFiles(p.mounts)
	if p.eventsDir != nil {
		_ = p.eventsDir.Close()
		p.eventsDir = nil
	}
	if p.dir != "" {
		_ = os.RemoveAll(p.dir)
	}
}

func closeMountFiles(mounts []mount) {
	for i := range mounts {
		if mounts[i].file != nil {
			_ = mounts[i].file.Close()
			mounts[i].file = nil
		}
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
	events = append(events, readPreparedEvents(p)...)
	if blockErr != nil {
		events = append(events, blockEvent(blockErr.Error()))
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
	p := &prepared{workspace: ws, command: req.Command, dir: dir, before: takeSnap(ws), cleanBash: req.CleanBash}
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
	// 0600, owned by the daemon. A root daemon with bwrap chowns it to the
	// overflow uid so the dropped jail can append. The jail can still write
	// the bytes; those lines are untrusted. World-writable mode is not used.
	if err := os.WriteFile(p.events, nil, 0o600); err != nil {
		return nil, err
	}
	if err := OwnPath(p.events, 0o600); err != nil {
		return nil, err
	}
	df, err := openEventsDirectory(dir)
	if err != nil {
		return nil, err
	}
	p.eventsDir = df
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
		if refuseUnshareBuildBinds != nil && refuseUnshareBuildBinds() {
			for _, raw := range req.BuildBinds {
				raw = strings.TrimSpace(raw)
				if raw == "" {
					continue
				}
				p.extra = append(p.extra, blockEvent("refused bind "+raw+": unsupported without bwrap"))
			}
		} else {
			mounts, events, applied := selectBuildBinds(ws, req.BuildBinds, req.Protect, req.ProtectInodes, req.ProtectTripped)
			p.mounts = append(p.mounts, mounts...)
			p.extra = append(p.extra, events...)
			if len(applied) > 0 {
				p.extra = append(p.extra, Event{Kind: "grant_use", Grant: "build", Detail: strings.Join(applied, ",")})
			}
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
	if p.cleanBash {
		p.env = dropEnvKeys(p.env, "BASH_ENV", "ENV")
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

func dropEnvKeys(env []string, keys ...string) []string {
	skip := map[string]bool{}
	for _, k := range keys {
		skip[k] = true
	}
	out := make([]string, 0, len(env))
	for _, e := range env {
		k, _, ok := strings.Cut(e, "=")
		if ok && skip[k] {
			continue
		}
		out = append(out, e)
	}
	return out
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
// A non-empty tripped suffix refuses every bind until the process restarts.
// An empty protected list, or an empty inode snapshot, refuses every bind.
// A protected directory in the snapshot that is missing, no longer a
// directory, or whose device or inode changed refuses every bind for the
// turn. Regular files in the snapshot do not. Each absolute path is then
// resolved with EvalSymlinks. A path that is not absolute, is a refused
// toolchain path, cannot be resolved, or overlaps protected (raw or
// resolved) is not mounted. On Linux the resolved path is opened without
// following symlinks and checked again; a failure skips that bind. The turn
// continues and a sandbox_block names the bind path. A path inside the
// workspace is skipped with no event when the protected list is non-empty
// and the snapshot is unchanged. The mount destination stays the resolved path.
func selectBuildBinds(ws string, binds, protected []string, snap []ProtectInode, tripped string) (mounts []mount, events []Event, applied []string) {
	if strings.TrimSpace(tripped) != "" {
		for _, raw := range binds {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			events = append(events, blockEvent("refused bind "+raw+": "+strings.TrimSpace(tripped)))
		}
		return nil, events, nil
	}
	if !protectListed(protected) || len(snap) == 0 {
		for _, raw := range binds {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			events = append(events, blockEvent("refused bind "+raw))
		}
		return nil, events, nil
	}
	if protectDirsChanged(snap) {
		for _, raw := range binds {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			events = append(events, blockEvent("refused bind "+raw+": protected path changed"))
		}
		return nil, events, nil
	}
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
			events = append(events, blockEvent("refused bind "+raw))
			continue
		}
		resolved, err := filepath.EvalSymlinks(raw)
		if err != nil {
			events = append(events, blockEvent("refused bind "+raw))
			continue
		}
		resolved = filepath.Clean(resolved)
		clean := filepath.Clean(raw)
		if bindOverlapsProtected(clean, resolved, protected) {
			events = append(events, blockEvent("refused bind "+raw))
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
		f, err := openBuildBind(resolved, protected, snap)
		if err != nil {
			if f != nil {
				_ = f.Close()
			}
			events = append(events, blockEvent("refused bind "+raw))
			continue
		}
		mounts = append(mounts, mount{Src: resolved, Dst: resolved, RO: true, file: f})
		applied = append(applied, raw)
	}
	return mounts, events, applied
}

// protectListed reports whether protected names at least one real path.
// Blank, ".", and "/" do not count: an empty set fails closed.
func protectListed(protected []string) bool {
	for _, p := range protected {
		p = strings.TrimSpace(p)
		if p != "" && p != "." && p != "/" {
			return true
		}
	}
	return false
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

// mountArgs is the bwrap bind list for mounts. Read-only path mounts use
// --ro-bind. A mount with an open fd is a build bind and uses --ro-bind-fd.
// already is the number of ExtraFiles the caller will place before these fds.
// Child fd numbers are 3+index in the final ExtraFiles slice. Build binds
// never fall back to a path --ro-bind. The unshare fallback refuses them.
func mountArgs(mounts []mount, already int) (args []string, files []*os.File) {
	n := already
	for _, m := range mounts {
		if m.file != nil {
			args = append(args, "--ro-bind-fd", strconv.Itoa(3+n), m.Dst)
			files = append(files, m.file)
			n++
			continue
		}
		flag := "--bind"
		if m.RO {
			flag = "--ro-bind"
		}
		args = append(args, flag, m.Src, m.Dst)
	}
	return args, files
}

func sameTree(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && !escapes(rel)
}

func capture(ctx context.Context, cmd *exec.Cmd) (string, string, error) {
	return captureReady(ctx, cmd, nil, nil)
}

// captureReady runs cmd. started, when set, runs after Start returns,
// including when Start fails. ready, when set, runs after a successful
// start and before the command is expected to finish. A ready error kills
// the process group.
func captureReady(ctx context.Context, cmd *exec.Cmd, started func(), ready func() error) (string, string, error) {
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
	startErr := cmd.Start()
	if started != nil {
		started()
	}
	if startErr != nil {
		return "", "", fmt.Errorf("shell sandbox: %w", startErr)
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
	ev := Event{Grant: "github", Detail: GitHubAllowlistDenied}
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

const (
	maxEventBytes  = 64 << 10
	maxEventLines  = 64
	maxEventDetail = 256
)

// blockEvent is a daemon-generated sandbox_block. Detail is printable ASCII
// and at most 256 bytes. Jail lines never use this.
func blockEvent(detail string) Event {
	return Event{Kind: "sandbox_block", Detail: clipASCII(detail)}
}

// clipASCII keeps bytes in 0x20–0x7E and then cuts to 256 bytes.
func clipASCII(s string) string {
	var b strings.Builder
	n := 0
	for i := 0; i < len(s) && n < maxEventDetail; i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			continue
		}
		b.WriteByte(c)
		n++
	}
	return b.String()
}

func clipEventFields(ev Event) Event {
	ev.Detail = clipASCII(ev.Detail)
	ev.Host = clipASCII(ev.Host)
	ev.Owner = clipASCII(ev.Owner)
	ev.Repo = clipASCII(ev.Repo)
	ev.Notice = clipASCII(ev.Notice)
	ev.Grant = clipASCII(ev.Grant)
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

// eventsUnavailable is the daemon event for any events-log failure.
func eventsUnavailable() []Event {
	return []Event{{Kind: "jail_report_truncated", Detail: "events unavailable"}}
}

// eventsFromFile reads a regular file already opened by the caller.
// A stat failure, a non-regular file, or a read error is events unavailable.
func eventsFromFile(f *os.File) []Event {
	if f == nil {
		return eventsUnavailable()
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return eventsUnavailable()
	}
	b, err := io.ReadAll(io.LimitReader(f, maxEventBytes+1))
	if err != nil {
		return eventsUnavailable()
	}
	return parseEventBytes(b)
}

// parseEventFile reads a path for tests. The turn reads through the
// directory fd from prepare. Any open, type, or read failure is one
// daemon-generated jail_report_truncated event, events unavailable.
func parseEventFile(path string) []Event {
	f, err := openEventsFile(path)
	if err != nil {
		return eventsUnavailable()
	}
	defer f.Close()
	return eventsFromFile(f)
}

// parseEventBytes applies the 64 KiB and 64-line caps. Overflow is one
// daemon-generated jail_report_truncated event with detail "dropped N".
func parseEventBytes(b []byte) []Event {
	overflow := 0
	if len(b) > maxEventBytes {
		overflow++
		b = b[:maxEventBytes]
		if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
			b = b[:i]
		} else {
			b = nil
		}
	}
	var out []Event
	kept := 0
	for _, raw := range bytes.Split(b, []byte{'\n'}) {
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		if kept >= maxEventLines {
			overflow++
			continue
		}
		kept++
		ev, ok := jailEvent(line)
		if !ok {
			continue
		}
		out = append(out, ev)
	}
	if overflow > 0 {
		out = append(out, Event{
			Kind:   "jail_report_truncated",
			Detail: clipASCII(fmt.Sprintf("dropped %d", overflow)),
		})
	}
	return out
}

// jailEvent maps one jail line to an untrusted report. The claimed kind is
// Reported. The event kind is never sandbox_block, grant_use, or grant_denied.
func jailEvent(line string) (Event, bool) {
	ev := Event{Kind: "jail_report", Untrusted: true}
	switch {
	case line == "push":
		ev.Reported = "grant_denied"
		ev.Grant = "git"
		ev.Detail = "push not sent"
		ev.Notice = "Untrusted jail report: push not sent"
	case line == "pkg":
		ev.Reported = "grant_use"
		ev.Detail = "package install"
		ev.Notice = "Untrusted jail report: Package install"
	case strings.HasPrefix(line, "deny github allowlist "):
		parsed := allowlistEvent(strings.TrimPrefix(line, "deny github allowlist "))
		ev.Reported = "grant_denied"
		ev.Grant = parsed.Grant
		ev.Detail = parsed.Detail
		ev.Owner = parsed.Owner
		ev.Repo = parsed.Repo
	case strings.HasPrefix(line, "deny git "):
		ev.Reported = "grant_denied"
		ev.Grant = "git"
		ev.Detail = strings.TrimPrefix(line, "deny git ")
	case strings.HasPrefix(line, "use git "):
		ev.Reported = "grant_use"
		ev.Grant = "git"
		ev.Detail = strings.TrimPrefix(line, "use git ")
	case strings.HasPrefix(line, "deny ssh "):
		ev.Reported = "grant_denied"
		ev.Grant = "ssh"
		ev.Host = strings.TrimPrefix(line, "deny ssh ")
	case strings.HasPrefix(line, "block "):
		ev.Reported = "sandbox_block"
		ev.Detail = strings.TrimPrefix(line, "block ")
	default:
		return Event{}, false
	}
	return clipEventFields(ev), true
}
