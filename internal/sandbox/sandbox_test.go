package sandbox

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if HandleArgs(os.Args[1:]) {
		return
	}
	os.Exit(m.Run())
}

func requireBin(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Fatalf("%s is required; refusing to skip", name)
	}
}

func runCmd(t *testing.T, req Request) (Result, error) {
	t.Helper()
	if runtime.GOOS == "darwin" {
		requireBin(t, "sandbox-exec")
	} else {
		requireBin(t, "bwrap")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	res, err := Run(ctx, req)
	t.Logf("err=%v\nstdout:\n%s\nstderr:\n%s\nevents=%+v", err, res.Stdout, res.Stderr, res.Events)
	return res, err
}

func mustRun(t *testing.T, req Request) Result {
	t.Helper()
	res, err := runCmd(t, req)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}

func findEvent(events []Event, kind, grant, host string) (Event, bool) {
	for _, e := range events {
		if kind != "" && e.Kind != kind {
			continue
		}
		if grant != "" && e.Grant != grant {
			continue
		}
		if host != "" && e.Host != host {
			continue
		}
		return e, true
	}
	return Event{}, false
}

func TestCheckWriteAndRestore(t *testing.T) {
	ws := t.TempDir()
	hook := filepath.Join(ws, ".git", "hooks", "pre-commit")
	if err := os.MkdirAll(filepath.Dir(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hook, []byte("old\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rc := filepath.Join(ws, ".bashrc")
	if err := os.WriteFile(rc, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := takeSnap(ws)

	abs, err := Resolve(ws, ".bashrc")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckWrite(ws, abs); err == nil {
		t.Fatal("CheckWrite allowed .bashrc")
	}
	cfg, err := Resolve(ws, ".git/config")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckWrite(ws, cfg); err == nil {
		t.Fatal("CheckWrite allowed .git/config")
	}
	if _, err := Resolve(ws, "../escape.txt"); err == nil {
		t.Fatal("Resolve allowed a parent path")
	}

	if err := os.WriteFile(hook, []byte("new\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rc, []byte("pwn\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("[core]\n\tsshCommand = /bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sample := filepath.Join(ws, ".git", "hooks", "pre-commit.sample")
	if err := os.WriteFile(sample, []byte("# sample\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := before.restore(); err == nil {
		t.Fatal("restore allowed hook, rc, and sshCommand")
	}
	b, err := os.ReadFile(hook)
	if err != nil || string(b) != "old\n" {
		t.Fatalf("hook not restored: %v %q", err, b)
	}
	b, err = os.ReadFile(rc)
	if err != nil || string(b) != "keep\n" {
		t.Fatalf("rc not restored: %v %q", err, b)
	}
	if _, err := os.Stat(cfg); !os.IsNotExist(err) {
		body, _ := os.ReadFile(cfg)
		t.Fatalf("dangerous git config remained: %v %q", err, body)
	}
	if _, err := os.Stat(sample); err != nil {
		t.Fatal("non-executable sample hook was removed")
	}

	benign := t.TempDir()
	snap := takeSnap(benign)
	benignCfg := filepath.Join(benign, ".git", "config")
	if err := os.MkdirAll(filepath.Dir(benignCfg), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "[core]\n\trepositoryformatversion = 0\n"
	if err := os.WriteFile(benignCfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := snap.restore(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(benignCfg)
	if err != nil || string(got) != body {
		t.Fatalf("benign config: %v %q", err, got)
	}
}

func TestMissingSandboxFailsClosed(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := Run(context.Background(), Request{Workspace: t.TempDir(), Command: "echo hi"})
	if err == nil || !strings.Contains(err.Error(), "sandbox unavailable") {
		t.Fatalf("expected fail closed, got %v", err)
	}
}

func TestBaseJailHidesHost(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "notes.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secret, []byte("TOPSECRET\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(os.TempDir(), "lgb-host-escape-"+filepath.Base(ws))
	t.Cleanup(func() { _ = os.Remove(marker) })
	outside := filepath.Join(filepath.Dir(ws), "outside-"+filepath.Base(ws)+".txt")
	t.Cleanup(func() { _ = os.Remove(outside) })
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")

	res, err := runCmd(t, Request{Workspace: ws, Command: fmt.Sprintf(
		"pwd; echo SOCK:${SSH_AUTH_SOCK-unset}; echo GIT:$GIT_CONFIG_GLOBAL; cat notes.txt; echo pwn > %s; echo x > ../outside.txt; cat %s || echo no-secret; cat /etc/passwd",
		marker, secret,
	)})
	if err == nil {
		t.Fatal("cat /etc/passwd succeeded inside the jail")
	}
	wantRoot := "/work"
	if runtime.GOOS == "darwin" {
		wantRoot = ws
	}
	if !strings.Contains(res.Stdout, wantRoot) || !strings.Contains(res.Stdout, "hello") {
		t.Fatalf("workspace was not the jail root:\n%s", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "SOCK:unset") {
		t.Fatalf("host SSH agent leaked: %s", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "GIT:/dev/null") {
		t.Fatalf("host git config was not cleared: %s", res.Stdout)
	}
	if strings.Contains(res.Stdout, "TOPSECRET") || !strings.Contains(res.Stdout, "no-secret") {
		t.Fatalf("host file was readable:\n%s", res.Stdout)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("shell wrote the host temp file")
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatal("shell wrote outside the workspace")
	}
	if _, err := os.Stat(filepath.Join(ws, "outside.txt")); !os.IsNotExist(err) {
		t.Fatal(".. write landed in the workspace")
	}
}

func TestShellBlocksHooksAndRC(t *testing.T) {
	ws := t.TempDir()
	res, err := runCmd(t, Request{Workspace: ws, Command: `mkdir -p .git/hooks
printf '%s\n' '#!/bin/sh' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
printf '%s\n' 'echo pwn' > .bashrc
mkdir -p .git
printf '%s\n' '[core]' '	sshCommand = /bin/sh' > .git/config
echo wrote
`})
	if err == nil {
		t.Fatal("protected writes were kept")
	}
	if _, ok := findEvent(res.Events, "sandbox_block", "", ""); !ok {
		t.Fatalf("missing sandbox_block: %+v", res.Events)
	}
	if _, err := os.Stat(filepath.Join(ws, ".bashrc")); !os.IsNotExist(err) {
		t.Fatal(".bashrc remained")
	}
	if _, err := os.Stat(filepath.Join(ws, ".git", "hooks", "pre-commit")); !os.IsNotExist(err) {
		t.Fatal("hook remained")
	}
	body, _ := os.ReadFile(filepath.Join(ws, ".git", "config"))
	if strings.Contains(string(body), "sshCommand") {
		t.Fatalf("sshCommand remained: %s", body)
	}
}

func dialRecorder(t *testing.T) (func(context.Context, string, string) (net.Conn, error), *[]string) {
	t.Helper()
	var mu sync.Mutex
	got := []string{}
	fn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		got = append(got, addr)
		mu.Unlock()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		go func() {
			c, err := ln.Accept()
			_ = ln.Close()
			if err != nil {
				return
			}
			defer c.Close()
			_, _ = io.WriteString(c, "SSH-2.0-fake\r\n")
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 1024)
			_, _ = c.Read(buf)
		}()
		return net.Dial("tcp", ln.Addr().String())
	}
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		t.Logf("dialed %#v", got)
	})
	return fn, &got
}

const netScript = `python3 - <<'PY'
import socket
def hit(host, port):
    try:
        s = socket.create_connection((host, port), 3)
        s.sendall(b"hi")
        s.close()
        print("open", host, port)
    except Exception as e:
        print("fail", host, port, type(e).__name__)
hit("allowed.test", 80)
hit("denied.test", 80)
hit("1.2.3.4", 80)
hit("allowed.test", 22)
PY`

func TestNetDeniedWithoutGrant(t *testing.T) {
	requireBin(t, "python3")
	dial, got := dialRecorder(t)
	res, err := runCmd(t, Request{Workspace: t.TempDir(), Command: netScript, Dial: dial})
	if err == nil && !strings.Contains(res.Stdout, "fail") {
		t.Fatal("network connection succeeded without a grant")
	}
	if _, ok := findEvent(res.Events, "grant_denied", "net", "allowed.test"); !ok {
		t.Fatalf("missing net denial: %+v", res.Events)
	}
	if _, ok := findEvent(res.Events, "grant_use", "net", ""); ok {
		t.Fatalf("net grant was used: %+v", res.Events)
	}
	if len(*got) != 0 {
		t.Fatalf("proxy dialed without a grant: %#v", *got)
	}
}

func TestNetAllowlist(t *testing.T) {
	requireBin(t, "python3")
	dial, got := dialRecorder(t)
	res, err := runCmd(t, Request{
		Workspace: t.TempDir(),
		Command:   netScript,
		Grants:    []string{"net"},
		NetAllow:  []string{"Allowed.Test."},
		Dial:      dial,
	})
	if err != nil && !strings.Contains(res.Stdout, "open allowed.test 80") {
		t.Fatalf("allowlisted connect failed: %v", err)
	}
	if !strings.Contains(res.Stdout, "open allowed.test 80") {
		t.Fatal("allowlisted host was not reached")
	}
	if strings.Contains(res.Stdout, "open denied.test") || strings.Contains(res.Stdout, "open 1.2.3.4") || strings.Contains(res.Stdout, "open allowed.test 22") {
		t.Fatalf("non-allowlisted connect succeeded:\n%s", res.Stdout)
	}
	if _, ok := findEvent(res.Events, "grant_use", "net", "allowed.test"); !ok {
		t.Fatalf("missing net use: %+v", res.Events)
	}
	if _, ok := findEvent(res.Events, "net_request", "net", "denied.test"); !ok {
		t.Fatalf("missing domain request: %+v", res.Events)
	}
	if _, ok := findEvent(res.Events, "net_request", "net", "1.2.3.4"); !ok {
		t.Fatalf("missing IP request: %+v", res.Events)
	}
	if ev, ok := findEvent(res.Events, "grant_denied", "ssh", "allowed.test"); !ok || ev.Detail == "" {
		t.Fatalf("port 22 was not an ssh denial: %+v", res.Events)
	}
	if len(*got) != 1 || !strings.HasPrefix((*got)[0], "allowed.test:") {
		t.Fatalf("dialed %#v", *got)
	}
}

func TestGitDeniedWithoutGrant(t *testing.T) {
	requireBin(t, "git")
	res, err := runCmd(t, Request{Workspace: t.TempDir(), Command: "git init"})
	if err == nil {
		t.Fatal("git init succeeded without a grant")
	}
	if _, ok := findEvent(res.Events, "grant_denied", "git", ""); !ok {
		t.Fatalf("missing git denial: %+v", res.Events)
	}
	if strings.Contains(res.Stdout, "Initialized") {
		t.Fatalf("git init ran:\n%s", res.Stdout)
	}
}

func TestGitCommitAndPushHeld(t *testing.T) {
	requireBin(t, "git")
	ws := t.TempDir()
	res := mustRun(t, Request{Workspace: ws, Grants: []string{"git"}, Command: `set -e
git init
echo hello > readme.txt
git add readme.txt
git commit -m note
git push
echo PUSH_DONE
`})
	if !strings.Contains(res.Stdout, "git push held for review") || !strings.Contains(res.Stdout, "not sent") {
		t.Fatalf("push was not held:\n%s", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "PUSH_DONE") || !strings.Contains(res.Stdout, "note") {
		t.Fatalf("commit review missing:\n%s", res.Stdout)
	}
	var held bool
	for _, e := range res.Events {
		if e.Kind == "grant_use" && e.Grant == "git" && e.Notice == "Git push held for review" {
			held = true
		}
	}
	if !held {
		t.Fatalf("missing push notice: %+v", res.Events)
	}
	for _, sub := range []string{"init", "add", "commit"} {
		found := false
		for _, e := range res.Events {
			if e.Kind == "grant_use" && e.Grant == "git" && e.Detail == sub {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing git %s use: %+v", sub, res.Events)
		}
	}
	cmd := exec.Command("git", "-C", ws, "--no-pager", "log", "--oneline")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "note") {
		t.Fatalf("commit not in worktree: %v %s", err, out)
	}
}

func TestSSHDeniedWithoutGrant(t *testing.T) {
	requireBin(t, "ssh")
	dial, got := dialRecorder(t)
	res, err := runCmd(t, Request{
		Workspace: t.TempDir(),
		Command:   "ssh -o ConnectTimeout=2 allowed.test true; echo denied:$?",
		Dial:      dial,
		SSHAllow:  []string{"allowed.test"},
	})
	if err == nil && !strings.Contains(res.Stdout, "denied:") {
		t.Fatal(err)
	}
	if _, ok := findEvent(res.Events, "grant_denied", "ssh", "allowed.test"); !ok {
		t.Fatalf("missing ssh denial: %+v", res.Events)
	}
	if _, ok := findEvent(res.Events, "grant_use", "ssh", ""); ok {
		t.Fatalf("ssh was used: %+v", res.Events)
	}
	if len(*got) != 0 {
		t.Fatalf("ssh dialed without a grant: %#v", *got)
	}
}

func TestSSHAllowlist(t *testing.T) {
	requireBin(t, "ssh")
	requireBin(t, "ssh-keygen")
	dial, got := dialRecorder(t)
	res, err := runCmd(t, Request{
		Workspace: t.TempDir(),
		Command: `ssh -o ConnectTimeout=2 allowed.test true; echo allowed:$?
ssh -o ConnectTimeout=2 other.test true; echo other:$?`,
		Grants:   []string{"ssh"},
		SSHAllow: []string{"allowed.test"},
		Dial:     dial,
	})
	if !strings.Contains(res.Stdout, "other:") {
		t.Fatalf("ssh command did not finish: %v\n%s\n%s", err, res.Stdout, res.Stderr)
	}
	ev, ok := findEvent(res.Events, "grant_use", "ssh", "allowed.test")
	if !ok || ev.Notice != "SSH to allowed.test" {
		t.Fatalf("missing ssh notice: %+v", res.Events)
	}
	if _, ok := findEvent(res.Events, "grant_denied", "ssh", "other.test"); !ok {
		t.Fatalf("other host was not denied: %+v", res.Events)
	}
	if len(*got) != 1 || !strings.HasPrefix((*got)[0], "allowed.test:") {
		t.Fatalf("dialed %#v", *got)
	}
}

func TestJailPATHIncludesToolchain(t *testing.T) {
	path := jailPATH()
	if !strings.Contains(":"+path+":", ":/usr/bin:") || !strings.Contains(":"+path+":", ":/bin:") {
		t.Fatalf("PATH = %s", path)
	}
	if strings.Contains(path, "/home/") || strings.Contains(path, "/Users/") || strings.Contains(path, "/snap/") || strings.Contains(path, "nvm") {
		t.Fatalf("PATH includes a private dir: %s", path)
	}
	res, err := runCmd(t, Request{Workspace: t.TempDir(), Command: `printf '%s' "$PATH"`})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != path && !strings.HasSuffix(res.Stdout, ":"+path) {
		t.Fatalf("jail PATH %q want %q", res.Stdout, path)
	}
	goBin := "/usr/local/go/bin/go"
	if st, err := os.Stat(goBin); err == nil && !st.IsDir() {
		res, err = runCmd(t, Request{Workspace: t.TempDir(), Command: "command -v go"})
		if err != nil || strings.TrimSpace(res.Stdout) != goBin {
			t.Fatalf("go lookup: %v stdout=%q stderr=%q", err, res.Stdout, res.Stderr)
		}
	}
}

func TestBuildBinds(t *testing.T) {
	tool := t.TempDir()
	if err := os.WriteFile(filepath.Join(tool, "tool.txt"), []byte("toolchain\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	badDir := filepath.Join(t.TempDir(), ".ssh")
	if err := os.MkdirAll(badDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ws := t.TempDir()
	cat := "cat " + filepath.Join(tool, "tool.txt") + " || echo missing"
	res, err := runCmd(t, Request{Workspace: ws, Command: cat})
	if strings.Contains(res.Stdout, "toolchain") {
		t.Fatal("toolchain was visible without the build grant")
	}
	if err == nil && !strings.Contains(res.Stdout, "missing") {
		t.Fatalf("ungranted cat succeeded: %v\n%s", err, res.Stdout)
	}
	res, err = runCmd(t, Request{
		Workspace:  ws,
		Command:    cat,
		Grants:     []string{"build"},
		BuildBinds: []string{ws, badDir, tool},
	})
	if err != nil || !strings.Contains(res.Stdout, "toolchain") {
		t.Fatalf("build bind missing: %v\n%s\n%s", err, res.Stdout, res.Stderr)
	}
	ev, ok := findEvent(res.Events, "grant_use", "build", "")
	if !ok || ev.Detail != tool+" read-only" {
		t.Fatalf("build event: %+v", res.Events)
	}
	if _, ok := findEvent(res.Events, "sandbox_block", "", ""); !ok {
		t.Fatalf("ssh bind was not refused: %+v", res.Events)
	}
}

func TestPackageInstallNotice(t *testing.T) {
	requireBin(t, "apt-get")
	res, err := runCmd(t, Request{Workspace: t.TempDir(), Command: "timeout 8 apt-get install lgb-no-such-pkg || true"})
	if err != nil {
		t.Fatal(err)
	}
	ev, ok := findEvent(res.Events, "grant_use", "", "")
	if !ok || ev.Notice != "Package install" {
		t.Fatalf("missing package notice: %+v", res.Events)
	}
}

func runJail(t *testing.T, req Request) (Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	res, err := Run(ctx, req)
	t.Logf("err=%v\nstdout:\n%s\nstderr:\n%s", err, res.Stdout, res.Stderr)
	return res, err
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func entropyCommand(secret string, strictDev bool) string {
	extra := ""
	if strictDev {
		extra = `
if test -e /dev/tty || test -e /dev/shm; then echo EXTRA_DEV; exit 1; fi
echo NO_EXTRA_DEV
`
	}
	return fmt.Sprintf(`set -eu
test -c /dev/null
test -c /dev/zero
test -c /dev/full
test -c /dev/random
test -c /dev/urandom
echo BEGIN_BYTES
od -An -N16 -tx1 /dev/urandom
echo END_BYTES
if cat /etc/passwd >/dev/null 2>&1; then echo PASSWD_READABLE; exit 1; fi
echo PASSWD_HIDDEN
if cat %s >/dev/null 2>&1; then echo HOST_READABLE; exit 1; fi
echo HOST_HIDDEN
%sssh-keygen -t ed25519 -f id_ed25519 -N "" -q
test -s id_ed25519
echo KEY_OK
`, shellQuote(secret), extra)
}

func hexByteCount(s string) int {
	n := 0
	for _, f := range strings.Fields(s) {
		if len(f) != 2 {
			continue
		}
		if _, err := strconv.ParseUint(f, 16, 8); err == nil {
			n++
		}
	}
	return n
}

func assertEntropyJail(t *testing.T, forceUnshare bool) {
	t.Helper()
	ws := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secret, []byte("TOPSECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := runJail(t, Request{
		Workspace:    ws,
		Command:      entropyCommand(secret, forceUnshare),
		forceUnshare: forceUnshare,
	})
	if err != nil {
		t.Fatalf("jail: %v\nstdout:\n%s\nstderr:\n%s", err, res.Stdout, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "PASSWD_HIDDEN") || strings.Contains(res.Stdout, "PASSWD_READABLE") {
		t.Fatalf("/etc/passwd was readable:\n%s", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "HOST_HIDDEN") || strings.Contains(res.Stdout, "HOST_READABLE") || strings.Contains(res.Stdout, "TOPSECRET") {
		t.Fatalf("host file was readable:\n%s", res.Stdout)
	}
	if forceUnshare && !strings.Contains(res.Stdout, "NO_EXTRA_DEV") {
		t.Fatalf("unshare jail exposed tty or shm:\n%s", res.Stdout)
	}
	start := strings.Index(res.Stdout, "BEGIN_BYTES")
	end := strings.Index(res.Stdout, "END_BYTES")
	if start < 0 || end < start {
		t.Fatalf("od output missing:\n%s", res.Stdout)
	}
	if n := hexByteCount(res.Stdout[start:end]); n != 16 {
		t.Fatalf("od printed %d bytes, want 16:\n%s", n, res.Stdout[start:end])
	}
	if !strings.Contains(res.Stdout, "KEY_OK") {
		t.Fatalf("ssh-keygen did not succeed:\n%s\n%s", res.Stdout, res.Stderr)
	}
	st, err := os.Stat(filepath.Join(ws, "id_ed25519"))
	if err != nil || st.Size() == 0 {
		t.Fatalf("jail key missing: %v", err)
	}
}

func TestEntropyDevices(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("bubblewrap and unshare are linux jails")
	}
	requireBin(t, "unshare")
	requireBin(t, "od")
	requireBin(t, "ssh-keygen")
	t.Run("unshare", func(t *testing.T) {
		// AppArmor's unprivileged_userns profile denies sys_admin, so
		// /usr/bin/unshare cannot write uid_map from this host. A privileged
		// container is unconfined root and can run the same launcher.
		// That container is opt-in so a normal go test does not start it.
		if os.Getenv("LGB_SANDBOX_INNER") != "1" && !canUnshare() {
			if os.Getenv("LGB_SANDBOX_DOCKER") != "1" {
				t.Skip("unprivileged user namespaces are blocked; set LGB_SANDBOX_DOCKER=1 to run this subtest in a privileged container")
			}
			reexecUnshare(t)
			return
		}
		assertEntropyJail(t, true)
	})
	if _, err := exec.LookPath("bwrap"); err == nil {
		t.Run("bwrap", func(t *testing.T) {
			assertEntropyJail(t, false)
		})
	}
}

func canUnshare() bool {
	cmd := exec.Command("unshare", "--user", "--map-root-user", "--mount", "--propagation", "private", "true")
	return cmd.Run() == nil
}

const unshareImageDockerfile = `FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client gcc libc6-dev && rm -rf /var/lib/apt/lists/*
`

func reexecUnshare(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("unshare cannot map root, and docker is unavailable: %v", err)
	}
	ensureUnshareImage(t)
	root := moduleRoot(t)
	goroot := strings.TrimSpace(mustOut(t, "go", "env", "GOROOT"))
	modcache := strings.TrimSpace(mustOut(t, "go", "env", "GOMODCACHE"))
	cmd := exec.Command("docker", "run", "--rm", "--privileged",
		"-e", "LGB_SANDBOX_INNER=1",
		"-e", "GOFLAGS=-mod=readonly",
		"-e", "GOPROXY=off",
		"-e", "GOTELEMETRY=off",
		"-e", "GOMODCACHE=/gomod",
		"-e", "GOCACHE=/tmp/gocache",
		"-e", "PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"-v", goroot+":/usr/local/go:ro",
		"-v", modcache+":/gomod:ro",
		"-v", root+":/src:ro",
		"-w", "/src",
		"lgb-sandbox-unshare:local",
		"go", "test", "./internal/sandbox/", "-count=1", "-run", "TestEntropyDevices/^unshare$", "-timeout", "120s",
	)
	out, err := cmd.CombinedOutput()
	t.Logf("inner unshare:\n%s", out)
	if err != nil {
		t.Fatalf("unshare jail via privileged container: %v\n%s", err, out)
	}
}

func ensureUnshareImage(t *testing.T) {
	t.Helper()
	if exec.Command("docker", "image", "inspect", "lgb-sandbox-unshare:local").Run() == nil {
		return
	}
	cmd := exec.Command("docker", "build", "-t", "lgb-sandbox-unshare:local", "-")
	cmd.Stdin = strings.NewReader(unshareImageDockerfile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build unshare test image: %v\n%s", err, out)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func mustOut(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		t.Fatalf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return string(out)
}

func TestRefusedBindHelper(t *testing.T) {
	if !refusedBind("/home/me/.ssh") || !refusedBind("/tmp/.gitconfig") || !refusedBind("/etc/gitconfig") {
		t.Fatal("credential paths were allowed")
	}
	if refusedBind("/opt/toolchains/go") {
		t.Fatal("toolchain path was refused")
	}
}
