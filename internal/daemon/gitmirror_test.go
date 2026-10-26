//go:build unix

package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMirrorAuthorsMatch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
	commit := func(t *testing.T, env []string) string {
		t.Helper()
		dir := t.TempDir()
		git := func(args ...string) {
			t.Helper()
			cmd := exec.Command("git", args...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(),
				"GIT_CONFIG_GLOBAL=/dev/null",
				"GIT_CONFIG_SYSTEM=/dev/null",
				"GIT_CONFIG_NOSYSTEM=1",
			)
			cmd.Env = append(cmd.Env, env...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("git %v: %v\n%s", args, err, out)
			}
		}
		git("init")
		git("checkout", "-b", "feature")
		git("commit", "--allow-empty", "-m", "note")
		return filepath.Join(dir, ".git")
	}
	zero := strings.Repeat("0", 40)
	good := commit(t, []string{
		"GIT_AUTHOR_NAME=Ada",
		"GIT_AUTHOR_EMAIL=Ada@users.noreply",
		"GIT_COMMITTER_NAME=Ada",
		"GIT_COMMITTER_EMAIL=Ada@users.noreply",
	})
	if err := mirrorAuthorsMatch(context.Background(), good, zero, "refs/heads/feature", "Ada", "Ada@users.noreply"); err != nil {
		t.Fatal(err)
	}
	bad := commit(t, []string{
		"GIT_AUTHOR_NAME=Evil",
		"GIT_AUTHOR_EMAIL=evil@evil.example",
		"GIT_COMMITTER_NAME=Evil",
		"GIT_COMMITTER_EMAIL=evil@evil.example",
	})
	if err := mirrorAuthorsMatch(context.Background(), bad, zero, "refs/heads/feature", "Ada", "Ada@users.noreply"); err == nil {
		t.Fatal("foreign author was accepted")
	}
}

func TestMirrorIgnoresWorkspaceConfig(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
	t.Run("gpg", func(t *testing.T) {
		ws, mark, script := hostileRepo(t)
		gitRepo(t, ws, "config", "gpg.program", script)
		gitRepo(t, ws, "config", "log.showSignature", "true")
		forgeSignedCommit(t, ws)
		controlGit(t, ws, mark, nil, "log", "--stat")
		mirror := mustMirror(t, ws)
		if !markerAbsent(mark) {
			t.Fatal("marker survived the control cleanup")
		}
		if _, _, err := runGit(context.Background(), mirror, "log", "--stat"); err != nil && markerPresent(mark) {
			t.Fatal("mirror log ran gpg.program")
		}
		if markerPresent(mark) {
			t.Fatal("mirror log created the gpg marker")
		}
		appendConfig(t, mirror, "[gpg]\n\tprogram = "+script+"\n[log]\n\tshowSignature = true\n")
		_, _, _ = runGit(context.Background(), mirror, "log", "--stat")
		if markerPresent(mark) {
			t.Fatal("override did not stop gpg.program")
		}
		_, _, err := runGit(context.Background(), mirror, "log", "-n", "1", "--stat", "--no-show-signature", "--")
		if err != nil {
			t.Fatal(err)
		}
		if markerPresent(mark) {
			t.Fatal("signed log created the gpg marker")
		}
	})
	t.Run("fsmonitor", func(t *testing.T) {
		ws, mark, script := hostileRepo(t)
		gitRepo(t, ws, "config", "core.fsmonitor", script)
		controlGit(t, ws, mark, nil, "status")
		mirror := mustMirror(t, ws)
		_, _, _ = runGit(context.Background(), mirror, "status")
		if markerPresent(mark) {
			t.Fatal("mirror status ran core.fsmonitor")
		}
		appendConfig(t, mirror, "[core]\n\tfsmonitor = "+script+"\n")
		_, _, _ = runGit(context.Background(), mirror, "status")
		if markerPresent(mark) {
			t.Fatal("override did not stop core.fsmonitor")
		}
	})
	t.Run("textconv", func(t *testing.T) {
		ws, mark, script := hostileRepo(t)
		gitRepo(t, ws, "config", "diff.evil.textconv", script)
		attr := filepath.Join(ws, ".gitattributes")
		if err := os.WriteFile(attr, []byte("* diff=evil\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		gitRepo(t, ws, "add", ".gitattributes")
		gitRepo(t, ws, "commit", "-m", "attrs")
		info := filepath.Join(ws, ".git", "info")
		if err := os.MkdirAll(info, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(info, "attributes"), []byte("* diff=evil\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		controlGit(t, ws, mark, nil, "log", "-p")
		if reason := configReasonAt(t, ws); reason != "" {
			t.Fatalf("textconv config was refused: %s", reason)
		}
		mirror := mustMirror(t, ws)
		_, _, _ = runGit(context.Background(), mirror, "log", "-p")
		if markerPresent(mark) {
			t.Fatal("mirror log -p ran textconv")
		}
		if err := os.MkdirAll(filepath.Join(mirror, "info"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(mirror, "info", "attributes"), []byte("* diff=evil\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		appendConfig(t, mirror, "[diff \"evil\"]\n\ttextconv = "+script+"\n")
		_, _, err := runGit(context.Background(), mirror, "log", "-n", "5", "--stat", "--no-textconv", "--no-ext-diff", "--", "refs/heads/feature")
		if err != nil {
			t.Fatal(err)
		}
		if markerPresent(mark) {
			t.Fatal("production log ran textconv")
		}
	})
	t.Run("credential helper", func(t *testing.T) {
		ws, mark, script := hostileRepo(t)
		gitRepo(t, ws, "config", "credential.helper", script)
		up := authServer(t)
		controlGit(t, ws, mark, nil, "push", up+"/acme/widgets.git", "HEAD")
		mirror := mustMirror(t, ws)
		_, _, _ = runGit(context.Background(), mirror, "push", up+"/acme/widgets.git", "refs/heads/feature")
		if markerPresent(mark) {
			t.Fatal("mirror push ran credential.helper")
		}
		appendConfig(t, mirror, "[credential]\n\thelper = "+script+"\n")
		_, _, _ = runGit(context.Background(), mirror, "push", up+"/acme/widgets.git", "refs/heads/feature")
		if markerPresent(mark) {
			t.Fatal("override did not stop credential.helper")
		}
	})
	t.Run("askpass", func(t *testing.T) {
		ws, mark, script := hostileRepo(t)
		gitRepo(t, ws, "config", "core.askPass", script)
		fill := []byte("protocol=http\nhost=example.com\n\n")
		controlGit(t, ws, mark, fill, "credential", "fill")
		mirror := mustMirror(t, ws)
		askGit(t, mirror, nil, "credential", "fill")
		if markerPresent(mark) {
			t.Fatal("mirror credential fill ran core.askPass")
		}
		appendConfig(t, mirror, "[core]\n\taskPass = "+script+"\n")
		askGit(t, mirror, []string{"GIT_TERMINAL_PROMPT=1"}, "credential", "fill")
		if markerPresent(mark) {
			t.Fatal("override did not stop core.askPass")
		}
	})
}

func TestWorkspaceConfigRefusesHostileKeys(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
	ws := t.TempDir()
	gitRepo(t, ws, "init")
	gitRepo(t, ws, "checkout", "-b", "feature")
	if configReasonAt(t, ws) != "" {
		t.Fatal("ordinary init config was refused")
	}
	for _, key := range []string{"url.http://attacker/.insteadOf", "credential.helper", "http.proxy", "core.fsmonitor", "core.askPass", "gpg.program", "core.sshCommand", "core.hooksPath", "alias.push", "filter.evil.clean", "diff.external", "remote.origin.pushurl"} {
		dir := t.TempDir()
		gitRepo(t, dir, "init")
		gitRepo(t, dir, "config", key, "/tmp/lgb-should-not-run")
		if configReasonAt(t, dir) != "config" {
			t.Fatalf("%s was not refused", key)
		}
	}
	dir := t.TempDir()
	gitRepo(t, dir, "init")
	if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("[include]\n\tpath = /tmp/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if configReasonAt(t, dir) != "config" {
		t.Fatal("include was not refused")
	}
}

func hostileRepo(t *testing.T) (ws, mark, script string) {
	t.Helper()
	ws = t.TempDir()
	mark = filepath.Join(t.TempDir(), "mark")
	script = filepath.Join(t.TempDir(), "run.sh")
	body := "#!/bin/sh\nprintf 'ran\\n' > '" + mark + "'\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	gitRepo(t, ws, "init")
	gitRepo(t, ws, "checkout", "-b", "feature")
	if err := os.WriteFile(filepath.Join(ws, "readme.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRepo(t, ws, "add", "readme.txt")
	gitRepo(t, ws, "commit", "-m", "note")
	return ws, mark, script
}

func configReasonAt(t *testing.T, ws string) string {
	t.Helper()
	h, reason := resolveWorkspaceRepo(ws, ".")
	if reason != "" || h == nil {
		t.Fatalf("resolve config: %s", reason)
	}
	defer h.Close()
	return h.configReason()
}

func holdRepo(t *testing.T, ws, rel string) *repoHandle {
	t.Helper()
	h, reason := resolveWorkspaceRepo(ws, rel)
	if reason != "" || h == nil {
		t.Fatalf("resolve %s: %s", rel, reason)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func sameRepo(h *repoHandle, path string) bool {
	var st unix.Stat_t
	if h == nil || unix.Lstat(path, &st) != nil {
		return false
	}
	return uint64(st.Dev) == h.repoDev && uint64(st.Ino) == h.repoIno
}

func mustMirror(t *testing.T, ws string) string {
	t.Helper()
	h := holdRepo(t, ws, ".")
	dir, err := copyGitMirror(context.Background(), t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg, err := os.ReadFile(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfg), "fsmonitor") || strings.Contains(string(cfg), "textconv") || strings.Contains(string(cfg), "insteadOf") || strings.Contains(string(cfg), "askPass") {
		t.Fatalf("mirror config copied workspace keys:\n%s", cfg)
	}
	return dir
}

func controlGit(t *testing.T, ws, mark string, stdin []byte, args ...string) {
	t.Helper()
	_ = os.Remove(mark)
	cmd := exec.Command("git", append([]string{"-C", ws}, args...)...)
	cmd.Env = hostEnv(t, ws)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
		cmd.Env = append(cmd.Env, "GIT_TERMINAL_PROMPT=1")
	}
	out, err := cmd.CombinedOutput()
	if !markerPresent(mark) {
		t.Fatalf("control %v did not create a marker: %v %s", args, err, out)
	}
	if err := os.Remove(mark); err != nil {
		t.Fatal(err)
	}
}

func askGit(t *testing.T, mirror string, extra []string, args ...string) {
	t.Helper()
	ctx := context.Background()
	cmdArgs := append(gitFixedArgs(), args...)
	cmd := exec.CommandContext(ctx, "git", cmdArgs...)
	cmd.Dir = mirror
	cmd.Env = mirrorEnv(mirror, nil)
	for _, e := range extra {
		key, _, _ := strings.Cut(e, "=")
		prefix := key + "="
		replaced := false
		for i, cur := range cmd.Env {
			if strings.HasPrefix(cur, prefix) {
				cmd.Env[i] = e
				replaced = true
				break
			}
		}
		if !replaced {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Stdin = bytes.NewReader([]byte("protocol=http\nhost=example.com\n\n"))
	_, _ = cmd.CombinedOutput()
}

func hostEnv(t *testing.T, home string) []string {
	t.Helper()
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	}
}

func gitRepo(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = hostEnv(t, dir)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, b)
	}
}

func forgeSignedCommit(t *testing.T, dir string) {
	t.Helper()
	cmd := exec.Command("git", "-C", dir, "cat-file", "commit", "HEAD")
	cmd.Env = hostEnv(t, dir)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	parts := bytes.SplitN(raw, []byte("\n\n"), 2)
	if len(parts) != 2 {
		t.Fatal("commit")
	}
	sig := []byte("\ngpgsig -----BEGIN PGP SIGNATURE-----\n fake\n -----END PGP SIGNATURE-----")
	forged := append(append(parts[0], sig...), append([]byte("\n\n"), parts[1]...)...)
	hash := exec.Command("git", "-C", dir, "hash-object", "-t", "commit", "-w", "--stdin")
	hash.Env = hostEnv(t, dir)
	hash.Stdin = bytes.NewReader(forged)
	out, err := hash.Output()
	if err != nil {
		t.Fatalf("hash: %v %s", err, out)
	}
	sha := strings.TrimSpace(string(out))
	gitRepo(t, dir, "update-ref", "HEAD", sha)
}

func appendConfig(t *testing.T, mirror, text string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(mirror, "config"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(text)
	cerr := f.Close()
	if err != nil || cerr != nil {
		t.Fatal(err, cerr)
	}
}

func authServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="lgb"`)
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestMirrorPushSurvivesHostileWorkspace(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
	spec := []pushSpec{{src: "refs/heads/feature", dst: "refs/heads/feature", branch: "feature"}}
	t.Run("gpg", func(t *testing.T) {
		ws, mark, script := hostileRepo(t)
		gitRepo(t, ws, "config", "gpg.program", script)
		gitRepo(t, ws, "config", "log.showSignature", "true")
		forgeSignedCommit(t, ws)
		if configReasonAt(t, ws) != "config" {
			t.Fatal("gpg config was not refused")
		}
		controlGit(t, ws, mark, nil, "log", "--stat")
		assertCleanPush(t, ws, mark, spec)
	})
	t.Run("fsmonitor", func(t *testing.T) {
		ws, mark, script := hostileRepo(t)
		gitRepo(t, ws, "config", "core.fsmonitor", script)
		if configReasonAt(t, ws) != "config" {
			t.Fatal("fsmonitor was not refused")
		}
		controlGit(t, ws, mark, nil, "status")
		assertCleanPush(t, ws, mark, spec)
	})
	t.Run("textconv", func(t *testing.T) {
		ws, mark, script := hostileRepo(t)
		gitRepo(t, ws, "config", "diff.evil.textconv", script)
		if err := os.WriteFile(filepath.Join(ws, ".gitattributes"), []byte("* diff=evil\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		gitRepo(t, ws, "add", ".gitattributes")
		gitRepo(t, ws, "commit", "-m", "attrs")
		info := filepath.Join(ws, ".git", "info")
		if err := os.MkdirAll(info, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(info, "attributes"), []byte("* diff=evil\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if configReasonAt(t, ws) != "" {
			t.Fatal("textconv config was refused")
		}
		controlGit(t, ws, mark, nil, "log", "-p")
		assertCleanPush(t, ws, mark, spec)
	})
	t.Run("credential helper", func(t *testing.T) {
		ws, mark, script := hostileRepo(t)
		gitRepo(t, ws, "config", "credential.helper", script)
		if configReasonAt(t, ws) != "config" {
			t.Fatal("credential helper was not refused")
		}
		controlGit(t, ws, mark, nil, "push", authServer(t)+"/acme/widgets.git", "HEAD")
		assertCleanPush(t, ws, mark, spec)
	})
	t.Run("askpass", func(t *testing.T) {
		ws, mark, script := hostileRepo(t)
		gitRepo(t, ws, "config", "core.askPass", script)
		if configReasonAt(t, ws) != "config" {
			t.Fatal("askpass was not refused")
		}
		controlGit(t, ws, mark, []byte("protocol=http\nhost=example.com\n\n"), "credential", "fill")
		assertCleanPush(t, ws, mark, spec)
	})
	t.Run("sshCommand", func(t *testing.T) {
		ws, mark, script := hostileRepo(t)
		gitRepo(t, ws, "config", "core.sshCommand", script)
		if configReasonAt(t, ws) != "config" {
			t.Fatal("sshCommand was not refused")
		}
		controlTimeout(t, ws, mark, "ls-remote", "git@example.com:acme/widgets.git")
		assertCleanPush(t, ws, mark, spec)
	})
	t.Run("hooksPath", func(t *testing.T) {
		ws, mark, script := hostileRepo(t)
		hookDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(hookDir, "pre-commit"), []byte("#!/bin/sh\n'"+script+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		gitRepo(t, ws, "config", "core.hooksPath", hookDir)
		if configReasonAt(t, ws) != "config" {
			t.Fatal("hooksPath was not refused")
		}
		controlTimeout(t, ws, mark, "commit", "--allow-empty", "-m", "hook")
		assertCleanPush(t, ws, mark, spec)
	})
	t.Run("alias", func(t *testing.T) {
		ws, mark, script := hostileRepo(t)
		gitRepo(t, ws, "config", "alias.st", "!"+script)
		gitRepo(t, ws, "config", "alias.push", "!"+script)
		if configReasonAt(t, ws) != "config" {
			t.Fatal("alias was not refused")
		}
		controlTimeout(t, ws, mark, "st")
		assertCleanPush(t, ws, mark, spec)
	})
	t.Run("filter", func(t *testing.T) {
		ws, mark, script := hostileRepo(t)
		gitRepo(t, ws, "config", "filter.evil.clean", script)
		gitRepo(t, ws, "config", "filter.evil.smudge", script)
		if err := os.WriteFile(filepath.Join(ws, ".gitattributes"), []byte("* filter=evil\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if configReasonAt(t, ws) != "config" {
			t.Fatal("filter was not refused")
		}
		if err := os.WriteFile(filepath.Join(ws, "extra.txt"), []byte("more\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		controlTimeout(t, ws, mark, "add", "extra.txt")
		assertCleanPush(t, ws, mark, spec)
	})
	t.Run("diff external", func(t *testing.T) {
		ws, mark, script := hostileRepo(t)
		if err := os.WriteFile(filepath.Join(ws, "readme.txt"), []byte("hello\nmore\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		gitRepo(t, ws, "add", "readme.txt")
		gitRepo(t, ws, "commit", "-m", "more")
		gitRepo(t, ws, "config", "diff.external", script)
		if configReasonAt(t, ws) != "config" {
			t.Fatal("diff.external was not refused")
		}
		controlTimeout(t, ws, mark, "diff", "HEAD~1", "HEAD")
		assertCleanPush(t, ws, mark, spec)
	})
	t.Run("pushurl", func(t *testing.T) {
		ws, mark, _ := hostileRepo(t)
		good, bad := splitServers(t)
		gitRepo(t, ws, "remote", "add", "origin", good.URL+"/acme/widgets.git")
		gitRepo(t, ws, "config", "remote.origin.pushurl", bad.URL+"/stolen.git")
		if configReasonAt(t, ws) != "config" {
			t.Fatal("pushurl was not refused")
		}
		runWorkspaceGit(t, ws, "push", "origin", "HEAD:refs/heads/feature")
		bad.mu.Lock()
		badPath := bad.path
		bad.mu.Unlock()
		if bad.hits.Load() == 0 || !strings.Contains(badPath, "/stolen.git") {
			t.Fatalf("control pushurl hits=%d path=%s", bad.hits.Load(), badPath)
		}
		bad.hits.Store(0)
		good.hits.Store(0)
		assertCleanPushTo(t, ws, mark, spec, good, bad)
	})
	t.Run("insteadOf", func(t *testing.T) {
		ws, mark, _ := hostileRepo(t)
		good, bad := splitServers(t)
		gitRepo(t, ws, "config", "url."+bad.URL+"/p/.insteadOf", "http://127.0.0.1:")
		gitRepo(t, ws, "config", "url."+bad.URL+"/p/.pushInsteadOf", "http://127.0.0.1:")
		if configReasonAt(t, ws) != "config" {
			t.Fatal("insteadOf was not refused")
		}
		runWorkspaceGit(t, ws, "ls-remote", good.URL+"/acme/widgets.git")
		if bad.hits.Load() == 0 {
			t.Fatal("control insteadOf did not redirect")
		}
		bad.hits.Store(0)
		good.hits.Store(0)
		_ = os.Remove(mark)
		assertCleanPushTo(t, ws, mark, spec, good, bad)
	})
}

type hitServer struct {
	URL  string
	hits *atomic.Int32
	path string
	mu   sync.Mutex
}

func splitServers(t *testing.T) (good, bad *hitServer) {
	t.Helper()
	mk := func() *hitServer {
		t.Helper()
		hs := &hitServer{hits: &atomic.Int32{}}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hs.hits.Add(1)
			hs.mu.Lock()
			hs.path = r.URL.Path
			hs.mu.Unlock()
			http.NotFound(w, r)
		}))
		t.Cleanup(srv.Close)
		hs.URL = srv.URL
		return hs
	}
	return mk(), mk()
}

func assertCleanPush(t *testing.T, ws, mark string, specs []pushSpec) {
	t.Helper()
	good, bad := splitServers(t)
	assertCleanPushTo(t, ws, mark, specs, good, bad)
}

func assertCleanPushTo(t *testing.T, ws, mark string, specs []pushSpec, good, bad *hitServer) {
	t.Helper()
	if markerPresent(mark) {
		t.Fatal("marker was still present before the mirror")
	}
	mirror := mustMirror(t, ws)
	log, err := mirrorLog(context.Background(), mirror, specs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log, "note") {
		t.Fatalf("commit list %q", log)
	}
	if markerPresent(mark) {
		t.Fatal("commit list created a marker")
	}
	remote := good.URL + "/acme/widgets.git"
	_, _ = mirrorPush(context.Background(), mirror, remote, "0123456789abcdef0123456789abcdef", specs)
	if good.hits.Load() == 0 {
		t.Fatal("push did not reach the intended host")
	}
	if bad != nil && bad.hits.Load() != 0 {
		t.Fatal("push reached another host")
	}
	good.mu.Lock()
	path := good.path
	good.mu.Unlock()
	if !strings.Contains(path, "/acme/widgets.git") || strings.Contains(path, "stolen") {
		t.Fatalf("push target %s", path)
	}
	if markerPresent(mark) {
		t.Fatal("push created a marker")
	}
}

func runWorkspaceGit(t *testing.T, ws string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", ws}, args...)...)
	cmd.Env = hostEnv(t, ws)
	_, _ = cmd.CombinedOutput()
}

func controlTimeout(t *testing.T, ws, mark string, args ...string) {
	t.Helper()
	_ = os.Remove(mark)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", ws}, args...)...)
	cmd.Env = hostEnv(t, ws)
	out, _ := cmd.CombinedOutput()
	if !markerPresent(mark) {
		t.Fatalf("control %v did not create a marker: %s", args, out)
	}
	if err := os.Remove(mark); err != nil {
		t.Fatal(err)
	}
}

func TestPushPlanOmitsGateFromArgv(t *testing.T) {
	const gate = "abc123secretgateabc123secretgate"
	remote := "http://127.0.0.1:9/github/acme/widgets.git"
	args, cfg, err := pushPlan(remote, gate, []pushSpec{{
		src: "refs/heads/feature", dst: "refs/heads/feature", branch: "feature",
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range args {
		if strings.Contains(arg, gate) || strings.Contains(arg, remote) {
			t.Fatalf("gate in argv %q", arg)
		}
	}
	if len(args) < 2 || args[0] != "push" || args[1] != "lgbpush" {
		t.Fatalf("args %v", args)
	}
	var sawURL, sawHeader bool
	for _, pair := range cfg {
		if strings.Contains(pair[1], gate) && pair[0] != "http.extraHeader" {
			t.Fatalf("gate in config %q", pair[0])
		}
		if pair[0] == "http.extraHeader" && pair[1] == "X-LGB-Gate: "+gate {
			sawHeader = true
		}
		if strings.Contains(pair[1], remote) && (pair[0] == "remote.lgbpush.url" || pair[0] == "remote.lgbpush.pushurl") {
			sawURL = true
			if strings.Contains(pair[1], gate) {
				t.Fatalf("gate in push url %q", pair[1])
			}
		}
		if strings.Contains(pair[0], gate) {
			t.Fatalf("gate in config key %q", pair[0])
		}
	}
	if !sawURL || !sawHeader {
		t.Fatal("push url or gate header was not passed as git config")
	}
	if _, _, err := pushPlan(remote+"/"+gate, gate, []pushSpec{{
		src: "refs/heads/feature", dst: "refs/heads/feature", branch: "feature",
	}}); err == nil {
		t.Fatal("push plan accepted a url that contains the gate")
	}
}

func TestMirrorInsteadOfDoesNotRedirect(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
	const gate = "abc123secretgateabc123secretgate"
	var goodHits, badHits atomic.Int32
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		goodHits.Add(1)
		if strings.Contains(r.URL.Path, gate) || strings.Contains(r.URL.RawQuery, gate) {
			t.Errorf("gate in request target")
		}
		if r.Header.Get("X-LGB-Gate") != gate {
			t.Errorf("missing gate header")
		}
		http.NotFound(w, r)
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		badHits.Add(1)
		http.NotFound(w, r)
	}))
	defer bad.Close()

	ws, _, _ := hostileRepo(t)
	mirror := mustMirror(t, ws)
	appendConfig(t, mirror, "[url \""+bad.URL+"/p/\"]\n\tinsteadOf = http://127.0.0.1:\n\tpushInsteadOf = http://127.0.0.1:\n")
	remote := good.URL + "/github/acme/widgets.git"
	var got []string
	prev := commandContext
	commandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		got = append([]string{name}, args...)
		return exec.CommandContext(ctx, name, args...)
	}
	t.Cleanup(func() { commandContext = prev })
	_, _ = mirrorPush(context.Background(), mirror, remote, gate, []pushSpec{{
		src: "refs/heads/feature", dst: "refs/heads/feature", branch: "feature",
	}})
	if goodHits.Load() == 0 {
		t.Fatal("push did not reach the write-gate host")
	}
	if badHits.Load() != 0 {
		t.Fatal("mirror insteadOf redirected the push")
	}
	for _, arg := range got {
		if strings.Contains(arg, gate) || strings.Contains(arg, remote) {
			t.Fatalf("gate in constructed argv %q", arg)
		}
	}
	cfg, err := os.ReadFile(filepath.Join(mirror, "config"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfg), "insteadOf") || strings.Contains(string(cfg), "pushInsteadOf") {
		t.Fatalf("mirror config kept a url rewrite:\n%s", cfg)
	}
}

func TestResolveWorkspaceRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
	ws := t.TempDir()
	scratch := filepath.Join(ws, "scratch")
	if err := os.Mkdir(scratch, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRepo(t, scratch, "init")
	sub := filepath.Join(scratch, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	got := holdRepo(t, ws, "scratch")
	if !sameRepo(got, scratch) {
		t.Fatal("scratch")
	}
	got = holdRepo(t, ws, "scratch/sub")
	if !sameRepo(got, scratch) {
		t.Fatal("nested")
	}
	if reason := resolveReason(ws, "."); reason != "repository not found in workspace" {
		t.Fatalf("workspace root %q", reason)
	}
	if err := os.Symlink("scratch", filepath.Join(ws, "link")); err != nil {
		t.Fatal(err)
	}
	if reason := resolveReason(ws, "link"); reason != "symlink" {
		t.Fatalf("symlink %q", reason)
	}
	if reason := resolveReason(ws, "link/sub"); reason != "symlink" {
		t.Fatalf("symlink nested %q", reason)
	}
	for _, rel := range []string{"", "..", "scratch/../../etc", "/etc", "foo/../bar", `scratch\sub`} {
		if reason := resolveReason(ws, rel); reason != "path" {
			t.Fatalf("%q -> %q", rel, reason)
		}
	}
	gf := filepath.Join(ws, "gf")
	if err := os.Mkdir(gf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gf, ".git"), []byte("gitdir: /tmp/elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if reason := resolveReason(ws, "gf"); reason != "gitfile" {
		t.Fatalf("gitfile %q", reason)
	}
	if err := os.Symlink("scratch/.git", filepath.Join(ws, "dotgit")); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(ws, "linked")
	if err := os.Mkdir(linked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nope", filepath.Join(linked, ".git")); err != nil {
		t.Fatal(err)
	}
	if reason := resolveReason(ws, "linked"); reason != "symlink" {
		t.Fatalf("git symlink %q", reason)
	}
	empty := filepath.Join(ws, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if reason := resolveReason(ws, "empty"); reason != "repository not found in workspace" {
		t.Fatalf("empty %q", reason)
	}
	odd := filepath.Join(ws, "foo..bar")
	if err := os.Mkdir(odd, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRepo(t, odd, "init")
	got = holdRepo(t, ws, "foo..bar")
	if !sameRepo(got, odd) {
		t.Fatal("dots")
	}
}

func resolveReason(ws, rel string) string {
	h, reason := resolveWorkspaceRepo(ws, rel)
	if h != nil {
		_ = h.Close()
	}
	return reason
}

func TestMirrorPushGateStaysOutOfCmdline(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	gate := hex.EncodeToString(buf)
	ws, _, _ := hostileRepo(t)
	mirror := mustMirror(t, ws)
	var leaked atomic.Bool
	var sawRemote atomic.Bool
	note := func() {
		leak, remote := scanCmdline(gate)
		if leak {
			leaked.Store(true)
		}
		if remote {
			sawRemote.Store(true)
		}
	}
	var mu sync.Mutex
	var sawHeader bool
	var gateInTarget bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		note()
		if strings.Contains(r.URL.Path, gate) || strings.Contains(r.URL.RawQuery, gate) {
			mu.Lock()
			gateInTarget = true
			mu.Unlock()
		}
		if r.Header.Get("X-LGB-Gate") == gate {
			mu.Lock()
			sawHeader = true
			mu.Unlock()
		}
		time.Sleep(1500 * time.Millisecond)
		note()
		http.NotFound(w, r)
	}))
	defer up.Close()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				note()
			}
		}
	}()
	remote := up.URL + "/github/acme/widgets.git"
	_, _ = mirrorPush(context.Background(), mirror, remote, gate, []pushSpec{{
		src: "refs/heads/feature", dst: "refs/heads/feature", branch: "feature",
	}})
	close(stop)
	wg.Wait()
	note()
	if leaked.Load() {
		t.Fatal("gate appeared in a process cmdline")
	}
	if !sawRemote.Load() {
		t.Fatal("remote-http was not observed")
	}
	mu.Lock()
	defer mu.Unlock()
	if gateInTarget {
		t.Fatal("gate appeared in the request target")
	}
	if !sawHeader {
		t.Fatal("upstream did not receive the gate header")
	}
}

func scanCmdline(gate string) (leaked, remote bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, false
	}
	needle := []byte(gate)
	for _, e := range entries {
		name := e.Name()
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		b, err := os.ReadFile("/proc/" + name + "/cmdline")
		if err != nil || len(b) == 0 {
			continue
		}
		if bytes.Contains(b, needle) {
			leaked = true
		}
		if bytes.Contains(b, []byte("remote-http")) {
			remote = true
		}
	}
	return leaked, remote
}

func markerPresent(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func markerAbsent(path string) bool {
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}

func writeRepo(t *testing.T, dir, file, body, msg string) {
	t.Helper()
	gitRepo(t, dir, "init")
	gitRepo(t, dir, "checkout", "-b", "feature")
	if err := os.WriteFile(filepath.Join(dir, file), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRepo(t, dir, "add", file)
	gitRepo(t, dir, "commit", "-m", msg)
}

func TestMirrorSwapIntermediateDirectory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
	ws := t.TempDir()
	proj := filepath.Join(ws, "sub", "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	writeRepo(t, proj, "readme.txt", "original-bytes\n", "original-subject")
	outside := t.TempDir()
	outProj := filepath.Join(outside, "proj")
	if err := os.MkdirAll(outProj, 0o755); err != nil {
		t.Fatal(err)
	}
	writeRepo(t, outProj, "secret.txt", "HOST-MARKER-OBJECT\n", "HOST-SECRET-COMMIT")
	assertSwapCopy(t, ws, "sub/proj", proj, outProj, func() {
		sub := filepath.Join(ws, "sub")
		if err := os.Rename(sub, sub+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, sub); err != nil {
			t.Fatal(err)
		}
	})
}

func TestMirrorSwapGitDirectory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
	ws := t.TempDir()
	proj := filepath.Join(ws, "sub", "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	writeRepo(t, proj, "readme.txt", "original-bytes\n", "original-subject")
	outside := t.TempDir()
	outProj := filepath.Join(outside, "proj")
	if err := os.MkdirAll(outProj, 0o755); err != nil {
		t.Fatal(err)
	}
	writeRepo(t, outProj, "secret.txt", "HOST-MARKER-OBJECT\n", "HOST-SECRET-COMMIT")
	assertSwapCopy(t, ws, "sub/proj", proj, outProj, func() {
		gitDir := filepath.Join(proj, ".git")
		if err := os.Rename(gitDir, gitDir+".orig"); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(outProj, ".git"), gitDir); err != nil {
			t.Fatal(err)
		}
	})
}

func assertSwapCopy(t *testing.T, ws, rel, proj, outProj string, swap func()) {
	t.Helper()
	origHead := strings.TrimSpace(gitRepoOut(t, proj, "rev-parse", "HEAD"))
	outsideHead := strings.TrimSpace(gitRepoOut(t, outProj, "rev-parse", "HEAD"))
	if origHead == "" || origHead == outsideHead {
		t.Fatalf("heads %s %s", origHead, outsideHead)
	}
	h := holdRepo(t, ws, rel)
	parent := t.TempDir()
	beforeMirrorCopy = swap
	t.Cleanup(func() { beforeMirrorCopy = nil })
	mirror, err := copyGitMirror(context.Background(), parent, h)
	if mirror != "" {
		t.Cleanup(func() { _ = os.RemoveAll(mirror) })
	}
	if err != nil {
		if mirror != "" {
			t.Fatalf("refused copy returned %s", mirror)
		}
		left, rerr := os.ReadDir(parent)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if len(left) != 0 {
			t.Fatalf("partial mirror remains: %v", left)
		}
		return
	}
	patch := gitRepoOut(t, mirror, "--git-dir", mirror, "log", "-p", "--all")
	if strings.Contains(patch, "HOST-MARKER-OBJECT") || strings.Contains(patch, "HOST-SECRET-COMMIT") {
		t.Fatalf("mirror contains the outside repository:\n%s", patch)
	}
	if !strings.Contains(patch, "original-subject") || !strings.Contains(patch, "original-bytes") {
		t.Fatalf("mirror lost the original repository:\n%s", patch)
	}
	got := strings.TrimSpace(gitRepoOut(t, mirror, "--git-dir", mirror, "rev-parse", "HEAD"))
	if got != origHead {
		t.Fatalf("mirror HEAD %s original %s", got, origHead)
	}
	cmd := exec.Command("git", "--git-dir", mirror, "cat-file", "-e", outsideHead+"^{commit}")
	cmd.Env = hostEnv(t, mirror)
	if out, cerr := cmd.CombinedOutput(); cerr == nil {
		t.Fatalf("outside commit is reachable: %s", out)
	}
}

func gitRepoOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if len(args) > 0 && args[0] == "--git-dir" {
		cmd = exec.Command("git", args...)
	}
	cmd.Env = hostEnv(t, dir)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, b)
	}
	return string(b)
}

func writePlainGit(t *testing.T, proj string) {
	t.Helper()
	git := filepath.Join(proj, ".git")
	for _, sub := range []string{"refs/heads", "objects"} {
		if err := os.MkdirAll(filepath.Join(git, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"HEAD":               "ref: refs/heads/feature\n",
		"config":             "[core]\n\trepositoryformatversion = 0\n",
		"refs/heads/feature": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(git, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCancelledCopyRemovesMirror(t *testing.T) {
	ws := t.TempDir()
	proj := filepath.Join(ws, "proj")
	writePlainGit(t, proj)
	h := holdRepo(t, ws, "proj")
	parent := t.TempDir()
	okDir, err := copyGitMirror(context.Background(), parent, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(okDir); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	prev := beforeMirrorCopy
	beforeMirrorCopy = cancel
	t.Cleanup(func() { beforeMirrorCopy = prev })
	dir, err := copyGitMirror(ctx, parent, h)
	if err == nil || dir != "" {
		t.Fatalf("cancelled copy returned %q %v", dir, err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	left, rerr := os.ReadDir(parent)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(left) != 0 {
		t.Fatalf("partial mirror %v", left)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	dir, err = copyGitMirror(ctx2, parent, h)
	if err == nil || dir != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("already cancelled: %q %v", dir, err)
	}
	left, rerr = os.ReadDir(parent)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(left) != 0 {
		t.Fatalf("partial mirror %v", left)
	}
}

func TestMountIDMismatchRefusesWalkAndCopy(t *testing.T) {
	prev := mountID
	t.Cleanup(func() { mountID = prev })

	ws := t.TempDir()
	if err := os.Mkdir(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(ws, "proj")
	writePlainGit(t, proj)
	h := holdRepo(t, ws, "proj")

	mountID = func(fd int) (uint64, bool) {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			return 0, false
		}
		return uint64(st.Ino), true
	}
	root, err := unix.Open(ws, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root)
	if nodes, err := openChainWalk(root, []string{"sub"}); err == nil || !errors.Is(err, unix.EXDEV) {
		closeHeldDirs(nodes)
		t.Fatalf("walk %v", err)
	}
	parent := t.TempDir()
	if dir, err := copyGitMirror(context.Background(), parent, h); err == nil || dir != "" || !strings.Contains(err.Error(), "device") {
		if dir != "" {
			_ = os.RemoveAll(dir)
		}
		t.Fatalf("copy %q %v", dir, err)
	}
	left, rerr := os.ReadDir(parent)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(left) != 0 {
		t.Fatalf("partial mirror %v", left)
	}

	mountID = func(int) (uint64, bool) { return 0, false }
	nodes, err := openChainWalk(root, []string{"sub"})
	if err != nil {
		t.Fatal(err)
	}
	closeHeldDirs(nodes)
	dir, err := copyGitMirror(context.Background(), parent, h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
}

func TestMirrorEnvStripsTrace(t *testing.T) {
	keys := []string{
		"GIT_TRACE", "GIT_TRACE_CURL", "GIT_TRACE_PACKET", "GIT_TRACE2",
		"GIT_TRACE2_EVENT", "GIT_TRACE_SETUP", "GIT_CURL_VERBOSE",
	}
	for _, key := range keys {
		t.Setenv(key, "1")
	}
	t.Setenv("PATH", "/usr/bin:/bin")
	for _, e := range mirrorEnv(t.TempDir(), [][2]string{{"http.extraHeader", "X-LGB-Gate: secret"}}) {
		key, _, _ := strings.Cut(e, "=")
		if traceEnv(key) {
			t.Fatalf("mirror env carried %s", key)
		}
	}
	dir := t.TempDir()
	prev := commandContext
	commandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "env")
	}
	t.Cleanup(func() { commandContext = prev })
	stdout, stderr, err := execGit(context.Background(), dir, []string{
		"GIT_TRACE=1", "GIT_TRACE2_EVENT=1", "GIT_CURL_VERBOSE=1", "FOO=bar",
	}, nil, "status")
	if err != nil {
		t.Fatalf("exec %v %s", err, stderr)
	}
	text := string(stdout)
	for _, line := range strings.Split(text, "\n") {
		key, _, _ := strings.Cut(line, "=")
		if traceEnv(key) {
			t.Fatalf("exec env carried %s", line)
		}
	}
	if !strings.Contains(text, "FOO=bar") {
		t.Fatalf("dropped a normal extra:\n%s", text)
	}
}
