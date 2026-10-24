//go:build unix

package daemon

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
		if reason := workspaceConfigReason(ws); reason != "" {
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
	if workspaceConfigReason(ws) != "" {
		t.Fatal("ordinary init config was refused")
	}
	for _, key := range []string{"url.http://attacker/.insteadOf", "credential.helper", "http.proxy", "core.fsmonitor", "core.askPass", "gpg.program"} {
		dir := t.TempDir()
		gitRepo(t, dir, "init")
		gitRepo(t, dir, "config", key, "/tmp/lgb-should-not-run")
		if workspaceConfigReason(dir) != "config" {
			t.Fatalf("%s was not refused", key)
		}
	}
	dir := t.TempDir()
	gitRepo(t, dir, "init")
	if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("[include]\n\tpath = /tmp/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if workspaceConfigReason(dir) != "config" {
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

func mustMirror(t *testing.T, ws string) string {
	t.Helper()
	dir, err := copyGitMirror(t.TempDir(), ws)
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
	cmd.Env = mirrorEnv(mirror)
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

func markerPresent(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func markerAbsent(path string) bool {
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}
