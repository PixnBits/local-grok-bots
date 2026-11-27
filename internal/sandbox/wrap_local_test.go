package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func installGitWrapLogged(t *testing.T, work string, opts gitWrapOpts) (string, string) {
	t.Helper()
	if opts.Name == "" {
		opts.Name = "Ada"
	}
	if opts.Email == "" {
		opts.Email = "bot@localhost"
	}
	wrap := installGitWrapWith(t, work, opts)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(logPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(wrap)
	if err != nil {
		t.Fatal(err)
	}
	next := strings.ReplaceAll(string(body), "log=/lgb/events/log", "log="+logPath)
	if next == string(body) {
		t.Fatal("wrapper log path was not rewritten")
	}
	if err := os.WriteFile(wrap, []byte(next), 0o700); err != nil {
		t.Fatal(err)
	}
	return wrap, logPath
}

func withPushURL(t *testing.T, dir, remote, url string) {
	t.Helper()
	gitCmd(t, dir, "config", "remote."+remote+".pushurl", url)
}

func TestGitWrapLocalOnlyPushURL(t *testing.T) {
	work := t.TempDir()
	wrap, logPath := installGitWrapLogged(t, work, gitWrapOpts{Grant: true})
	src := filepath.Join(work, "src")
	commitRepo(t, src, "f.txt", "hi\n")
	dir := filepath.Join(work, "repo")
	commitRepo(t, dir, "a.txt", "a\n")
	gitCmd(t, dir, "config", "user.name", "Ada")
	gitCmd(t, dir, "config", "user.email", "ada@example.com")
	gitCmd(t, dir, "remote", "add", "origin", "file://"+src)
	withPushURL(t, dir, "github-readonly-disabled", "disabled")
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"status"},
		{"diff"},
		{"log", "-1"},
		{"rev-parse", "HEAD"},
		{"show", "HEAD"},
		{"branch"},
		{"add", "b.txt"},
		{"commit", "-m", "b"},
		{"checkout", "-b", "side"},
		{"checkout", "main"},
		{"switch", "-c", "side2"},
		{"switch", "main"},
		{"stash"},
		{"restore", "a.txt"},
		{"reset"},
	} {
		out, err := runInstalledWrap(t, wrap, dir, nil, args...)
		if err != nil || strings.Contains(out, "configuration is not allowed") {
			t.Fatalf("local %v: %v\n%s", args, err, out)
		}
	}
	audit, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "local-only git status skip remote.github-readonly-disabled.pushurl"
	if !strings.Contains(string(audit), want) {
		t.Fatalf("audit missing %q\n%s", want, audit)
	}
}

func TestGitWrapLocalOnlyNoRemote(t *testing.T) {
	work := t.TempDir()
	wrap, _ := installGitWrapLogged(t, work, gitWrapOpts{Grant: true})
	dir := filepath.Join(work, "repo")
	commitRepo(t, dir, "a.txt", "a\n")
	gitCmd(t, dir, "config", "user.name", "Ada")
	gitCmd(t, dir, "config", "user.email", "ada@example.com")
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"status"},
		{"diff"},
		{"log", "-1"},
		{"add", "b.txt"},
		{"commit", "-m", "b"},
	} {
		out, err := runInstalledWrap(t, wrap, dir, nil, args...)
		if err != nil || strings.Contains(out, "configuration is not allowed") {
			t.Fatalf("no remote %v: %v\n%s", args, err, out)
		}
	}
}

func TestGitWrapLocalOnlyRemoteOpsStayRefused(t *testing.T) {
	work := t.TempDir()
	wrap, _ := installGitWrapLogged(t, work, gitWrapOpts{Grant: true})
	src := filepath.Join(work, "src")
	commitRepo(t, src, "f.txt", "hi\n")
	dir := filepath.Join(work, "repo")
	commitRepo(t, dir, "a.txt", "a\n")
	gitCmd(t, dir, "remote", "add", "origin", "file://"+src)
	gitCmd(t, dir, "config", "branch.main.remote", "origin")
	gitCmd(t, dir, "config", "branch.main.merge", "refs/heads/main")
	withPushURL(t, dir, "origin", "file://"+src)
	refused := [][]string{
		{"push", "origin", "main"},
		{"fetch", "origin"},
		{"pull", "origin", "main"},
		{"ls-remote", "origin"},
		{"clone", "file://" + src, filepath.Join(dir, "child")},
		{"remote", "update"},
	}
	for _, args := range refused {
		out, err := runInstalledWrap(t, wrap, dir, nil, args...)
		if err == nil || !strings.Contains(out, "configuration is not allowed") || !strings.Contains(out, "pushurl") {
			t.Fatalf("remote %v should stay config-denied: %v\n%s", args, err, out)
		}
	}
}

func TestGitWrapLocalOnlyDangerousKeysStayRefused(t *testing.T) {
	work := t.TempDir()
	wrap, _ := installGitWrapLogged(t, work, gitWrapOpts{Grant: true})
	dir := filepath.Join(work, "repo")
	commitRepo(t, dir, "a.txt", "a\n")
	gitCmd(t, dir, "config", "user.name", "Ada")
	gitCmd(t, dir, "config", "user.email", "ada@example.com")
	for _, key := range []string{
		"core.hooksPath", "core.fsmonitor", "alias.st",
		"remote.origin.receivepack", "remote.origin.uploadpack",
		"url.base.pushInsteadOf", "remote.ori@gin.pushurl",
	} {
		gitCmd(t, dir, "config", key, "true")
		for _, args := range [][]string{{"status"}, {"commit", "-m", "no"}} {
			out, err := runInstalledWrap(t, wrap, dir, nil, args...)
			mark := strings.ToLower(refusedKeyMark(key))
			if err == nil || !strings.Contains(out, "configuration is not allowed") || !strings.Contains(strings.ToLower(out), mark) {
				t.Fatalf("%s %v: %v\n%s", key, args, err, out)
			}
		}
		gitCmd(t, dir, "config", "--unset", key)
	}
}

func refusedKeyMark(key string) string {
	switch key {
	case "remote.origin.receivepack":
		return "receivepack"
	case "remote.origin.uploadpack":
		return "uploadpack"
	case "url.base.pushInsteadOf":
		return "pushInsteadOf"
	case "remote.ori@gin.pushurl":
		return "ori?gin"
	default:
		return key
	}
}

func TestGitWrapProbeFailureStaysRefused(t *testing.T) {
	work := t.TempDir()
	wrap, _ := installGitWrapLogged(t, work, gitWrapOpts{Grant: true, Hub: true})
	src := filepath.Join(work, "src")
	commitRepo(t, src, "f.txt", "hi\n")
	dir := filepath.Join(work, "repo")
	commitRepo(t, dir, "a.txt", "a\n")
	gitCmd(t, dir, "remote", "add", "origin", "file://"+src)
	gitCmd(t, dir, "config", "--replace-all", "remote.origin.fetch", "::")
	withPushURL(t, dir, "origin", "disabled")
	out, err := runInstalledWrap(t, wrap, dir, nil, "status")
	if err == nil || !strings.Contains(out, "configuration is not allowed") || !strings.Contains(out, "pushurl") {
		t.Fatalf("probe failure status: %v\n%s", err, out)
	}
}

func TestGitWrapHubRemoteStillRefusesPushURL(t *testing.T) {
	work := t.TempDir()
	wrap, _ := installGitWrapLogged(t, work, gitWrapOpts{Grant: true, Hub: true})
	src := filepath.Join(work, "src")
	commitRepo(t, src, "f.txt", "hi\n")
	dir := filepath.Join(work, "repo")
	commitRepo(t, dir, "a.txt", "a\n")
	gitCmd(t, dir, "remote", "add", "origin", "file://"+src)
	withPushURL(t, dir, "origin", "disabled")
	out, err := runInstalledWrap(t, wrap, dir, nil, "status")
	if err == nil || !strings.Contains(out, "configuration is not allowed") || !strings.Contains(out, "pushurl") {
		t.Fatalf("hub status: %v\n%s", err, out)
	}
}

func TestGitWrapLocalOnlyGoBuildVCS(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	wrap, _ := installGitWrapLogged(t, work, gitWrapOpts{Grant: true})
	dir := filepath.Join(work, "mod")
	commitRepo(t, dir, "main.go", "package main\nfunc main() {}\n")
	gitCmd(t, dir, "remote", "add", "origin", "file://"+filepath.Join(work, "nowhere"))
	withPushURL(t, dir, "github-readonly-disabled", "disabled")
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/vcs\n\ngo 1.24.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(wrap, filepath.Join(bin, "git")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "app")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, raw)
	}
}
