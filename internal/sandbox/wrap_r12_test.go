package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func r12Join(parts ...[]string) []string {
	var out []string
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

// archive exec is refused for every unique prefix, with or without a remote.
func TestGitWrapR12ArchiveExec(t *testing.T) {
	script := r11HubOff()
	option := "option is not allowed"
	url := "https://github.com/acme/widgets.git"
	remotes := []struct {
		name string
		args []string
	}{
		{"path", []string{"--remote", "/work/repo"}},
		{"file", []string{"--remote=file:///work/repo"}},
		{"github", []string{"--remote", url}},
		{"none", nil},
	}
	execs := []struct {
		name string
		args []string
	}{
		{"exec-eq", []string{"--exec=X"}},
		{"exec-sep", []string{"--exec", "X"}},
		{"e-eq", []string{"--e=X"}},
		{"e-sep", []string{"--e", "X"}},
		{"ex-eq", []string{"--ex=X"}},
		{"ex-sep", []string{"--ex", "X"}},
		{"exe-eq", []string{"--exe=X"}},
		{"exe-sep", []string{"--exe", "X"}},
	}
	for _, ex := range execs {
		for _, rem := range remotes {
			orders := []struct {
				name string
				args []string
			}{
				{name: "before", args: r12Join([]string{"archive"}, ex.args, rem.args, []string{"HEAD"})},
			}
			if rem.args != nil {
				orders = append(orders, struct {
					name string
					args []string
				}{name: "after", args: r12Join([]string{"archive"}, rem.args, ex.args, []string{"HEAD"})})
			}
			for _, order := range orders {
				t.Run(ex.name+"/"+rem.name+"/"+order.name, func(t *testing.T) {
					text := r11Text(t, script, order.args...)
					if !strings.Contains(text, option) {
						t.Fatalf("%v: %s", order.args, text)
					}
				})
			}
		}
	}
	text := r11Text(t, script, "archive", "--no-exec", "--remote="+url, "HEAD")
	if strings.Contains(text, option) || !strings.Contains(text, GitHubGrantOff) {
		t.Fatalf("no-exec: %s", text)
	}
	text = r11Text(t, script, "archive", "--remote="+url, "--", "--exec")
	if strings.Contains(text, option) || !strings.Contains(text, GitHubGrantOff) {
		t.Fatalf("after --: %s", text)
	}
}

// archive --remote of a workspace path does not arm the file protocol.
func TestGitWrapR12ArchiveNoFile(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "R\n")
	real, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	real, err = filepath.Abs(real)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(base, "git.log")
	fake := filepath.Join(base, "real-git")
	if strings.Contains(logPath, "'") || strings.Contains(real, "'") {
		t.Fatal("path")
	}
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + logPath + "'\nexec '" + real + "' \"$@\"\n"
	if err := os.WriteFile(fake, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrapReal(t, work, fake, gitWrapOpts{
		Grant: true, Hub: false, Bridge: true,
		Repos: []string{"acme/widgets"},
		Name:  "Ada", Email: "bot@localhost",
	})
	run := func(args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, repo, nil, 20*time.Second, args...)
	}
	for _, args := range [][]string{
		{"archive", "--remote=" + repo, "HEAD"},
		{"archive", "--remote", repo, "HEAD"},
		{"archive", "--remote=file://" + repo, "HEAD"},
		{"archive", "--remote", "file://" + repo, "HEAD"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if err := os.WriteFile(logPath, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			out, err := run(args...)
			logText := ""
			if b, readErr := os.ReadFile(logPath); readErr == nil {
				logText = string(b)
			}
			if err == nil {
				t.Fatalf("%v exited 0\n%s", args, logText)
			}
			if strings.Contains(logText, "protocol.file.allow=user") || strings.Contains(logText, "GIT_ALLOW_PROTOCOL=file") {
				t.Fatalf("%v armed file\n%s\n%s", args, out, logText)
			}
			if !strings.Contains(logText, "protocol.file.allow=never") {
				t.Fatalf("%v did not keep file off\n%s\n%s", args, out, logText)
			}
			if !strings.Contains(out, "transport 'file' not allowed") {
				t.Fatalf("%v: %v\n%s\n%s", args, err, out, logText)
			}
		})
	}
}

// A slashless archive remote is every stored remote.<name>.url.
func TestGitWrapR12ArchiveRemoteName(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	inside := filepath.Join(work, "inside")
	commitRepo(t, inside, "i.txt", "I\n")
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "R\n")
	gitCmd(t, repo, "remote", "add", "gh", "https://github.com/acme/widgets.git")
	gitCmd(t, repo, "remote", "add", "other", "https://github.com/other/nope.git")
	gitCmd(t, repo, "remote", "add", "local", "file://"+inside)
	gitCmd(t, repo, "remote", "add", "both", "https://github.com/acme/widgets.git")
	gitCmd(t, repo, "config", "--add", "remote.both.url", "https://github.com/other/nope.git")

	off := gitWrapOpts{
		Grant: true, Hub: false, Bridge: true,
		Repos: []string{"acme/widgets"},
		Name:  "Ada", Email: "bot@localhost",
	}
	wrap := installGitWrapWith(t, work, off)
	run := func(args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, repo, nil, 20*time.Second, args...)
	}
	for _, args := range [][]string{
		{"archive", "--remote=gh", "HEAD"},
		{"archive", "--remote", "gh", "HEAD"},
		{"archive", "--rem=gh", "HEAD"},
		{"archive", "--rem", "gh", "HEAD"},
		{"archive", "--remote=local", "--remote=gh", "HEAD"},
		{"archive", "--remote", "local", "--remote", "gh", "HEAD"},
		{"archive", "--rem=local", "--rem=gh", "HEAD"},
	} {
		out, err := run(args...)
		if err == nil || !strings.Contains(out, GitHubGrantOff) || strings.Contains(out, RepoNotAvailable) {
			t.Fatalf("%v Hub:false: %v\n%s", args, err, out)
		}
	}
	out, err := run("archive", "--remote=other", "HEAD")
	if err == nil || !strings.Contains(out, RepoNotAvailable) || strings.Contains(out, GitHubGrantOff) {
		t.Fatalf("off-list: %v\n%s", err, out)
	}
	out, err = run("archive", "--remote=both", "HEAD")
	if err == nil || !strings.Contains(out, RepoNotAvailable) || strings.Contains(out, GitHubGrantOff) {
		t.Fatalf("both urls: %v\n%s", err, out)
	}

	on := off
	on.Hub = true
	on.Bridge = false
	wrapOn := installGitWrapWith(t, work, on)
	out, err = runWrapTimeout(t, wrapOn, repo, nil, 20*time.Second, "archive", "--remote=gh", "HEAD")
	if err == nil || !strings.Contains(out, GitHubBridgeDown) || strings.Contains(out, GitHubGrantOff) {
		t.Fatalf("bridge: %v\n%s", err, out)
	}
}

// Words after archive are not global options, so a following --remote is still read.
func TestGitWrapR12ArchiveGlobals(t *testing.T) {
	script := r11HubOff()
	url := "https://github.com/acme/widgets.git"
	for _, g := range []string{
		"-C", "-c", "--git-dir", "--work-tree", "--namespace",
		"--super-prefix", "--config-env", "--exec-path", "--config",
	} {
		for _, args := range [][]string{
			{"archive", g, "--remote=" + url, "HEAD"},
			{"archive", g, "--remote", url, "HEAD"},
		} {
			text := r11Text(t, script, args...)
			if !strings.Contains(text, GitHubGrantOff) {
				t.Fatalf("%v: %s", args, text)
			}
		}
	}
	for _, args := range [][]string{
		{"-C", ".", "archive", "--remote=" + url, "HEAD"},
		{"-c", "a.b=c", "archive", "--remote=" + url, "HEAD"},
		{"-c", "a.b=c", "archive", "--remote", url, "HEAD"},
	} {
		text := r11Text(t, script, args...)
		if !strings.Contains(text, GitHubGrantOff) {
			t.Fatalf("%v: %s", args, text)
		}
	}
	text := r11Text(t, script, "archive", "--attr-source", "HEAD")
	if !strings.Contains(text, "option is not allowed") {
		t.Fatalf("attr-source: %s", text)
	}
}
