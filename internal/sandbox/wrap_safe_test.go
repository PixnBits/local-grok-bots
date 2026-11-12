package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitWrapForcesSafeConfig(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	for _, needle := range []string{
		"core.fsmonitor=",
		"core.fsmonitorHookVersion=",
		"GIT_ALLOW_PROTOCOL=https:ssh",
		"GIT_ALLOW_PROTOCOL=https:ssh:http",
		"--no-ext-diff",
		"--no-textconv",
		"core.hooksPath=/dev/null",
		"protocol.file.allow=never",
		"unset SSH_AUTH_SOCK http_proxy https_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY no_proxy",
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("missing %s", needle)
		}
	}
	if strings.Contains(script, `""|file://*)`) {
		t.Fatal("file URL is still a blanket allow")
	}
	path := filepath.Join(t.TempDir(), "gitwrap")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "-n", path).CombinedOutput()
	if err != nil {
		t.Fatalf("sh -n: %v\n%s", err, out)
	}
}

func TestGitHubAllowlistWhere(t *testing.T) {
	if GitHubAllowlistWhere(nil, nil, "acme", "widgets") != "the policy [github].repos ceiling and the bot's github_allow" {
		t.Fatal(GitHubAllowlistWhere(nil, nil, "acme", "widgets"))
	}
	if GitHubAllowlistWhere([]string{"acme/widgets"}, []string{"other/nope"}, "other", "nope") != "the policy [github].repos ceiling" {
		t.Fatal("ceiling")
	}
	if GitHubAllowlistWhere([]string{"other/nope"}, []string{"acme/widgets"}, "other", "nope") != "the bot's github_allow" {
		t.Fatal("bot")
	}
	if GitHubAllowlistWhere([]string{"Acme/Widgets"}, []string{"acme/widgets"}, "acme", "widgets") != "" {
		t.Fatal("both lists contain it")
	}
}

func TestGitHubAllowlistWhereNormalizesOwner(t *testing.T) {
	lists := []string{"acme/widgets"}
	for _, tc := range []struct{ owner, repo string }{
		{" Acme ", " Widgets "},
		{"ACME", "widgets"},
		{"Acme", "WIDGETS"},
	} {
		if got := GitHubAllowlistWhere(lists, lists, tc.owner, tc.repo); got != "" {
			t.Fatalf("%q %q -> %q", tc.owner, tc.repo, got)
		}
	}
	if GitHubAllowlistWhere(lists, nil, " acme ", "widgets") != gitHubListBot {
		t.Fatal("bot list")
	}
}

func TestGitWrapDenialIsGeneric(t *testing.T) {
	run := func(t *testing.T, opts gitWrapOpts, remote string) {
		t.Helper()
		script := gitWrap(opts)
		for _, leaked := range []string{gitHubListBoth, gitHubListCeiling, gitHubListBot, "not allowlisted", "missing from"} {
			if strings.Contains(script, leaked) {
				t.Fatalf("script contains %q", leaked)
			}
		}
		text := runGitWrap(t, script, "clone", remote, "dest")
		if !strings.Contains(text, "git clone denied: "+RepoNotAvailable) {
			t.Fatalf("message: %s", text)
		}
		for _, leaked := range []string{gitHubListBoth, gitHubListCeiling, gitHubListBot, "not allowlisted", "missing from", GitHubGrantOff, GitHubBridgeDown} {
			if strings.Contains(text, leaked) {
				t.Fatalf("message names %q\n%s", leaked, text)
			}
		}
	}
	// Policy-only, bot-only, and neither are the same sentence. The wrapper
	// only receives the effective list, so none of those names are inputs.
	run(t, gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"}, "https://github.com/missing/repo.git")
	run(t, gitWrapOpts{Grant: true, Hub: true, Name: "Ada", Email: "bot@localhost", Repos: []string{"acme/widgets"}}, "https://github.com/onlybot/repo.git")
	run(t, gitWrapOpts{Grant: true, Hub: true, Name: "Ada", Email: "bot@localhost", Repos: []string{"acme/widgets"}}, "https://github.com/OnlyPol/repo.git")
	text := runGitWrap(t, gitWrap(gitWrapOpts{
		Grant: true, Hub: true, Name: "Ada", Email: "bot@localhost", Repos: []string{"acme/widgets"},
	}), "clone", "git@github.com:acme/widgets.git", "dest")
	if !strings.Contains(text, RepoNotAvailable) || strings.Contains(text, "missing from") || strings.Contains(text, gitHubListCeiling) {
		t.Fatalf("ssh: %s", text)
	}
}

func TestGitWrapGitHubGrantOff(t *testing.T) {
	script := gitWrap(gitWrapOpts{
		Grant: true, Hub: false, Bridge: true,
		Repos: []string{"acme/widgets"}, Name: "Ada", Email: "bot@localhost",
	})
	if !strings.Contains(script, "acme/widgets") || strings.Contains(script, gitHubListCeiling) {
		t.Fatal("effective list missing or policy text embedded")
	}
	for _, args := range [][]string{
		{"clone", "https://github.com/Acme/Widgets.git", "dest"},
		{"fetch", "https://github.com/ACME/widgets.git"},
		{"ls-remote", "https://github.com/acme/widgets"},
	} {
		text := runGitWrap(t, script, args...)
		if !strings.Contains(text, GitHubGrantOff) || strings.Contains(text, RepoNotAvailable) || strings.Contains(text, "not allowlisted") {
			t.Fatalf("%v: %s", args, text)
		}
	}
	text := runGitWrap(t, script, "clone", "https://github.com/other/nope.git", "dest")
	if !strings.Contains(text, RepoNotAvailable) || strings.Contains(text, GitHubGrantOff) {
		t.Fatalf("off-list with grant off: %s", text)
	}
}

func TestGitWrapBridgeDown(t *testing.T) {
	script := gitWrap(gitWrapOpts{
		Grant: true, Hub: true, Bridge: false,
		Repos: []string{"acme/widgets"}, Name: "Ada", Email: "bot@localhost",
	})
	text := runGitWrap(t, script, "fetch", "https://github.com/acme/widgets.git")
	if !strings.Contains(text, GitHubBridgeDown) || strings.Contains(text, RepoNotAvailable) || strings.Contains(text, "not allowlisted") || strings.Contains(text, GitHubGrantOff) {
		t.Fatalf("bridge: %s", text)
	}
	text = runGitWrap(t, script, "clone", "https://github.com/other/nope.git", "dest")
	if !strings.Contains(text, RepoNotAvailable) || strings.Contains(text, GitHubBridgeDown) {
		t.Fatalf("off-list bridge: %s", text)
	}
}

func TestGitWrapFileRemoteStaysInWorkspace(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	outside := "local path is outside the workspace"
	for _, args := range [][]string{
		{"clone", "file:///etc/passwd", "dest"},
		{"clone", "FILE:///etc/passwd", "dest"},
		{"clone", "file:///work/../etc/passwd", "dest"},
		{"clone", "file:///work/%2e%2e/etc/passwd", "dest"},
		{"clone", "file:///work/%2E%2E/etc/passwd", "dest"},
		{"clone", "FILE:///work/%2e%2e/etc/passwd", "dest"},
		{"clone", "file:///work/..%2fetc/passwd", "dest"},
		{"clone", "file:///work/ok%2f..%2f..%2fetc/passwd", "dest"},
		{"clone", "file:///work/a%00b", "dest"},
		{"clone", "file:///work/%", "dest"},
		{"clone", "file:///work/%2", "dest"},
		{"clone", "file:///work/%zz", "dest"},
		{"clone", "file://localhost/etc/passwd", "dest"},
		{"clone", "file://otherhost/work/repo", "dest"},
		{"clone", "/etc/passwd", "dest"},
		{"submodule", "add", "file:///etc/passwd"},
	} {
		text := runGitWrap(t, script, args...)
		if !strings.Contains(text, outside) {
			t.Fatalf("%v: %s", args, text)
		}
	}
	for _, args := range [][]string{
		{"clone", "file:///work/fixture", "dest"},
		{"clone", "file://localhost/work/fixture", "dest"},
		{"clone", "file:///work/%66ixture", "dest"},
		{"clone", "file:///work/%252e%252e/fixture", "dest"},
		{"clone", "file:///work/foo..bar", "dest"},
		{"clone", "file:///work/..hidden", "dest"},
		{"clone", "/work/fixture", "dest"},
		{"submodule", "add", "file:///work/fixture"},
	} {
		text := runGitWrap(t, script, args...)
		if strings.Contains(text, outside) {
			t.Fatalf("%v: %s", args, text)
		}
	}
}

func TestGitWrapRemoteBase(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	outside := "local path is outside the workspace"
	configDenied := "configuration is not allowed"
	for _, args := range [][]string{
		{"-C", "/etc", "clone", "passwd"},
		{"clone", "sub/dir"},
		{"clone", ".", "dest"},
	} {
		text := runGitWrap(t, script, args...)
		if !strings.Contains(text, outside) {
			t.Fatalf("%v: %s", args, text)
		}
	}
	for _, args := range [][]string{
		{"-C", "/work", "clone", "./fixture"},
		{"-c", "user.name=Ada", "clone", "file:///work/fixture", "dest"},
		{"clone", "--no-recurse-submodules", "file:///work/fixture", "dest"},
	} {
		text := runGitWrap(t, script, args...)
		if strings.Contains(text, outside) || strings.Contains(text, configDenied) {
			t.Fatalf("%v: %s", args, text)
		}
	}
	for _, args := range [][]string{
		{"-c", "url.https://example.com/.insteadOf=file:///etc/passwd", "clone", "file:///work/fixture", "dest"},
		{"-c", "URL.https://example.com/.insteadOf=file:///etc/passwd", "clone", "file:///work/fixture", "dest"},
		{"--config-env", "url.x=VAR", "status"},
		{"--config-env=url.x=VAR", "status"},
		{"clone", "-c", "url.file:///work/.insteadOf=file:///etc/passwd", "file:///work/fixture", "dest"},
		{"clone", "--config", "url.file:///work/.insteadOf=file:///etc/passwd", "file:///work/fixture", "dest"},
		{"clone", "--config=url.file:///work/.insteadOf=file:///etc/passwd", "file:///work/fixture", "dest"},
	} {
		text := runGitWrap(t, script, args...)
		if !strings.Contains(text, configDenied) {
			t.Fatalf("%v: %s", args, text)
		}
	}
	sub := "submodule path is outside the workspace"
	for _, flag := range []string{"--recurse-submodules", "--recursive", "--shallow-submodules"} {
		for _, subcmd := range []string{"clone", "fetch", "pull"} {
			text := runGitWrap(t, script, subcmd, flag, "file:///work/fixture", "dest")
			if !strings.Contains(text, sub) {
				t.Fatalf("%s %s: %s", subcmd, flag, text)
			}
		}
	}
}

func TestGitWrapSubmoduleStaysInWorkspace(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	outside := t.TempDir()
	parent := filepath.Join(work, "parent")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := "outside-marker-content\n"
	if err := os.WriteFile(filepath.Join(outside, "outside.txt"), []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "parent.txt"), []byte("parent-content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, outside, "init", "-b", "main")
	gitCmd(t, outside, "add", "--", "outside.txt")
	gitCmd(t, outside, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "outside")
	gitCmd(t, parent, "init", "-b", "main")
	gitCmd(t, parent, "add", "--", "parent.txt")
	gitCmd(t, parent, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "parent")
	gitCmd(t, parent, "-c", "protocol.file.allow=always", "-c", "user.name=Test", "-c", "user.email=test@example.com", "submodule", "add", "file://"+outside, "sub")
	gitCmd(t, parent, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "add sub")

	real, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	real, err = filepath.Abs(real)
	if err != nil {
		t.Fatal(err)
	}
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	script = strings.ReplaceAll(script, "/lgb/bin/git", real)
	script = strings.ReplaceAll(script, "/work", work)
	wrap := filepath.Join(t.TempDir(), "gitwrap")
	if err := os.WriteFile(wrap, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(work, "dest")
	cmd := exec.Command(wrap, "clone", "--recurse-submodules", "file://"+parent, dest)
	cmd.Dir = work
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("recurse clone succeeded:\n%s", out)
	}
	if !strings.Contains(string(out), "submodule path is outside the workspace") {
		t.Fatalf("recurse: %s", out)
	}
	if treeHas(t, dest, marker) {
		t.Fatal("recurse clone fetched the submodule")
	}

	plain := filepath.Join(work, "plain")
	cmd = exec.Command(wrap, "clone", "file://"+parent, plain)
	cmd.Dir = work
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	body, err := os.ReadFile(filepath.Join(plain, "parent.txt"))
	if err != nil || string(body) != "parent-content\n" {
		t.Fatalf("parent content %q %v", body, err)
	}
	if treeHas(t, plain, marker) {
		t.Fatal("clone fetched the submodule")
	}
}

func gitCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_TERMINAL_PROMPT=0",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func treeHas(t *testing.T, root, needle string) bool {
	t.Helper()
	found := false
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if strings.Contains(string(b), needle) {
			found = true
			return os.ErrExist
		}
		return nil
	})
	if err != nil && !os.IsExist(err) && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return found
}

func runGitWrap(t *testing.T, script string, args ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "gitwrap")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("sh -n: %v\n%s", err, out)
	}
	cmd := exec.Command(path, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("allowed %v: %s", args, out)
	}
	return string(out)
}
