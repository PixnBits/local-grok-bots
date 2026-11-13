package sandbox

import (
	"fmt"
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
		"protocol.allow=never",
		"protocol.https.allow=always",
		"protocol.ssh.allow=always",
		"protocol.http.allow=always",
		"protocol.file.allow=\"$pfile\"",
		"pfile=user",
		"pfile=never",
		"export GIT_ALLOW_PROTOCOL=$protos",
		"protos=https:ssh",
		"protos=$protos:http",
		"protos=$protos:file",
		"unset GIT_CONFIG GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT",
		"--no-ext-diff",
		"--no-textconv",
		"core.hooksPath=/dev/null",
		"unset SSH_AUTH_SOCK http_proxy https_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY no_proxy",
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("missing %s", needle)
		}
	}
	if !strings.Contains(script, "export GIT_ALLOW_PROTOCOL=$protos") {
		t.Fatal("protocol allow list is not exported")
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
		{"clone", "https://github.com/Acme/Widgets.git", "/work/dest"},
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
		{"clone", "file:///work/fixture", "/work/dest"},
		{"clone", "file://localhost/work/fixture", "/work/dest"},
		{"clone", "file:///work/%66ixture", "/work/dest"},
		{"clone", "file:///work/%252e%252e/fixture", "/work/dest"},
		{"clone", "file:///work/foo..bar", "/work/dest"},
		{"clone", "file:///work/..hidden", "/work/dest"},
		{"clone", "/work/fixture", "/work/dest"},
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
		{"-c", "user.name=Ada", "clone", "file:///work/fixture", "/work/dest"},
		{"clone", "--no-recurse-submodules", "file:///work/fixture", "/work/dest"},
		{"clone", "--jobs", "2", "file:///work/fixture", "/work/dest"},
		{"clone", "--jobs=2", "file:///work/fixture", "/work/dest"},
		{"clone", "-j", "2", "file:///work/fixture", "/work/dest"},
		{"clone", "--filter", "blob:none", "file:///work/fixture", "/work/dest"},
		{"clone", "--shallow-since", "2000-01-01", "file:///work/fixture", "/work/dest"},
		{"clone", "--bundle-uri", "/work/x", "file:///work/fixture", "/work/dest"},
		{"clone", "--reference-if-able", "/work/fixture", "file:///work/fixture", "/work/dest"},
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

func TestGitWrapRemoteCommandOption(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	denied := "option is not allowed"
	hook := "hook"
	for _, args := range [][]string{
		{"clone", "--upload-pack", hook, "file:///work/fixture", "dest"},
		{"clone", "--upload-pack=" + hook, "file:///work/fixture", "dest"},
		{"clone", "-u", hook, "file:///work/fixture", "dest"},
		{"clone", "-u" + hook, "file:///work/fixture", "dest"},
		{"clone", "file:///work/fixture", "--upload-pack", hook, "dest"},
		{"clone", "file:///work/fixture", "--upload-pack=" + hook, "dest"},
		{"fetch", "--upload-pack", hook, "file:///work/fixture"},
		{"fetch", "--upload-pack=" + hook, "file:///work/fixture"},
		{"ls-remote", "--upload-pack", hook, "file:///work/fixture"},
		{"ls-remote", "--upload-pack=" + hook, "file:///work/fixture"},
		{"pull", "--upload-pack", hook, "file:///work/fixture"},
		{"pull", "--upload-pack=" + hook, "file:///work/fixture"},
		{"push", "--receive-pack", hook},
		{"push", "--receive-pack=" + hook},
		{"push", "--exec", hook},
		{"push", "--exec=" + hook},
		{"clone", "--up=" + hook, "file:///work/fixture", "dest"},
		{"push", "--rece=" + hook},
		{"push", "--ex=" + hook},
		{"clone", "-qu", hook, "file:///work/fixture", "dest"},
		{"clone", "-qu" + hook, "file:///work/fixture", "dest"},
		{"clone", "-vu", hook, "file:///work/fixture", "dest"},
		{"clone", "-nu", hook, "file:///work/fixture", "dest"},
		{"clone", "-lu", hook, "file:///work/fixture", "dest"},
		{"clone", "-su", hook, "file:///work/fixture", "dest"},
		{"clone", "--exec", hook, "file:///work/fixture", "dest"},
		{"clone", "--exec=" + hook, "file:///work/fixture", "dest"},
		{"fetch", "--exec", hook, "file:///work/fixture"},
		{"fetch", "--exec=" + hook, "file:///work/fixture"},
		{"ls-remote", "--exec", hook, "file:///work/fixture"},
		{"ls-remote", "--exec=" + hook, "file:///work/fixture"},
		{"pull", "--exec", hook, "file:///work/fixture"},
		{"pull", "--exec=" + hook, "file:///work/fixture"},
		{"ls-remote", "--ex=" + hook, "file:///work/fixture"},
	} {
		text := runGitWrap(t, script, args...)
		if !strings.Contains(text, denied) {
			t.Fatalf("%v: %s", args, text)
		}
	}
	for _, args := range [][]string{
		{"fetch", "-u"},
		{"fetch", "--update-head-ok"},
		{"fetch", "--unshallow"},
		{"pull", "-u"},
		{"push", "-u", "origin"},
		{"push", "--recurse-submodules=check"},
		{"push", "--exec-path=/usr/bin"},
		{"clone", "--exec-path=/usr/bin", "file:///work/fixture", "dest"},
		{"--exec-path=/usr/bin", "status"},
	} {
		text := runGitWrap(t, script, args...)
		if strings.Contains(text, denied) {
			t.Fatalf("%v: %s", args, text)
		}
	}
}

// TestGitWrapRemoteCommandStaysRefused fails if the option is passed through.
// The helper writes a marker when it runs.
func TestGitWrapRemoteCommandStaysRefused(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	src := filepath.Join(work, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "f.txt"), []byte("f\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, src, "init", "-b", "main")
	gitCmd(t, src, "add", "--", "f.txt")
	gitCmd(t, src, "commit", "-m", "init")
	marker := filepath.Join(work, "marker")
	hook := filepath.Join(work, "hook.sh")
	if strings.Contains(marker, "'") || strings.Contains(hook, "'") {
		t.Fatal("path")
	}
	body := "#!/bin/sh\necho ran >> '" + marker + "'\nexec git-upload-pack \"$@\"\n"
	if err := os.WriteFile(hook, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	denied := "option is not allowed"
	url := "file://" + src
	check := func(dir string, args ...string) {
		t.Helper()
		if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		out, err := runInstalledWrap(t, wrap, dir, nil, args...)
		if err == nil {
			t.Fatalf("%v succeeded:\n%s", args, out)
		}
		if !strings.Contains(out, denied) {
			t.Fatalf("%v: %s", args, out)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("%v ran the helper\n%s", args, out)
		}
	}
	for _, args := range [][]string{
		{"clone", "--upload-pack", hook, url, "d-sep"},
		{"clone", "--upload-pack=" + hook, url, "d-eq"},
		{"clone", "-u", hook, url, "d-u"},
		{"clone", "-u" + hook, url, "d-uval"},
		{"clone", url, "--upload-pack=" + hook, "d-after"},
		{"clone", "--up=" + hook, url, "d-short"},
	} {
		check(work, args...)
	}
	for _, args := range [][]string{
		{"fetch", "--upload-pack", hook, url},
		{"fetch", "--upload-pack=" + hook, url},
		{"ls-remote", "--upload-pack", hook, url},
		{"ls-remote", "--upload-pack=" + hook, url},
		{"pull", "--upload-pack", hook, url},
		{"pull", "--upload-pack=" + hook, url},
		{"push", "--receive-pack", hook, url},
		{"push", "--receive-pack=" + hook, url},
		{"push", "--exec", hook, url},
		{"push", "--exec=" + hook, url},
		{"push", "--rece=" + hook, url},
		{"push", "--ex=" + hook, url},
	} {
		check(src, args...)
	}
	out, err := runInstalledWrap(t, wrap, src, nil, "fetch", "-u")
	if strings.Contains(out, denied) {
		t.Fatalf("fetch -u: %v\n%s", err, out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("fetch -u ran the helper")
	}
	ep, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Fatal(err)
	}
	out, err = runInstalledWrap(t, wrap, src, nil, "--exec-path="+strings.TrimSpace(string(ep)), "status")
	if err != nil || strings.Contains(out, denied) {
		t.Fatalf("exec-path: %v\n%s", err, out)
	}
	plain := filepath.Join(work, "plain")
	out, err = runInstalledWrap(t, wrap, work, nil, "clone", "--no-upload-pack", url, plain)
	if err != nil || strings.Contains(out, denied) {
		t.Fatalf("no-upload-pack: %v\n%s", err, out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("clone wrote the marker")
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

	wrap := installGitWrap(t, work)

	dest := filepath.Join(work, "dest")
	out, err := runInstalledWrap(t, wrap, work, nil, "clone", "--recurse-submodules", "file://"+parent, dest)
	if err == nil {
		t.Fatalf("recurse clone succeeded:\n%s", out)
	}
	if !strings.Contains(out, "submodule path is outside the workspace") {
		t.Fatalf("recurse: %s", out)
	}
	if treeHas(t, dest, marker) {
		t.Fatal("recurse clone fetched the submodule")
	}

	for _, flag := range []string{"--recurse", "--rec"} {
		got := filepath.Join(work, "short"+strings.TrimPrefix(flag, "--"))
		text, _ := runInstalledWrap(t, wrap, work, nil, "clone", flag, "file://"+parent, got)
		if treeHas(t, got, marker) {
			t.Fatalf("%s fetched the submodule\n%s", flag, text)
		}
	}

	plain := filepath.Join(work, "plain")
	out, err = runInstalledWrap(t, wrap, work, nil, "clone", "file://"+parent, plain)
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

	norec := filepath.Join(work, "norec")
	out, err = runInstalledWrap(t, wrap, work, nil, "clone", "--no-recurse-submodules", "file://"+parent, norec)
	if err != nil {
		t.Fatalf("no-recurse: %v\n%s", err, out)
	}
	if treeHas(t, norec, marker) {
		t.Fatal("no-recurse fetched the submodule")
	}

	for _, args := range [][]string{
		{"submodule", "update", "--init", "./sub"},
		{"submodule", "update", "--init", "--", "./sub"},
		{"submodule", "update", "--init", filepath.Join(plain, "sub")},
		{"submodule", "update", "--init", "--recursive", "./sub"},
	} {
		text, _ := runInstalledWrap(t, wrap, plain, nil, args...)
		if treeHas(t, plain, marker) {
			t.Fatalf("%v fetched the submodule\n%s", args, text)
		}
	}

	inRepo := filepath.Join(work, "in")
	mid := filepath.Join(work, "mid")
	if err := os.Mkdir(inRepo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inRepo, "in.txt"), []byte("in-content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, inRepo, "init", "-b", "main")
	gitCmd(t, inRepo, "add", "--", "in.txt")
	gitCmd(t, inRepo, "commit", "-m", "in")
	gitCmd(t, inRepo, "-c", "protocol.file.allow=always", "submodule", "add", "file://"+outside, "secret")
	gitCmd(t, inRepo, "commit", "-m", "secret")
	if err := os.Mkdir(mid, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mid, "mid.txt"), []byte("mid-content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, mid, "init", "-b", "main")
	gitCmd(t, mid, "add", "--", "mid.txt")
	gitCmd(t, mid, "commit", "-m", "mid")
	gitCmd(t, mid, "-c", "protocol.file.allow=always", "submodule", "add", "file://"+inRepo, "in")
	gitCmd(t, mid, "commit", "-m", "add in")
	if err := os.RemoveAll(filepath.Join(mid, "in", "secret")); err != nil {
		t.Fatal(err)
	}
	text, _ := runInstalledWrap(t, wrap, mid, nil, "submodule", "update", "--init", "--recursive", "./in")
	if treeHas(t, filepath.Join(mid, "in", "secret"), marker) {
		t.Fatalf("nested update fetched outside content\n%s", text)
	}
}

func TestGitWrapInjectedConfigStaysInWorkspace(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	outside := t.TempDir()
	inside := filepath.Join(work, "inside")
	if err := os.Mkdir(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := "outside-marker-content\n"
	want := "inside-marker-content\n"
	if err := os.WriteFile(filepath.Join(outside, "outside.txt"), []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inside, "inside.txt"), []byte(want), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, outside, "init", "-b", "main")
	gitCmd(t, outside, "add", "--", "outside.txt")
	gitCmd(t, outside, "commit", "-m", "outside")
	gitCmd(t, inside, "init", "-b", "main")
	gitCmd(t, inside, "add", "--", "inside.txt")
	gitCmd(t, inside, "commit", "-m", "inside")
	wrap := installGitWrap(t, work)
	insideURL := "file://" + inside
	key := "url." + outside + ".insteadOf"
	for _, tc := range []struct {
		name string
		env  []string
	}{
		{
			name: "count",
			env: []string{
				"GIT_CONFIG_COUNT=1",
				"GIT_CONFIG_KEY_0=" + key,
				"GIT_CONFIG_VALUE_0=" + insideURL,
			},
		},
		{
			name: "parameters",
			env: []string{
				"GIT_CONFIG_PARAMETERS='" + key + "=" + insideURL + "'",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := filepath.Join(work, "dest-"+tc.name)
			out, err := runInstalledWrap(t, wrap, work, tc.env, "clone", insideURL, dest)
			if treeHas(t, dest, marker) {
				t.Fatalf("cloned outside content\n%s", out)
			}
			if err != nil {
				t.Fatalf("clone: %v\n%s", err, out)
			}
			body, err := os.ReadFile(filepath.Join(dest, "inside.txt"))
			if err != nil || string(body) != want {
				t.Fatalf("content %q %v", body, err)
			}
		})
	}
}

func TestGitWrapClonePathsStayInWorkspace(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	outside := t.TempDir()
	ok := filepath.Join(work, "ok")
	if err := os.Mkdir(ok, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := "outside-marker-content\n"
	want := "inside-marker-content\n"
	if err := os.WriteFile(filepath.Join(outside, "outside.txt"), []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ok, "ok.txt"), []byte(want), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, outside, "init", "-b", "main")
	gitCmd(t, outside, "add", "--", "outside.txt")
	gitCmd(t, outside, "commit", "-m", "outside")
	gitCmd(t, ok, "init", "-b", "main")
	gitCmd(t, ok, "add", "--", "ok.txt")
	gitCmd(t, ok, "commit", "-m", "ok")
	if err := os.Symlink(outside, filepath.Join(work, "link")); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	okURL := "file://" + ok
	for _, args := range [][]string{
		{"clone", "link", "d-plain"},
		{"clone", "--jobs", "2", "link", "d-jobs"},
		{"clone", "-j", "2", "link", "d-j"},
		{"clone", "--jobs=2", "link", "d-jobs-eq"},
		{"clone", "--filter", "blob:none", "link", "d-filter"},
		{"clone", "--shallow-since", "2000-01-01", "link", "d-since"},
		{"clone", "--bundle-uri", "x", "link", "d-bundle"},
		{"clone", "--reference-if-able", "ok", "link", "d-ref"},
	} {
		dest := filepath.Join(work, args[len(args)-1])
		out, err := runInstalledWrap(t, wrap, work, nil, args...)
		if err == nil {
			t.Fatalf("%v succeeded:\n%s", args, out)
		}
		if !strings.Contains(out, "local path is outside the workspace") {
			t.Fatalf("%v: %s", args, out)
		}
		if treeHas(t, dest, marker) {
			t.Fatalf("%v cloned outside content", args)
		}
	}
	for _, args := range [][]string{
		{"clone", "--jobs", "2", okURL, "a-jobs"},
		{"clone", "-j", "2", okURL, "a-j"},
		{"clone", "--jobs=2", okURL, "a-jobs-eq"},
		{"clone", "--filter", "blob:none", okURL, "a-filter"},
		{"clone", "--shallow-since", "2000-01-01", okURL, "a-since"},
		{"clone", "--bundle-uri", "x", okURL, "a-bundle"},
		{"clone", "--reference-if-able", "ok", okURL, "a-ref"},
	} {
		dest := filepath.Join(work, args[len(args)-1])
		out, err := runInstalledWrap(t, wrap, work, nil, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		body, err := os.ReadFile(filepath.Join(dest, "ok.txt"))
		if err != nil || string(body) != want {
			t.Fatalf("%v content %q %v\n%s", args, body, err, out)
		}
		if treeHas(t, dest, marker) {
			t.Fatalf("%v has outside content", args)
		}
	}
}

func TestGitWrapConfigPinsStayForced(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	configDenied := "configuration is not allowed"
	for _, args := range [][]string{
		{"-c", "protocol.file.allow=always", "status"},
		{"-c", "PROTOCOL.EXT.ALLOW=always", "status"},
		{"-cprotocol.file.allow=always", "status"},
		{"-c", "core.sshCommand=/bin/sh", "status"},
		{"-c", "remote.origin.uploadpack=/bin/sh", "status"},
		{"-c", "include.path=/tmp/x", "status"},
		{"-c", "includeIf.gitdir:/work/.path=/tmp/x", "status"},
		{"-c", "credential.helper=osxkeychain", "status"},
		{"-c", "http.proxy=http://127.0.0.1:9", "status"},
		{"-c", "ssh.variant=plink", "status"},
		{"-c", "filter.lfs.clean=/bin/sh", "status"},
		{"--config", "url.x.insteadOf=https://example.com", "status"},
		{"--config=protocol.allow=always", "status"},
		{"--config-env", "core.sshCommand=VAR", "status"},
		{"--config-env=remote.origin.proxy=VAR", "status"},
	} {
		text := runGitWrap(t, script, args...)
		if !strings.Contains(text, configDenied) {
			t.Fatalf("%v: %s", args, text)
		}
	}

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
	gitCmd(t, outside, "commit", "-m", "outside")
	gitCmd(t, parent, "init", "-b", "main")
	gitCmd(t, parent, "add", "--", "parent.txt")
	gitCmd(t, parent, "commit", "-m", "parent")
	gitCmd(t, parent, "-c", "protocol.file.allow=always", "submodule", "add", "file://"+outside, "sub")
	gitCmd(t, parent, "commit", "-m", "add sub")
	if err := os.RemoveAll(filepath.Join(parent, "sub")); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	out, err := runInstalledWrap(t, wrap, parent, nil, "-c", "protocol.file.allow=always", "submodule", "update", "--init", "./sub")
	if err == nil {
		t.Fatalf("submodule update succeeded:\n%s", out)
	}
	if !strings.Contains(out, configDenied) {
		t.Fatalf("submodule: %s", out)
	}
	if treeHas(t, parent, marker) {
		t.Fatal("submodule update fetched outside content")
	}

	ran := filepath.Join(work, "ext-ran")
	hook := filepath.Join(work, "ext.sh")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\necho ran >> '"+ran+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err = runInstalledWrap(t, wrap, work, nil, "-c", "protocol.ext.allow=always", "clone", "ext::"+hook, "ext-dest")
	if err == nil {
		t.Fatalf("ext clone succeeded:\n%s", out)
	}
	if !strings.Contains(out, configDenied) {
		t.Fatalf("ext: %s", out)
	}
	if _, err := os.Stat(ran); !os.IsNotExist(err) {
		t.Fatalf("ext command ran\n%s", out)
	}

	out, err = runInstalledWrap(t, wrap, parent, nil, "-c", "user.name=Intruder", "config", "--get", "user.name")
	if err != nil {
		t.Fatalf("config: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Ada") || strings.Contains(out, "Intruder") {
		t.Fatalf("caller config won: %q", out)
	}
}

func TestGitWrapTransportHelpersStayRefused(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	src := filepath.Join(work, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "f.txt"), []byte("f\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, src, "init", "-b", "main")
	gitCmd(t, src, "add", "--", "f.txt")
	gitCmd(t, src, "commit", "-m", "init")
	marker := filepath.Join(work, "marker")
	hook := filepath.Join(work, "hook.sh")
	body := "#!/bin/sh\necho ran >> '" + marker + "'\nexec git-upload-pack \"$@\"\n"
	if err := os.WriteFile(hook, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	denied := "option is not allowed"
	configDenied := "configuration is not allowed"
	url := "file://" + src
	check := func(dir string, want string, args ...string) {
		t.Helper()
		if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		out, err := runInstalledWrap(t, wrap, dir, nil, args...)
		if err == nil {
			t.Fatalf("%v succeeded:\n%s", args, out)
		}
		if !strings.Contains(out, want) {
			t.Fatalf("%v: %s", args, out)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("%v ran the helper\n%s", args, out)
		}
	}
	for _, args := range [][]string{
		{"clone", "-qu", hook, url, "d-qu"},
		{"clone", "-qu" + hook, url, "d-quval"},
		{"clone", "-vu", hook, url, "d-vu"},
		{"ls-remote", "--exec", hook, url},
		{"ls-remote", "--exec=" + hook, url},
		{"fetch", "--exec", hook, url},
		{"pull", "--exec=" + hook, url},
	} {
		dir := work
		if args[0] != "clone" {
			dir = src
		}
		check(dir, denied, args...)
	}

	repo := filepath.Join(work, "repo")
	if err := os.Mkdir(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "init", "-b", "main")
	gitCmd(t, repo, "config", "remote.x.url", url)
	gitCmd(t, repo, "config", "remote.x.fetch", "+refs/heads/*:refs/remotes/x/*")
	gitCmd(t, repo, "config", "remote.x.uploadpack", hook)
	for _, args := range [][]string{
		{"fetch", "x"},
		{"ls-remote", "x"},
		{"pull", "x"},
		{"clone", url, "from-repo"},
	} {
		check(repo, configDenied, args...)
	}

	out, err := runInstalledWrap(t, wrap, src, nil, "fetch", "-u")
	if strings.Contains(out, denied) {
		t.Fatalf("fetch -u: %v\n%s", err, out)
	}
	out, err = runInstalledWrap(t, wrap, src, nil, "pull", "-u")
	if strings.Contains(out, denied) {
		t.Fatalf("pull -u: %v\n%s", err, out)
	}
	out, err = runInstalledWrap(t, wrap, src, nil, "push", "-u", "origin")
	if strings.Contains(out, denied) {
		t.Fatalf("push -u: %v\n%s", err, out)
	}
	ep, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Fatal(err)
	}
	out, err = runInstalledWrap(t, wrap, src, nil, "--exec-path="+strings.TrimSpace(string(ep)), "status")
	if err != nil || strings.Contains(out, denied) {
		t.Fatalf("exec-path: %v\n%s", err, out)
	}
	plain := filepath.Join(work, "plain")
	out, err = runInstalledWrap(t, wrap, work, nil, "clone", "--no-upload-pack", url, plain)
	if err != nil || strings.Contains(out, denied) {
		t.Fatalf("no-upload-pack: %v\n%s", err, out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("clone wrote the marker")
	}
}

func TestGitWrapScpRemoteStaysRefused(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	for _, needle := range []string{
		"unset GIT_SSH GIT_SSH_COMMAND GIT_SSH_VARIANT GIT_PROXY_COMMAND GIT_EXEC_PATH GIT_TEMPLATE_DIR",
		"unset GIT_DIR GIT_WORK_TREE GIT_ASKPASS GIT_EXTERNAL_DIFF GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_PROTOCOL",
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("missing %s", needle)
		}
	}
	for _, args := range [][]string{
		{"clone", "localhost:/outside/x", "dest"},
		{"clone", "host:path", "dest"},
		{"fetch", "localhost:/outside/x"},
	} {
		text := runGitWrap(t, script, args...)
		if !strings.Contains(text, RepoNotAvailable) {
			t.Fatalf("%v: %s", args, text)
		}
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	marker := filepath.Join(work, "ssh-ran")
	hook := filepath.Join(work, "ssh.sh")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\necho ran >> '"+marker+"'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	out, err := runInstalledWrap(t, wrap, work, []string{"GIT_SSH_COMMAND=" + hook}, "clone", "localhost:/outside/x", "scp-dest")
	if err == nil {
		t.Fatalf("scp clone succeeded:\n%s", out)
	}
	if !strings.Contains(out, RepoNotAvailable) {
		t.Fatalf("scp: %s", out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("ssh helper ran\n%s", out)
	}
}

func TestGitWrapCloneOptionPathsStayInWorkspace(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	outside := t.TempDir()
	ok := filepath.Join(work, "ok")
	tmpl := filepath.Join(work, "tmpl")
	if err := os.Mkdir(ok, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tmpl, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := "outside-marker-content\n"
	want := "inside-marker-content\n"
	if err := os.WriteFile(filepath.Join(outside, "outside.txt"), []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ok, "ok.txt"), []byte(want), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, outside, "init", "-b", "main")
	gitCmd(t, outside, "add", "--", "outside.txt")
	gitCmd(t, outside, "commit", "-m", "outside")
	gitCmd(t, ok, "init", "-b", "main")
	gitCmd(t, ok, "add", "--", "ok.txt")
	gitCmd(t, ok, "commit", "-m", "ok")
	wrap := installGitWrap(t, work)
	okURL := "file://" + ok
	outsideMsg := "local path is outside the workspace"
	n := 0
	for _, opt := range []string{"--reference", "--reference-if-able", "--separate-git-dir", "--template", "--bundle-uri"} {
		for _, args := range [][]string{
			{"clone", opt, outside, okURL, fmt.Sprintf("out-%s-%d", strings.TrimPrefix(opt, "--"), n)},
			{"clone", opt + "=" + outside, okURL, fmt.Sprintf("outeq-%s-%d", strings.TrimPrefix(opt, "--"), n)},
		} {
			n++
			dest := filepath.Join(work, args[len(args)-1])
			out, err := runInstalledWrap(t, wrap, work, nil, args...)
			if err == nil {
				t.Fatalf("%v succeeded:\n%s", args, out)
			}
			if !strings.Contains(out, outsideMsg) {
				t.Fatalf("%v: %s", args, out)
			}
			if treeHas(t, dest, marker) {
				t.Fatalf("%v cloned outside content", args)
			}
		}
	}
	sep := filepath.Join(work, "sep.git")
	sepEq := filepath.Join(work, "sep-eq.git")
	for _, args := range [][]string{
		{"clone", "--reference", ok, okURL, "in-reference"},
		{"clone", "--reference=" + ok, okURL, "in-reference-eq"},
		{"clone", "--reference-if-able", ok, okURL, "in-refable"},
		{"clone", "--reference-if-able=" + ok, okURL, "in-refable-eq"},
		{"clone", "--separate-git-dir", sep, okURL, "in-sep"},
		{"clone", "--separate-git-dir=" + sepEq, okURL, "in-sep-eq"},
		{"clone", "--template", tmpl, okURL, "in-template"},
		{"clone", "--template=" + tmpl, okURL, "in-template-eq"},
		{"clone", "--bundle-uri", "x", okURL, "in-bundle"},
		{"clone", "--bundle-uri=x", okURL, "in-bundle-eq"},
	} {
		dest := filepath.Join(work, args[len(args)-1])
		out, err := runInstalledWrap(t, wrap, work, nil, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if strings.Contains(out, outsideMsg) {
			t.Fatalf("%v refused:\n%s", args, out)
		}
		body, err := os.ReadFile(filepath.Join(dest, "ok.txt"))
		if err != nil || string(body) != want {
			t.Fatalf("%v content %q %v\n%s", args, body, err, out)
		}
	}
}

func TestGitWrapBridgeProtocolPins(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Hub: true, Bridge: true, Name: "Ada", Email: "bot@localhost"})
	parts := strings.Split(script, `if [ -n "$GHPORT" ]; then`)
	if len(parts) < 2 {
		t.Fatal("missing bridge exec")
	}
	last := parts[len(parts)-1]
	end := strings.Index(last, "\n  fi\n")
	if end < 0 {
		t.Fatal("bridge block")
	}
	block := last[:end]
	for _, needle := range []string{
		"protocol.allow=never",
		"protocol.https.allow=always",
		"protocol.ssh.allow=always",
		"protocol.http.allow=always",
		`protocol.file.allow="$pfile"`,
	} {
		if !strings.Contains(block, needle) {
			t.Fatalf("bridge exec missing %s", needle)
		}
	}
}

func installGitWrap(t *testing.T, work string) string {
	t.Helper()
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
	return wrap
}

func runInstalledWrap(t *testing.T, wrap, dir string, extra []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(wrap, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_ALLOW_PROTOCOL=https:ssh")
	cmd.Env = append(cmd.Env, extra...)
	out, err := cmd.CombinedOutput()
	return string(out), err
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
