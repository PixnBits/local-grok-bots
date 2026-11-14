package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
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
		"unset GIT_ALLOW_PROTOCOL",
		"export GIT_ALLOW_PROTOCOL=$protos",
		"protos=https:ssh",
		"protos=$protos:http",
		"-c fetch.recurseSubmodules=false",
		"-c submodule.recurse=false",
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
	if strings.Contains(script, "protos=$protos:file") || strings.Contains(script, "ssh:file") {
		t.Fatal("file is still added to the protocol list")
	}
	if strings.Count(script, "unset GIT_ALLOW_PROTOCOL") < 2 {
		t.Fatal("inherited protocol list is not cleared for a local path")
	}
	if strings.Count(script, "-c fetch.recurseSubmodules=false") < 3 || strings.Count(script, "-c submodule.recurse=false") < 3 {
		t.Fatal("recurse pins are missing")
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
		{"clone", "-4u", hook, "file:///work/fixture", "dest"},
		{"clone", "-6u", hook, "file:///work/fixture", "dest"},
		{"clone", "-q4u", hook, "file:///work/fixture", "dest"},
		{"clone", "-4qu", hook, "file:///work/fixture", "dest"},
		{"clone", "-4u" + hook, "file:///work/fixture", "dest"},
		{"--exec-path=/usr/bin", "status"},
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
	if err == nil || !strings.Contains(out, denied) {
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
		{"-c", "alias.cl=clone", "status"},
		{"--config", "alias.x=fetch", "status"},
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

	skipIfJailWrapper(t)
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
	skipIfJailWrapper(t)
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
	if err == nil || !strings.Contains(out, denied) {
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
		"unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_NAMESPACE GIT_OBJECT_DIRECTORY GIT_INDEX_FILE GIT_CEILING_DIRECTORIES GIT_ASKPASS GIT_EXTERNAL_DIFF GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_PROTOCOL",
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
	skipIfJailWrapper(t)
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
		"-c fetch.recurseSubmodules=false",
		"-c submodule.recurse=false",
	} {
		if !strings.Contains(block, needle) {
			t.Fatalf("bridge exec missing %s", needle)
		}
	}
}

func TestGitWrapCloneShortDigitClustersStayRefused(t *testing.T) {
	skipIfJailWrapper(t)
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
	writeMarkerHook(t, hook, marker)
	wrap := installGitWrap(t, work)
	denied := "option is not allowed"
	url := "file://" + src
	for _, args := range [][]string{
		{"clone", "-4u", hook, url, "d-4u"},
		{"clone", "-6u", hook, url, "d-6u"},
		{"clone", "-q4u", hook, url, "d-q4u"},
		{"clone", "-4qu", hook, url, "d-4qu"},
		{"clone", "-4u" + hook, url, "d-4uval"},
	} {
		if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		out, err := runInstalledWrap(t, wrap, work, nil, args...)
		if err == nil || !strings.Contains(out, denied) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("%v ran the helper\n%s", args, out)
		}
	}
}

func TestGitWrapIncludedConfigStaysRefused(t *testing.T) {
	skipIfJailWrapper(t)
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
	url := "file://" + src
	marker := filepath.Join(work, "marker")
	hook := filepath.Join(work, "hook.sh")
	writeMarkerHook(t, hook, marker)
	wrap := installGitWrap(t, work)
	configDenied := "configuration is not allowed"
	refuse := func(dir string, args ...string) {
		t.Helper()
		if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		out, err := runInstalledWrap(t, wrap, dir, nil, args...)
		if err == nil || !strings.Contains(out, configDenied) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("%v ran the helper\n%s", args, out)
		}
	}
	newRepo := func(name string) string {
		t.Helper()
		dir := filepath.Join(work, name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		gitCmd(t, dir, "init", "-b", "main")
		return dir
	}
	writeInc := func(name, body string) string {
		t.Helper()
		path := filepath.Join(work, name)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	repo := newRepo("inc-up")
	inc := writeInc("inc-up.gitconfig", "[remote \"x\"]\n\tuploadpack = "+hook+"\n")
	gitCmd(t, repo, "config", "include.path", inc)
	gitCmd(t, repo, "config", "remote.x.url", url)
	gitCmd(t, repo, "config", "remote.x.fetch", "+refs/heads/*:refs/remotes/x/*")
	refuse(repo, "fetch", "x")
	refuse(repo, "ls-remote", "x")

	repo = newRepo("inc-if")
	inc = writeInc("inc-if.gitconfig", "[remote \"x\"]\n\tuploadpack = "+hook+"\n")
	gitCmd(t, repo, "config", "includeIf.gitdir:**.path", inc)
	gitCmd(t, repo, "config", "remote.x.url", url)
	gitCmd(t, repo, "config", "remote.x.fetch", "+refs/heads/*:refs/remotes/x/*")
	refuse(repo, "fetch", "x")
	refuse(repo, "ls-remote", "x")

	repo = newRepo("inc-only")
	inc = writeInc("inc-only.gitconfig", "[advice]\n\tdetachedHead = false\n")
	gitCmd(t, repo, "config", "include.path", inc)
	gitCmd(t, repo, "config", "remote.x.url", url)
	gitCmd(t, repo, "config", "remote.x.fetch", "+refs/heads/*:refs/remotes/x/*")
	refuse(repo, "fetch", "x")

	repo = newRepo("wt")
	gitCmd(t, repo, "config", "extensions.worktreeConfig", "true")
	gitCmd(t, repo, "config", "remote.origin.url", url)
	gitCmd(t, repo, "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
	gitCmd(t, repo, "config", "--worktree", "remote.origin.uploadpack", hook)
	refuse(repo, "fetch", "origin")
	refuse(repo, "ls-remote", "origin")

	repo = newRepo("from-out")
	gitCmd(t, repo, "config", "remote.x.url", url)
	gitCmd(t, repo, "config", "remote.x.fetch", "+refs/heads/*:refs/remotes/x/*")
	gitCmd(t, repo, "config", "remote.x.uploadpack", hook)
	refuse(work, "-C", repo, "fetch", "x")
	refuse(work, "-C", repo, "ls-remote", "x")

	empty := filepath.Join(work, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := runInstalledWrap(t, wrap, empty, nil, "fetch", url)
	if err == nil || strings.Contains(out, configDenied) {
		t.Fatalf("non-repo fetch: %v\n%s", err, out)
	}

	dest := filepath.Join(work, "dest")
	out, err = runInstalledWrap(t, wrap, work, nil, "-c", "user.name=Ada", "-c", "user.email=bot@localhost", "clone", url, dest)
	if err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(src, "g.txt"), []byte("g\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, src, "add", "--", "g.txt")
	gitCmd(t, src, "commit", "-m", "more")
	out, err = runInstalledWrap(t, wrap, dest, nil, "fetch", url)
	if err != nil {
		t.Fatalf("fetch: %v\n%s", err, out)
	}
	out, err = runInstalledWrap(t, wrap, dest, nil, "pull", url)
	if err != nil {
		t.Fatalf("pull: %v\n%s", err, out)
	}
	body, err := os.ReadFile(filepath.Join(dest, "g.txt"))
	if err != nil || string(body) != "g\n" {
		t.Fatalf("pull content %q %v\n%s", body, err, out)
	}
	out, err = runInstalledWrap(t, wrap, work, nil, "ls-remote", url)
	if err != nil || !strings.Contains(out, "refs/heads/main") {
		t.Fatalf("ls-remote: %v\n%s", err, out)
	}
}

func TestGitWrapExecPathStaysRefused(t *testing.T) {
	skipIfJailWrapper(t)
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
	fake := filepath.Join(work, "fake-exec")
	if err := os.Mkdir(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	writeMarkerHook(t, filepath.Join(fake, "git-upload-pack"), marker)
	wrap := installGitWrap(t, work)
	denied := "option is not allowed"
	url := "file://" + src
	for _, tc := range []struct {
		dir  string
		args []string
	}{
		{work, []string{"--exec-path=" + fake, "clone", url, filepath.Join(work, "c-eq")}},
		{src, []string{"--exec-path=" + fake, "fetch", url}},
		{src, []string{"--exec-path=" + fake, "ls-remote", url}},
		{work, []string{"--exec-path", fake, "clone", url, filepath.Join(work, "c-sep")}},
		{src, []string{"--exec-path", fake, "fetch", url}},
		{src, []string{"--exec-path", fake, "ls-remote", url}},
		{src, []string{"--exec-path"}},
	} {
		if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		out, err := runInstalledWrap(t, wrap, tc.dir, nil, tc.args...)
		if err == nil || !strings.Contains(out, denied) {
			t.Fatalf("%v: %v\n%s", tc.args, err, out)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("%v ran the helper\n%s", tc.args, out)
		}
	}
}

func TestGitWrapNestedFetchStaysInWorkspace(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	if strings.Contains(script, "protos=$protos:file") || strings.Contains(script, "ssh:file") {
		t.Fatal("file is still added to the protocol list")
	}
	if !strings.Contains(script, "-c fetch.recurseSubmodules=false") || !strings.Contains(script, "-c submodule.recurse=false") {
		t.Fatal("recurse pins missing")
	}
	// Those two keys are outside the allowlist, so a repository that stores
	// them is refused before fetch runs. The pins above are what still force
	// the values off when the keys are not stored. A submodule URL outside
	// the workspace is refused on its own and names the key.
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	outside := t.TempDir()
	parent := filepath.Join(work, "parent")
	inside := filepath.Join(work, "inside")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "base.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, outside, "init", "-b", "main")
	gitCmd(t, outside, "add", "--", "base.txt")
	gitCmd(t, outside, "commit", "-m", "base")
	gitCmd(t, parent, "init", "-b", "main")
	gitCmd(t, parent, "-c", "protocol.file.allow=always", "submodule", "add", "file://"+outside, "nested")
	gitCmd(t, parent, "commit", "-m", "add nested")
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside-secret-marker\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, outside, "add", "--", "secret.txt")
	gitCmd(t, outside, "commit", "-m", "secret")
	secret := gitCmdOut(t, outside, "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(inside, "inside.txt"), []byte("inside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, inside, "init", "-b", "main")
	gitCmd(t, inside, "add", "--", "inside.txt")
	gitCmd(t, inside, "commit", "-m", "inside")
	insideSHA := gitCmdOut(t, inside, "rev-parse", "HEAD")
	nestedGit := filepath.Join(parent, ".git", "modules", "nested")
	if gitHasObject(nestedGit, secret) {
		t.Fatal("setup already stored the outside commit")
	}
	wrap := installGitWrap(t, work)
	out, err := runInstalledWrap(t, wrap, parent, nil, "fetch", "file://"+inside)
	if err == nil || !strings.Contains(out, "configuration is not allowed") || !strings.Contains(out, "submodule.nested.url") {
		t.Fatalf("fetch: %v\n%s", err, out)
	}
	if gitHasObject(filepath.Join(parent, ".git"), insideSHA) {
		t.Fatal("refused fetch stored the workspace commit")
	}
	if gitHasObject(nestedGit, secret) {
		t.Fatal("fetch stored the outside repository in the nested repository")
	}
	gitCmd(t, parent, "config", "fetch.recurseSubmodules", "yes")
	gitCmd(t, parent, "config", "submodule.recurse", "true")
	out, err = runInstalledWrap(t, wrap, parent, nil, "fetch", "file://"+inside)
	if err == nil || !strings.Contains(out, "configuration is not allowed") {
		t.Fatalf("recurse config: %v\n%s", err, out)
	}
	if gitHasObject(nestedGit, secret) {
		t.Fatal("refused fetch stored the outside repository")
	}
}

func TestGitWrapEnvironmentStaysIgnored(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	for _, name := range []string{
		"GIT_ALLOW_PROTOCOL",
		"GIT_CONFIG_COUNT",
		"GIT_CONFIG_KEY_0",
		"GIT_CONFIG_VALUE_0",
		"GIT_CONFIG_GLOBAL",
		"GIT_CONFIG_SYSTEM",
		"GIT_CONFIG_NOSYSTEM",
		"GIT_EXEC_PATH",
		"GIT_SSH_COMMAND",
		"GIT_COMMON_DIR",
		"GIT_NAMESPACE",
		"GIT_OBJECT_DIRECTORY",
		"GIT_INDEX_FILE",
		"GIT_CEILING_DIRECTORIES",
		"LGB_REAL_GIT",
		"GIT_WRAP_TEST",
	} {
		if strings.Contains(script, "$"+name) || strings.Contains(script, "${"+name) {
			t.Fatalf("script reads %s", name)
		}
	}
	for _, needle := range []string{
		"export GIT_CONFIG_SYSTEM=/dev/null",
		"export GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_CONFIG_NOSYSTEM",
		`unset "$cfg_name"`,
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("missing %s", needle)
		}
	}
	srcText, err := os.ReadFile("wrap.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(srcText), "os.Getenv") || strings.Contains(string(srcText), "os.LookupEnv") {
		t.Fatal("wrapper reads the environment")
	}
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	outside := t.TempDir()
	inside := filepath.Join(work, "inside")
	if err := os.Mkdir(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "o.txt"), []byte("o\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inside, "i.txt"), []byte("i\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, outside, "init", "-b", "main")
	gitCmd(t, outside, "add", "--", "o.txt")
	gitCmd(t, outside, "commit", "-m", "o")
	gitCmd(t, inside, "init", "-b", "main")
	gitCmd(t, inside, "add", "--", "i.txt")
	gitCmd(t, inside, "commit", "-m", "i")
	marker := filepath.Join(work, "marker")
	hook := filepath.Join(work, "hook.sh")
	writeMarkerHook(t, hook, marker)
	fake := filepath.Join(work, "fake-exec")
	if err := os.Mkdir(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	writeMarkerHook(t, filepath.Join(fake, "git-upload-pack"), marker)
	global := filepath.Join(work, "global.gitconfig")
	if err := os.WriteFile(global, []byte("[protocol]\n\tfile.allow = always\n[remote \"x\"]\n\tuploadpack = "+hook+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	system := filepath.Join(work, "system.gitconfig")
	if err := os.WriteFile(system, []byte("[protocol]\n\tfile.allow = always\n[remote \"x\"]\n\tuploadpack = "+hook+"\n[url \"file://"+outside+"\"]\n\tinsteadOf = file://"+inside+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	// GIT_CONFIG_NOSYSTEM is left unset. The wrapper sets it.
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + work,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL=https:ssh:file",
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=protocol.file.allow",
		"GIT_CONFIG_VALUE_0=always",
		"GIT_CONFIG_GLOBAL=" + global,
		"GIT_CONFIG_SYSTEM=" + system,
		"GIT_EXEC_PATH=" + fake,
		"GIT_SSH_COMMAND=" + hook,
		"GIT_COMMON_DIR=" + filepath.Join(outside, ".git"),
		"GIT_NAMESPACE=hostile",
		"GIT_OBJECT_DIRECTORY=" + filepath.Join(outside, ".git", "objects"),
		"GIT_INDEX_FILE=" + filepath.Join(outside, "index"),
		"GIT_CEILING_DIRECTORIES=" + inside,
		"LGB_REAL_GIT=" + hook,
		"GIT_WRAP_TEST=1",
	}
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		cmd := exec.Command(wrap, args...)
		cmd.Dir = dir
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	out, err := run(work, "clone", "file://"+outside, filepath.Join(work, "out-dest"))
	if err == nil || !strings.Contains(out, "local path is outside the workspace") {
		t.Fatalf("outside clone: %v\n%s", err, out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("outside clone ran a helper\n%s", out)
	}
	out, err = run(work, "-c", "protocol.file.allow=always", "status")
	if err == nil || !strings.Contains(out, "configuration is not allowed") {
		t.Fatalf("protocol config: %v\n%s", err, out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("protocol config ran a helper\n%s", out)
	}
	out, err = run(work, "clone", "file://"+inside, filepath.Join(work, "in-dest"))
	if err != nil {
		t.Fatalf("inside clone: %v\n%s", err, out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("inside clone ran a helper\n%s", out)
	}
	body, err := os.ReadFile(filepath.Join(work, "in-dest", "i.txt"))
	if err != nil || string(body) != "i\n" {
		t.Fatalf("inside content %q %v", body, err)
	}
	out, err = run(inside, "status", "--short")
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
}

func TestGitWrapGitDirStaysReadOnly(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	unset := ""
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "unset ") && strings.Contains(line, "GIT_DIR") {
			unset = line
			break
		}
	}
	if unset == "" {
		t.Fatal("missing unset list")
	}
	for _, name := range []string{
		"GIT_COMMON_DIR",
		"GIT_NAMESPACE",
		"GIT_OBJECT_DIRECTORY",
		"GIT_INDEX_FILE",
		"GIT_CEILING_DIRECTORIES",
	} {
		if !strings.Contains(unset, name) {
			t.Fatalf("unset list missing %s", name)
		}
	}
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	clean := filepath.Join(work, "clean")
	src := filepath.Join(work, "src")
	commitRepo(t, clean, "c.txt", "clean\n")
	srcSHA := commitRepo(t, src, "s.txt", "src\n")
	if err := os.Mkdir(filepath.Join(clean, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(work, "marker")
	hook := filepath.Join(work, "hook.sh")
	writeMarkerHook(t, hook, marker)
	srcURL := "file://" + src
	newTracked := func(name string) string {
		t.Helper()
		dir := filepath.Join(clean, name)
		commitRepo(t, dir, "t.txt", name+"\n")
		gitCmd(t, dir, "remote", "add", "origin", srcURL)
		return dir
	}
	up := newTracked("up")
	gitCmd(t, up, "config", "remote.origin.uploadpack", hook)
	inc := newTracked("inc")
	incFile := filepath.Join(work, "inc.gitconfig")
	if err := os.WriteFile(incFile, []byte("[remote \"origin\"]\n\tuploadpack = "+hook+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, inc, "config", "include.path", incFile)
	urlRepo := filepath.Join(clean, "urlrepo")
	commitRepo(t, urlRepo, "u.txt", "url\n")
	gitCmd(t, urlRepo, "remote", "add", "x", srcURL)
	wrap := installGitWrap(t, work)
	denied := "option is not allowed"
	refuse := func(dir string, args ...string) {
		t.Helper()
		if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		out, err := runInstalledWrap(t, wrap, dir, nil, args...)
		if err == nil || !strings.Contains(out, denied) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
			t.Fatalf("%v created the marker\n%s", args, out)
		}
	}
	refuse(clean, "--git-dir=up/.git", "fetch", "origin")
	refuse(clean, "--git-dir", "up/.git", "fetch", "origin")
	refuse(filepath.Join(clean, "sub"), "--git-dir=../up/.git", "fetch", "origin")
	refuse(clean, "--git-dir=up/.git", "--work-tree=up", "fetch", "origin")
	refuse(clean, "--git-dir=up/.git", "ls-remote", "origin")
	refuse(clean, "--git-dir=up/.git", "pull", "origin")
	refuse(clean, "--git-dir=inc/.git", "fetch", "origin")
	refuse(clean, "--git-dir=urlrepo/.git", "fetch", "x")
	if gitHasObject(filepath.Join(urlRepo, ".git"), srcSHA) {
		t.Fatal("fetch stored the other repository")
	}
	for _, args := range [][]string{
		{"--git-dir=.git", "status"},
		{"--work-tree=.", "status"},
		{"--git-dir=.git", "--work-tree=.", "status"},
	} {
		out, err := runInstalledWrap(t, wrap, clean, nil, args...)
		if err != nil || strings.Contains(out, denied) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
}

func TestGitWrapAliasStaysRefused(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	if !strings.Contains(script, "alias.*") || !strings.Contains(script, `config --includes --get "alias.$sub"`) {
		t.Fatal("alias check is missing")
	}
	// A command-line alias is refused.
	// A repository that stores any alias is refused for every command except
	// config, including an alias that is not the invoked word.
	configDenied := "configuration is not allowed"
	for _, args := range [][]string{
		{"-c", "alias.cl=clone", "status"},
		{"--config", "alias.x=fetch", "status"},
		{"--config=alias.y=log", "status"},
	} {
		text := runGitWrap(t, script, args...)
		if !strings.Contains(text, configDenied) {
			t.Fatalf("%v: %s", args, text)
		}
	}
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	outside := t.TempDir()
	inside := filepath.Join(work, "inside")
	repo := filepath.Join(work, "repo")
	clean := filepath.Join(work, "clean")
	commitRepo(t, inside, "i.txt", "inside\n")
	outsideSHA := commitRepo(t, outside, "o.txt", "outside-marker\n")
	commitRepo(t, repo, "r.txt", "repo\n")
	commitRepo(t, clean, "c.txt", "clean\n")
	marker := filepath.Join(work, "marker")
	hook := filepath.Join(work, "hook.sh")
	writeMarkerHook(t, hook, marker)
	url := "file://" + inside
	gitCmd(t, repo, "config", "alias.cl", "clone")
	gitCmd(t, repo, "config", "alias.fe", "fetch")
	gitCmd(t, repo, "config", "alias.lr", "ls-remote")
	gitCmd(t, repo, "config", "alias.boom", "!"+hook)
	gitCmd(t, repo, "config", "alias.other", "status")
	wrap := installGitWrap(t, work)
	refuse := func(dir string, args ...string) {
		t.Helper()
		if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		out, err := runInstalledWrap(t, wrap, dir, nil, args...)
		if err == nil || !strings.Contains(out, configDenied) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
			t.Fatalf("%v ran the helper\n%s", args, out)
		}
	}
	refuse(repo, "cl", "--upload-pack="+hook, url, filepath.Join(work, "d-eq"))
	refuse(repo, "cl", "-qu"+hook, url, filepath.Join(work, "d-qu"))
	refuse(repo, "cl", "-u", hook, url, filepath.Join(work, "d-u"))
	refuse(repo, "fe", "--upload-pack="+hook, url)
	refuse(repo, "lr", "--exec="+hook, url)
	refuse(repo, "cl", "--reference", outside, url, filepath.Join(work, "d-ref"))
	if gitHasObject(filepath.Join(work, "d-ref", ".git"), outsideSHA) {
		t.Fatal("reference read the outside repository")
	}
	refuse(repo, "boom")
	// The alias lookup has to read the repository named by -C.
	gitCmd(t, clean, "config", "alias.keep", "status")
	aliased := filepath.Join(work, "aliased")
	commitRepo(t, aliased, "a.txt", "aliased\n")
	gitCmd(t, aliased, "config", "alias.cl", "clone")
	refuse(clean, "-C", aliased, "cl", "--upload-pack="+hook, url, filepath.Join(work, "d-c"))
	// alias.other is not the invoked word. The stored alias is still refused.
	refuse(repo, "status")
	refuse(repo, "log", "--oneline")
}

func TestGitWrapFetchMultipleStaysRefused(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	outside := t.TempDir()
	inside := filepath.Join(work, "inside")
	repo := filepath.Join(work, "repo")
	insideSHA := commitRepo(t, inside, "i.txt", "inside\n")
	outsideSHA := commitRepo(t, outside, "o.txt", "outside-marker\n")
	commitRepo(t, repo, "r.txt", "repo\n")
	gitCmd(t, repo, "remote", "add", "x", "file://"+inside)
	gitCmd(t, repo, "remote", "add", "e", "file://"+outside)
	wrap := installGitWrap(t, work)
	denied := "option is not allowed"
	gitDir := filepath.Join(repo, ".git")
	for _, args := range [][]string{
		{"fetch", "--multiple", "x", "e"},
		{"fetch", "--multiple=1", "x", "e"},
		{"fetch", "--m", "x", "e"},
		{"fetch", "--mu", "x", "e"},
		{"fetch", "--mul", "x", "e"},
		{"fetch", "-m", "x", "e"},
		{"fetch", "-qm", "x", "e"},
		{"fetch", "-mq", "x", "e"},
		{"fetch", "-vm", "x", "e"},
	} {
		out, err := runInstalledWrap(t, wrap, repo, nil, args...)
		if err == nil || !strings.Contains(out, denied) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if gitHasObject(gitDir, outsideSHA) {
			t.Fatalf("%v stored the outside commit\n%s", args, out)
		}
	}
	for _, args := range [][]string{
		{"fetch", "x"},
		{"fetch", "x", "main"},
		{"fetch", "-q", "x"},
		{"fetch", "--depth", "1", "x"},
		{"fetch", "-j2", "x"},
	} {
		out, err := runInstalledWrap(t, wrap, repo, nil, args...)
		if err != nil || strings.Contains(out, denied) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	if !gitHasObject(gitDir, insideSHA) {
		t.Fatal("fetch did not store the workspace commit")
	}
	if gitHasObject(gitDir, outsideSHA) {
		t.Fatal("fetch stored the outside commit")
	}
}

func TestGitWrapInsteadOfStaysRefused(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	outside := t.TempDir()
	inside := filepath.Join(work, "inside")
	insideSHA := commitRepo(t, inside, "i.txt", "inside\n")
	outsideSHA := commitRepo(t, outside, "o.txt", "outside-marker\n")
	insideURL := "file://" + inside
	wrap := installGitWrap(t, work)
	configDenied := "configuration is not allowed"
	newConsumer := func(name string) string {
		t.Helper()
		dir := filepath.Join(work, name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		gitCmd(t, dir, "init", "-b", "main")
		return dir
	}
	refuseFetch := func(dir string, args ...string) {
		t.Helper()
		out, err := runInstalledWrap(t, wrap, dir, nil, args...)
		if err == nil || !strings.Contains(out, configDenied) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if gitHasObject(filepath.Join(dir, ".git"), outsideSHA) {
			t.Fatalf("%v stored the outside commit\n%s", args, out)
		}
	}
	fileRepo := newConsumer("file-url")
	gitCmd(t, fileRepo, "config", "url.file://"+outside+".insteadOf", insideURL)
	refuseFetch(fileRepo, "fetch", insideURL)
	refuseFetch(fileRepo, "ls-remote", insideURL)
	refuseFetch(fileRepo, "pull", "--no-rebase", insideURL, "main")
	pathRepo := newConsumer("path-url")
	gitCmd(t, pathRepo, "config", "url."+outside+".insteadOf", inside)
	refuseFetch(pathRepo, "fetch", inside)
	pushRepo := newConsumer("push-url")
	gitCmd(t, pushRepo, "config", "url.file://"+outside+".pushInsteadOf", insideURL)
	refuseFetch(pushRepo, "fetch", insideURL)
	plain := newConsumer("plain")
	out, err := runInstalledWrap(t, wrap, plain, nil, "fetch", insideURL)
	if err != nil {
		t.Fatalf("fetch: %v\n%s", err, out)
	}
	if !gitHasObject(filepath.Join(plain, ".git"), insideSHA) {
		t.Fatal("fetch did not store the workspace commit")
	}
	if gitHasObject(filepath.Join(plain, ".git"), outsideSHA) {
		t.Fatal("fetch stored the outside commit")
	}
}

func TestGitWrapIncludeIfStaysRefused(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	if !strings.Contains(script, `include(if\..*)?\.path`) {
		t.Fatal("include pattern is missing")
	}
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	src := filepath.Join(work, "src")
	srcSHA := commitRepo(t, src, "s.txt", "src\n")
	url := "file://" + src
	harmless := filepath.Join(work, "harmless.gitconfig")
	if err := os.WriteFile(harmless, []byte("[advice]\n\tdetachedHead = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	configDenied := "configuration is not allowed"
	refuse := func(name, key, value string) {
		t.Helper()
		dir := filepath.Join(work, name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		gitCmd(t, dir, "init", "-b", "main")
		gitCmd(t, dir, "remote", "add", "x", url)
		gitCmd(t, dir, "config", key, value)
		out, err := runInstalledWrap(t, wrap, dir, nil, "fetch", "x")
		if err == nil || !strings.Contains(out, configDenied) {
			t.Fatalf("%s: %v\n%s", key, err, out)
		}
		if gitHasObject(filepath.Join(dir, ".git"), srcSHA) {
			t.Fatalf("%s stored the commit", key)
		}
	}
	refuse("gitdir", "includeIf.gitdir:"+work+"/.path", harmless)
	refuse("onbranch", "includeIf.onbranch:main.path", harmless)
}

func TestGitWrapConfigReadUsesDashC(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	clean := filepath.Join(work, "clean")
	src := filepath.Join(work, "src")
	commitRepo(t, clean, "c.txt", "clean\n")
	srcSHA := commitRepo(t, src, "s.txt", "src\n")
	url := "file://" + src
	marker := filepath.Join(work, "marker")
	hook := filepath.Join(work, "hook.sh")
	writeMarkerHook(t, hook, marker)
	harmless := filepath.Join(work, "harmless.gitconfig")
	if err := os.WriteFile(harmless, []byte("[advice]\n\tdetachedHead = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	configDenied := "configuration is not allowed"
	withRemote := func(name string) string {
		t.Helper()
		dir := filepath.Join(work, name)
		commitRepo(t, dir, "t.txt", name+"\n")
		gitCmd(t, dir, "remote", "add", "origin", url)
		return dir
	}
	t.Run("uploadpack", func(t *testing.T) {
		dir := withRemote("up")
		gitCmd(t, dir, "config", "remote.origin.uploadpack", hook)
		if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		out, err := runInstalledWrap(t, wrap, clean, nil, "-C", dir, "fetch", "origin")
		if err == nil || !strings.Contains(out, configDenied) {
			t.Fatalf("fetch: %v\n%s", err, out)
		}
		if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
			t.Fatalf("helper ran\n%s", out)
		}
	})
	t.Run("include", func(t *testing.T) {
		dir := withRemote("inc")
		gitCmd(t, dir, "config", "include.path", harmless)
		out, err := runInstalledWrap(t, wrap, clean, nil, "-C", dir, "fetch", "origin")
		if err == nil || !strings.Contains(out, configDenied) {
			t.Fatalf("fetch: %v\n%s", err, out)
		}
		if gitHasObject(filepath.Join(dir, ".git"), srcSHA) {
			t.Fatal("fetch stored the commit")
		}
	})
}

func TestGitWrapRemoteKeysStayRefused(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	src := filepath.Join(work, "src")
	commitRepo(t, src, "s.txt", "src\n")
	url := "file://" + src
	marker := filepath.Join(work, "marker")
	hook := filepath.Join(work, "hook.sh")
	writeMarkerHook(t, hook, marker)
	wrap := installGitWrap(t, work)
	configDenied := "configuration is not allowed"
	keys := []struct {
		name  string
		value string
	}{
		{"vcs", "true"},
		{"proxy", "127.0.0.1:9"},
		{"receivepack", hook},
		{"uploadpack", hook},
	}
	for _, key := range keys {
		t.Run(key.name, func(t *testing.T) {
			dir := filepath.Join(work, key.name)
			commitRepo(t, dir, "t.txt", key.name+"\n")
			gitCmd(t, dir, "remote", "add", "x", url)
			gitCmd(t, dir, "config", "remote.x."+key.name, key.value)
			if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			out, err := runInstalledWrap(t, wrap, dir, nil, "fetch", "x")
			if err == nil || !strings.Contains(out, configDenied) {
				t.Fatalf("fetch: %v\n%s", err, out)
			}
			if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
				t.Fatalf("helper ran\n%s", out)
			}
		})
	}
}

func TestGitWrapCommandLinePins(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Hub: true, Bridge: true, Name: "Ada", Email: "bot@localhost"})
	pins := []string{
		"protocol.allow=never",
		"protocol.https.allow=always",
		"protocol.ssh.allow=always",
		`protocol.file.allow="$pfile"`,
		"fetch.recurseSubmodules=false",
		"submodule.recurse=false",
	}
	cargs := between(t, script, "cargs=(", ")")
	requirePins(t, "cargs", cargs, pins)
	if strings.Contains(cargs, "protocol.http.allow") {
		t.Fatal("cargs contains protocol.http.allow")
	}
	parts := strings.Split(script, `if [ -n "$GHPORT" ]; then`)
	if len(parts) < 2 {
		t.Fatal("missing bridge exec")
	}
	last := parts[len(parts)-1]
	fi := strings.Index(last, "\n  fi\n")
	if fi < 0 {
		t.Fatal("bridge block")
	}
	bridge := last[:fi]
	plain := last[fi:]
	requirePins(t, "bridge", bridge, pins)
	if !strings.Contains(bridge, "protocol.http.allow=always") {
		t.Fatal("bridge missing protocol.http.allow=always")
	}
	plainEnd := strings.Index(plain, `-- "$@"`)
	if plainEnd < 0 {
		t.Fatal("plain exec has no argument separator")
	}
	plain = plain[:plainEnd]
	requirePins(t, "plain", plain, pins)
	if strings.Contains(plain, "protocol.http.allow") {
		t.Fatal("plain exec contains protocol.http.allow")
	}
	bash := between(t, script, "exec /bin/bash --norc --noprofile -c '", "' bash ")
	if !strings.Contains(bash, "pfile=$5") {
		t.Fatal("bash path missing pfile=$5")
	}
	for _, constant := range []string{"pfile=never", "pfile=user", "pfile=always", "protocol.file.allow=never", "protocol.file.allow=user", "protocol.file.allow=always"} {
		if strings.Contains(bash, constant) {
			t.Fatalf("bash path has constant %s", constant)
		}
	}
	requirePins(t, "bash", bash, pins)
	if strings.Count(bash, "protocol.http.allow=always") != 1 {
		t.Fatal("bash path should set protocol.http.allow only for the bridge")
	}
	if !strings.Contains(bash, `"${lead[@]}" "${cargs[@]}"`) {
		t.Fatal("bash pins do not follow the caller's arguments")
	}
	if strings.Contains(bash, `"${cargs[@]}" "${lead[@]}"`) {
		t.Fatal("bash pins precede the caller's arguments")
	}
	if !strings.Contains(script, `eval "set -- $lead $pins $rest"`) {
		t.Fatal("pins do not follow the caller's arguments")
	}
	if !strings.Contains(script, `"$GHPORT" "$pfile" "$sub"`) {
		t.Fatal("bash path does not take pfile from its arguments")
	}
}

func TestGitWrapOptionValuesStayAttached(t *testing.T) {
	// clone -u <value> is refused when that option word is seen, so the
	// following word is not used as the repository. The refusal exits
	// before a later check can tell whether the word was consumed.
	// TestGitWrapRemoteCommandStaysRefused covers the separate -u word.
	// A one-dash word is not a long option. The helper returns before it
	// reads the name, and stripping two dashes leaves the word unchanged,
	// so a command cannot separate those two checks.
	// -omyorigin is one word and is passed through with every other short
	// cluster, so dropping only the attached -o arm does not change it.
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	src := filepath.Join(work, "src")
	commitRepo(t, src, "ok.txt", "ok\n")
	url := "file://" + src
	wrap := installGitWrap(t, work)
	succeed := func(args []string, dest string) {
		t.Helper()
		out, err := runInstalledWrap(t, wrap, work, nil, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		body, err := os.ReadFile(filepath.Join(dest, "ok.txt"))
		if err != nil || string(body) != "ok\n" {
			t.Fatalf("%v content %q %v\n%s", args, body, err, out)
		}
	}
	origin := filepath.Join(work, "named")
	succeed([]string{"clone", "-o", "myorigin", url, origin}, origin)
	if got := gitCmdOut(t, origin, "remote"); got != "myorigin" {
		t.Fatalf("origin name %q", got)
	}
	attached := filepath.Join(work, "attached")
	succeed([]string{"clone", "-omyorigin", url, attached}, attached)
	server := filepath.Join(work, "server")
	succeed([]string{"clone", "--server-option", "opt", url, server}, server)
	rev := filepath.Join(work, "rev")
	succeed([]string{"clone", "--revision", "main", url, rev}, rev)
	end := filepath.Join(work, "end")
	succeed([]string{"clone", "--", url, end}, end)
	out, err := runInstalledWrap(t, wrap, work, nil, "clone", "--=x", url, filepath.Join(work, "empty-name"))
	if strings.Contains(out, "option is not allowed") {
		t.Fatalf("empty option name: %v\n%s", err, out)
	}
}

func between(t *testing.T, script, start, end string) string {
	t.Helper()
	i := strings.Index(script, start)
	if i < 0 {
		t.Fatalf("missing %q", start)
	}
	rest := script[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		t.Fatalf("missing %q after %q", end, start)
	}
	return rest[:j]
}

func requirePins(t *testing.T, where, block string, pins []string) {
	t.Helper()
	for _, pin := range pins {
		if !strings.Contains(block, pin) {
			t.Fatalf("%s missing %s", where, pin)
		}
	}
}

func commitRepo(t *testing.T, dir, file, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, file), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, dir, "init", "-b", "main")
	gitCmd(t, dir, "add", "--", file)
	gitCmd(t, dir, "commit", "-m", "init")
	return gitCmdOut(t, dir, "rev-parse", "HEAD")
}

func installGitWrap(t *testing.T, work string) string {
	t.Helper()
	return installGitWrapWith(t, work, gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
}

func installGitWrapWith(t *testing.T, work string, opts gitWrapOpts) string {
	t.Helper()
	skipIfJailWrapper(t)
	real, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	real, err = filepath.Abs(real)
	if err != nil {
		t.Fatal(err)
	}
	return installGitWrapReal(t, work, real, opts)
}

func installGitWrapReal(t *testing.T, work, real string, opts gitWrapOpts) string {
	t.Helper()
	skipIfJailWrapper(t)
	if opts.Name == "" {
		opts.Name = "Ada"
	}
	if opts.Email == "" {
		opts.Email = "bot@localhost"
	}
	script := gitWrap(opts)
	script = strings.ReplaceAll(script, "/lgb/bin/git", real)
	script = strings.ReplaceAll(script, "/work", work)
	wrap := filepath.Join(t.TempDir(), "gitwrap")
	if err := os.WriteFile(wrap, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return wrap
}

func hostGitAtLeast(t *testing.T, major, minor int) bool {
	t.Helper()
	out, err := exec.Command("git", "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 3 {
		return false
	}
	parts := strings.Split(fields[2], ".")
	if len(parts) < 2 {
		return false
	}
	ma, err1 := strconv.Atoi(parts[0])
	mi, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return ma > major || (ma == major && mi >= minor)
}

func gitLocalGet(dir, key string) (string, bool) {
	cmd := exec.Command("git", "-C", dir, "config", "--local", "--get", key)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

func gitConfigFileGet(file, key string) (string, bool) {
	cmd := exec.Command("git", "config", "--file", file, "--get", key)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + filepath.Dir(file),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

func runWrapTimeout(t *testing.T, wrap, dir string, extra []string, d time.Duration, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	cmd := exec.CommandContext(ctx, wrap, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_ALLOW_PROTOCOL=https:ssh", "GIT_TERMINAL_PROMPT=0")
	cmd.Env = append(cmd.Env, extra...)
	out, err := cmd.CombinedOutput()
	return string(out), err
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
	gitCmdOut(t, dir, args...)
}

func gitCmdOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	skipIfJailWrapper(t)
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
	return strings.TrimSpace(string(out))
}

func gitHasObject(gitDir, oid string) bool {
	cmd := exec.Command("git", "--git-dir", gitDir, "cat-file", "-e", oid)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + gitDir,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
	}
	return cmd.Run() == nil
}

func writeMarkerHook(t *testing.T, path, marker string) {
	t.Helper()
	if strings.Contains(path, "'") || strings.Contains(marker, "'") {
		t.Fatal("path")
	}
	body := "#!/bin/sh\necho ran >> '" + marker + "'\nexit 1\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// Behavioral wrapper checks run on the host only. In the jail, the static script checks still run.
func skipIfJailWrapper(t *testing.T) {
	t.Helper()
	if st, err := os.Stat("/lgb/bin/git"); err == nil && !st.IsDir() {
		t.Skip("skipped in the jail, where git on PATH is the wrapper")
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

func TestGitWrapFetchUpdateHeadStaysVetted(t *testing.T) {
	// fetch -u takes no value, so the word after it is still the remote.
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	outside := t.TempDir()
	inside := filepath.Join(work, "inside")
	repo := filepath.Join(work, "repo")
	commitRepo(t, inside, "i.txt", "inside\n")
	outsideSHA := commitRepo(t, outside, "o.txt", "outside-marker\n")
	commitRepo(t, repo, "r.txt", "repo\n")
	gitCmd(t, repo, "remote", "add", "e", "file://"+outside)
	wrap := installGitWrap(t, work)
	gitDir := filepath.Join(repo, ".git")
	for _, args := range [][]string{
		{"fetch", "-u", "e", "file://" + inside},
		{"fetch", "-u", "e", inside},
		{"fetch", "--update-head-ok", "e", "file://" + inside},
		{"pull", "-u", "e", "file://" + inside},
	} {
		out, err := runInstalledWrap(t, wrap, repo, nil, args...)
		if gitHasObject(gitDir, outsideSHA) {
			t.Fatalf("%v stored the outside commit: %v\n%s", args, err, out)
		}
	}
}

// TestGitWrapConfigAllowlistStaysClosed refuses repository config outside the
// short allowed set. git config is the only command that still runs, so a key
// can be removed. A repository config that stores a command-valued alias, or
// a filter driver, is refused even when that command is not the one invoked.
func TestGitWrapConfigAllowlistStaysClosed(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	guard := `[ "$sub" != config ]`
	list := "config --includes --name-only --list --show-origin"
	guardAt := strings.Index(script, guard)
	listAt := strings.Index(script, list)
	if guardAt < 0 || listAt < 0 || listAt < guardAt {
		t.Fatal("allowlist read is missing or is not limited to commands other than config")
	}
	block := script[guardAt : listAt+len(list)]
	for _, needle := range []string{
		`eval "set -- $gitdir_args"`,
		`-C "$vet_base"`,
		"core.hooksPath=/dev/null",
		"core.fsmonitor=",
		"core.sshCommand=/bin/false",
		"protocol.allow=never",
		"safe.directory=",
		"--includes --name-only --list",
		"--show-origin",
	} {
		if !strings.Contains(block, needle) {
			t.Fatalf("allowlist read missing %s", needle)
		}
	}
	if strings.Contains(script[guardAt:guardAt+len(guard)+40], "status") {
		t.Fatal("allowlist exemption is not only config")
	}
	if strings.Count(script, `eval "set -- $gitdir_args"`) < 2 {
		t.Fatal("repository options are not passed to the config reads")
	}
	if !strings.Contains(script, `gitdir_args="$gitdir_args $(quote "$arg")"`) {
		t.Fatal("repository options are not recorded")
	}
	if !strings.Contains(script, "config_key_allowed()") {
		t.Fatal("allowlist is not a shared function")
	}
	if !strings.Contains(script, "config_guard()") {
		t.Fatal("config_guard is missing")
	}
	if strings.Contains(script, "remote.*.promisor") || strings.Contains(script, "partialclonefilter") {
		t.Fatal("promisor keys are still on the allowlist")
	}
	for _, pat := range []string{
		"core.repositoryformatversion|core.filemode|core.bare|core.logallrefupdates|core.ignorecase|core.precomposeunicode|core.symlinks)",
		"core.worktree)",
		"branch.*.remote|branch.*.merge|branch.*.rebase|branch.*.description|branch.*.pushremote)",
		"remote.*.url|remote.*.fetch)",
		"remote.*.tagopt)",
		"remote.*.mirror)",
		"extensions.objectformat)",
		"user.name|user.email)",
		"submodule.*.url|submodule.*.active|submodule.active)",
		"core.autocrlf|core.eol|core.safecrlf)",
		"core.sparsecheckout|core.sparsecheckoutcone|index.sparse|extensions.worktreeconfig)",
		"pull.rebase|pull.ff)",
		"color.*)",
		"advice.*)",
	} {
		if !strings.Contains(script, pat) {
			t.Fatalf("missing allow pattern %s", pat)
		}
	}
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	wrap := installGitWrap(t, work)
	marker := filepath.Join(work, "marker")
	hook := filepath.Join(work, "hook.sh")
	writeMarkerHook(t, hook, marker)
	configDenied := "configuration is not allowed"
	commands := [][]string{
		{"status"},
		{"log"},
		{"add", "f.txt"},
		{"commit", "-m", "x"},
		{"diff"},
		{"fetch"},
	}
	repoDir := func(name string) string {
		t.Helper()
		dir := filepath.Join(work, name)
		commitRepo(t, dir, "f.txt", name+"\n")
		return dir
	}
	refused := func(dir string, args ...string) {
		t.Helper()
		if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		out, err := runInstalledWrap(t, wrap, dir, nil, args...)
		if err == nil || !strings.Contains(out, configDenied) {
			t.Fatalf("%s %v: %v\n%s", dir, args, err, out)
		}
		if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
			t.Fatalf("%v ran the marker\n%s", args, out)
		}
	}
	unsetAndStatus := func(dir, key string, unsetArgs ...string) {
		t.Helper()
		out, err := runInstalledWrap(t, wrap, dir, nil, unsetArgs...)
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("unset %s: %v\n%s", key, err, out)
		}
		if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
			t.Fatalf("unset %s ran the marker\n%s", key, out)
		}
		out, err = runInstalledWrap(t, wrap, dir, nil, "status")
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("status after unset %s: %v\n%s", key, err, out)
		}
	}
	for _, tc := range []struct {
		name  string
		key   string
		value string
	}{
		{"fsmonitor", "core.fsmonitor", hook},
		{"hooks", "core.hooksPath", hook},
		{"pager", "core.pager", hook},
		{"editor", "core.editor", hook},
		{"attributes", "core.attributesFile", hook},
		{"clean", "filter.x.clean", hook},
		{"smudge", "filter.x.smudge", hook},
		{"textconv", "diff.x.textconv", hook},
		{"merge", "merge.x.driver", hook},
		{"credential", "credential.helper", hook},
		{"proxy", "http.proxy", "http://127.0.0.1:9"},
		{"fileproto", "protocol.file.allow", "always"},
		{"recurse", "fetch.recurseSubmodules", "yes"},
		{"alias-bang", "alias.x", "!echo hi"},
		{"alias-plain", "alias.x", "status"},
		{"alias-hook", "alias.x", "!" + hook},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := repoDir(tc.name)
			gitCmd(t, dir, "config", tc.key, tc.value)
			for _, args := range commands {
				refused(dir, args...)
			}
			unsetAndStatus(dir, tc.key, "config", "--unset", tc.key)
		})
	}

	t.Run("include", func(t *testing.T) {
		dir := repoDir("include")
		inc := filepath.Join(work, "included.gitconfig")
		if err := os.WriteFile(inc, []byte("[core]\n\tfsmonitor = "+hook+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// include.path is itself outside the allowlist.
		gitCmd(t, dir, "config", "include.path", inc)
		for _, args := range commands {
			refused(dir, args...)
		}
		unsetAndStatus(dir, "include.path", "config", "--unset", "include.path")
	})

	t.Run("worktree", func(t *testing.T) {
		dir := repoDir("worktree-key")
		gitCmd(t, dir, "config", "extensions.worktreeConfig", "true")
		gitCmd(t, dir, "config", "--worktree", "core.fsmonitor", hook)
		for _, args := range commands {
			refused(dir, args...)
		}
		out, err := runInstalledWrap(t, wrap, dir, nil, "config", "--worktree", "--unset", "core.fsmonitor")
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("unset worktree key: %v\n%s", err, out)
		}
		unsetAndStatus(dir, "extensions.worktreeConfig", "config", "--unset", "extensions.worktreeConfig")
	})

	t.Run("git-dir", func(t *testing.T) {
		clean := repoDir("clean-gitdir")
		hostile := repoDir("hostile-gitdir")
		gitCmd(t, hostile, "config", "core.fsmonitor", hook)
		hostileGit := filepath.Join(hostile, ".git")
		for _, args := range [][]string{
			{"--git-dir=" + hostileGit, "status"},
			{"--git-dir", hostileGit, "--work-tree", hostile, "log"},
			{"--git-dir=" + hostileGit, "--work-tree=" + hostile, "diff"},
		} {
			refused(clean, args...)
		}
		// The clean repository named by --git-dir is the one that is read.
		out, err := runInstalledWrap(t, wrap, hostile, nil, "--git-dir="+filepath.Join(clean, ".git"), "--work-tree="+clean, "status")
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("clean git dir: %v\n%s", err, out)
		}
		if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
			t.Fatalf("clean git dir ran the marker\n%s", out)
		}
	})

	t.Run("allowed", func(t *testing.T) {
		dir := repoDir("allowed")
		inside := repoDir("allowed-src")
		gitCmd(t, dir, "config", "user.name", "Ada")
		gitCmd(t, dir, "config", "user.email", "ada@example.com")
		gitCmd(t, dir, "remote", "add", "origin", "file://"+inside)
		gitCmd(t, dir, "config", "branch.main.remote", "origin")
		gitCmd(t, dir, "config", "branch.main.merge", "refs/heads/main")
		if err := os.WriteFile(filepath.Join(dir, "n.txt"), []byte("n\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{
			{"status"},
			{"log", "-1"},
			{"diff"},
			{"add", "n.txt"},
			{"commit", "-m", "n"},
			{"fetch", "origin"},
			{"branch"},
			{"checkout", "-b", "side"},
			{"show", "HEAD"},
		} {
			out, err := runInstalledWrap(t, wrap, dir, nil, args...)
			if err != nil || strings.Contains(out, configDenied) {
				t.Fatalf("%v: %v\n%s", args, err, out)
			}
		}
	})
}

// TestGitWrapRecordedConfigStaysAllowed runs the ordinary init, clone, and
// checkout flows with plain git and requires the wrapper to accept each
// resulting repository. Sparse-checkout writes keys that stay refused.
func TestGitWrapRecordedConfigStaysAllowed(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	wrap := installGitWrap(t, work)
	configDenied := "configuration is not allowed"
	src := filepath.Join(work, "src")
	commitRepo(t, src, "f.txt", "hi\n")
	// The source allows a partial clone. uploadpack.allowFilter is not an
	// allowed key, so this repository is not required to pass the wrapper.
	gitCmd(t, src, "config", "uploadpack.allowFilter", "true")
	url := "file://" + src

	localKeys := func(dir string) []string {
		t.Helper()
		text := gitCmdOut(t, dir, "config", "--local", "--list", "--name-only")
		if text == "" {
			return nil
		}
		keys := strings.Split(text, "\n")
		sort.Strings(keys)
		return keys
	}
	effectiveKeys := func(dir string) []string {
		t.Helper()
		cmd := exec.Command("git", "-C", dir, "config", "--includes", "--name-only", "--list", "--show-origin")
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + dir,
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_TERMINAL_PROMPT=0",
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("effective keys: %v\n%s", err, out)
		}
		var keys []string
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimRight(line, "\r")
			if line == "" || strings.HasPrefix(line, "command line:") {
				continue
			}
			if i := strings.IndexByte(line, '\t'); i >= 0 {
				line = line[i+1:]
			}
			keys = append(keys, line)
		}
		sort.Strings(keys)
		return keys
	}
	accept := func(name, dir string, bare bool) {
		t.Helper()
		local := localKeys(dir)
		eff := effectiveKeys(dir)
		t.Logf("%s local: %s", name, strings.Join(local, " "))
		t.Logf("%s effective: %s", name, strings.Join(eff, " "))
		if bare {
			out, err := runInstalledWrap(t, wrap, dir, nil, "rev-parse", "--is-bare-repository")
			if err != nil || strings.TrimSpace(out) != "true" {
				t.Fatalf("%s rev-parse: %v\n%s\nkeys %v", name, err, out, eff)
			}
			out, _ = runInstalledWrap(t, wrap, dir, nil, "status")
			if strings.Contains(out, configDenied) {
				t.Fatalf("%s status refused\n%s\nkeys %v", name, out, eff)
			}
			return
		}
		out, err := runInstalledWrap(t, wrap, dir, nil, "status")
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("%s status: %v\n%s\nkeys %v", name, err, out, eff)
		}
	}
	mkdir := func(name string) string {
		t.Helper()
		dir := filepath.Join(work, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	initDir := func(name string, args ...string) string {
		t.Helper()
		dir := mkdir(name)
		gitCmd(t, dir, append([]string{"init"}, args...)...)
		return dir
	}

	accept("init", initDir("init"), false)
	accept("init-b", initDir("init-b", "-b", "main"), false)
	accept("init-bare", initDir("init-bare", "--bare"), true)
	accept("init-sha256", initDir("init-sha256", "-b", "main", "--object-format=sha256"), false)

	clone := func(name string, args ...string) string {
		t.Helper()
		dir := filepath.Join(work, name)
		gitCmd(t, work, append(append([]string{"clone"}, args...), url, dir)...)
		return dir
	}
	accept("clone", clone("c-plain"), false)
	accept("clone-depth", clone("c-depth", "--depth", "1"), false)
	accept("clone-branch", clone("c-branch", "--branch", "main"), false)
	accept("clone-single", clone("c-single", "--single-branch"), false)
	accept("clone-notags", clone("c-notags", "--no-tags"), false)
	accept("clone-origin", clone("c-origin", "--origin", "x"), false)
	accept("clone-bare", clone("c-bare", "--bare"), true)
	accept("clone-mirror", clone("c-mirror", "--mirror"), true)
	sep := filepath.Join(work, "sep.git")
	sepDest := filepath.Join(work, "c-sep")
	gitCmd(t, work, "clone", "--separate-git-dir", sep, url, sepDest)
	accept("clone-separate-git-dir", sepDest, false)
	// clone --filter writes remote.*.promisor and remote.*.partialclonefilter.
	filterDir := clone("c-filter", "--filter=blob:none")
	out, err := runInstalledWrap(t, wrap, filterDir, nil, "status")
	if err == nil || !strings.Contains(out, configDenied) {
		t.Fatalf("clone-filter status: %v\n%s", err, out)
	}

	remoteAdd := initDir("remote-add", "-b", "main")
	gitCmd(t, remoteAdd, "remote", "add", "origin", url)
	accept("remote-add", remoteAdd, false)

	dotted := filepath.Join(work, "dotted")
	commitRepo(t, dotted, "d.txt", "d\n")
	gitCmd(t, dotted, "remote", "add", "a.b", url)
	accept("remote-dotted", dotted, false)

	cob := filepath.Join(work, "checkout")
	commitRepo(t, cob, "a.txt", "a\n")
	gitCmd(t, cob, "checkout", "-b", "feature")
	accept("checkout-b", cob, false)
	gitCmd(t, cob, "remote", "add", "origin", url)
	gitCmd(t, cob, "fetch", "origin")
	gitCmd(t, cob, "branch", "--set-upstream-to=origin/main", "feature")
	accept("set-upstream", cob, false)

	committed := filepath.Join(work, "committed")
	commitRepo(t, committed, "b.txt", "b\n")
	accept("commit", committed, false)

	subsrc := filepath.Join(work, "subsrc")
	commitRepo(t, subsrc, "s.txt", "s\n")
	parent := filepath.Join(work, "sub-parent")
	commitRepo(t, parent, "p.txt", "p\n")
	gitCmd(t, parent, "-c", "protocol.file.allow=always", "submodule", "add", "file://"+subsrc, "sub")
	accept("submodule-add", parent, false)
	accept("submodule-gitdir", filepath.Join(parent, "sub"), false)

	wt := filepath.Join(work, "wt")
	commitRepo(t, wt, "w.txt", "w\n")
	linked := filepath.Join(work, "wt-linked")
	gitCmd(t, wt, "worktree", "add", "-b", "wtbranch", linked)
	accept("worktree", wt, false)
	accept("worktree-linked", linked, false)

	// sparse-checkout writes extensions.worktreeConfig plus core.sparseCheckout
	// and core.sparseCheckoutCone in the worktree config. Those keys are allowed.
	sparse := filepath.Join(work, "sparse")
	commitRepo(t, sparse, "s.txt", "s\n")
	gitCmd(t, sparse, "sparse-checkout", "init")
	sparseKeys := effectiveKeys(sparse)
	t.Logf("sparse effective: %s", strings.Join(sparseKeys, " "))
	for _, key := range []string{"extensions.worktreeconfig", "core.sparsecheckout", "core.sparsecheckoutcone"} {
		if !stringListHas(sparseKeys, key) {
			t.Fatalf("sparse-checkout did not write %s: %v", key, sparseKeys)
		}
	}
	accept("sparse", sparse, false)

	// Ordinary commands through the wrapper, in a fresh clone.
	fileDest := filepath.Join(work, "op-file")
	out, err = runInstalledWrap(t, wrap, work, nil, "clone", url, fileDest)
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("file clone: %v\n%s", err, out)
	}
	pathDest := filepath.Join(work, "op-path")
	out, err = runInstalledWrap(t, wrap, work, nil, "clone", src, pathDest)
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("path clone: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(src, "g.txt"), []byte("g\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, src, "add", "--", "g.txt")
	gitCmd(t, src, "commit", "-m", "more")
	for _, args := range [][]string{
		{"fetch", "origin"},
		{"pull", "origin"},
		{"status"},
		{"log", "-1"},
		{"diff"},
		{"show", "HEAD"},
		{"branch"},
	} {
		out, err = runInstalledWrap(t, wrap, fileDest, nil, args...)
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(fileDest, "n.txt"), []byte("n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", "n.txt"},
		{"commit", "-m", "n"},
		{"checkout", "-b", "side"},
		{"checkout", "main"},
		{"config", "user.name", "x"},
		{"status"},
	} {
		out, err = runInstalledWrap(t, wrap, fileDest, nil, args...)
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	out, err = runInstalledWrap(t, wrap, fileDest, nil, "push", "origin", "main")
	if err == nil || !strings.Contains(out, "not sent") || strings.Contains(out, configDenied) {
		t.Fatalf("push: %v\n%s", err, out)
	}
	out, err = runInstalledWrap(t, wrap, work, nil, "status")
	if err == nil || strings.Contains(out, configDenied) {
		t.Fatalf("non-repo status: %v\n%s", err, out)
	}
}

func stringListHas(keys []string, want string) bool {
	for _, key := range keys {
		if key == want {
			return true
		}
	}
	return false
}

func TestGitWrapR4CoreWorktreeOutsideRefused(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("SECRETOUT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	configDenied := "configuration is not allowed"
	refuseAndUntouched := func(dir string, args ...string) {
		t.Helper()
		out, err := runInstalledWrap(t, wrap, dir, nil, args...)
		if err == nil || !strings.Contains(out, configDenied) {
			t.Fatalf("%s %v: %v\n%s", dir, args, err, out)
		}
		body, readErr := os.ReadFile(secret)
		if readErr != nil || string(body) != "SECRETOUT\n" {
			t.Fatalf("outside file changed: %q %v\n%s", body, readErr, out)
		}
		if treeHas(t, dir, "SECRETOUT") {
			t.Fatalf("outside content reached the workspace\n%s", out)
		}
	}

	absRepo := filepath.Join(work, "abs")
	commitRepo(t, absRepo, "a.txt", "abs\n")
	gitCmd(t, absRepo, "config", "core.worktree", outside)
	refuseAndUntouched(absRepo, "status")
	refuseAndUntouched(absRepo, "fetch")

	relRepo := filepath.Join(work, "rel")
	commitRepo(t, relRepo, "r.txt", "rel\n")
	rel, err := filepath.Rel(filepath.Join(relRepo, ".git"), outside)
	if err != nil {
		t.Fatal(err)
	}
	gitCmd(t, relRepo, "config", "core.worktree", rel)
	refuseAndUntouched(relRepo, "status")
	refuseAndUntouched(relRepo, "fetch")

	// An absolute value must not be resolved against the git directory: a
	// look-alike directory under .git must not make an outside path pass.
	shadowRepo := filepath.Join(work, "shadow")
	commitRepo(t, shadowRepo, "h.txt", "shadow\n")
	if err := os.MkdirAll(filepath.Join(shadowRepo, ".git", outside), 0o755); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, shadowRepo, "config", "core.worktree", outside)
	refuseAndUntouched(shadowRepo, "status")

	subsrc := filepath.Join(work, "subsrc")
	commitRepo(t, subsrc, "s.txt", "s\n")
	parent := filepath.Join(work, "parent")
	commitRepo(t, parent, "p.txt", "p\n")
	gitCmd(t, parent, "-c", "protocol.file.allow=always", "submodule", "add", "file://"+subsrc, "sub")
	sub := filepath.Join(parent, "sub")
	out, err := runInstalledWrap(t, wrap, sub, nil, "status")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("submodule status: %v\n%s", err, out)
	}
	out, err = runInstalledWrap(t, wrap, parent, nil, "status")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("parent status: %v\n%s", err, out)
	}
	// A submodule git directory whose worktree value points outside is refused.
	modCfg := filepath.Join(parent, ".git", "modules", "sub")
	modRel, err := filepath.Rel(modCfg, outside)
	if err != nil {
		t.Fatal(err)
	}
	gitCmd(t, modCfg, "config", "--file", filepath.Join(modCfg, "config"), "core.worktree", modRel)
	refuseAndUntouched(sub, "status")
}

func TestGitWrapR4PromisorLazyFetchRefused(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	if !strings.Contains(script, "export GIT_NO_LAZY_FETCH=1") {
		t.Fatal("GIT_NO_LAZY_FETCH is not exported")
	}
	if strings.Contains(script, "remote.*.promisor") || strings.Contains(script, "partialclonefilter") {
		t.Fatal("promisor keys are still on the allowlist")
	}
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	outside := t.TempDir()
	outsideSHA := commitRepo(t, outside, "secret.txt", "SECRETOUT\n")
	ok := filepath.Join(work, "ok")
	if err := os.WriteFile(ok, []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "repo\n")
	gitCmd(t, repo, "config", "remote.p.url", "file://"+outside)
	gitCmd(t, repo, "config", "remote.p.promisor", "true")
	gitCmd(t, repo, "config", "remote.p.partialclonefilter", "blob:none")
	wrap := installGitWrap(t, work)
	repoGit := filepath.Join(repo, ".git")
	hasNoFetch := func() bool {
		t.Helper()
		cmd := exec.Command("git", "--git-dir", repoGit, "cat-file", "-e", outsideSHA)
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + repoGit,
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_TERMINAL_PROMPT=0",
			"GIT_NO_LAZY_FETCH=1",
		}
		return cmd.Run() == nil
	}
	if hasNoFetch() {
		t.Fatal("workspace already had the outside object")
	}
	out, err := runInstalledWrap(t, wrap, repo, nil, "show", outsideSHA, "--", "file://"+ok)
	if err == nil || !strings.Contains(out, "configuration is not allowed") {
		t.Fatalf("armed show: %v\n%s", err, out)
	}
	if !strings.Contains(out, "remote.p.promisor") {
		t.Fatalf("denial did not name the key: %s", out)
	}
	if hasNoFetch() {
		t.Fatal("outside object arrived in the workspace")
	}
	if treeHas(t, filepath.Join(repo, ".git"), "SECRETOUT") {
		t.Fatal("outside content reached the workspace")
	}
}

func TestGitWrapR4ConfigExemptionConfined(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	if !strings.Contains(script, "config_guard()") {
		t.Fatal("config_guard is missing")
	}
	if !strings.Contains(script, "config_key_allowed()") {
		t.Fatal("config_key_allowed is missing")
	}
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	wrap := installGitWrap(t, work)
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "f.txt", "f\n")
	inside := filepath.Join(work, "inside")
	commitRepo(t, inside, "i.txt", "i\n")
	gitCmd(t, repo, "remote", "add", "origin", "file://"+inside)
	foreign := filepath.Join(t.TempDir(), "x")
	optionDenied := "option is not allowed"
	configDenied := "configuration is not allowed"
	refuseOption := func(args ...string) {
		t.Helper()
		out, err := runInstalledWrap(t, wrap, repo, nil, args...)
		if err == nil || !strings.Contains(out, optionDenied) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	refuseOption("config", "--file", foreign, "a.b", "c")
	refuseOption("config", "-f", foreign, "--list")
	refuseOption("config", "-f"+foreign, "--list")
	refuseOption("config", "--fi", foreign, "--list")
	refuseOption("config", "--fil", foreign, "--list")
	refuseOption("config", "--global", "--list")
	refuseOption("config", "--gl", "--list")
	refuseOption("config", "--system", "--list")
	refuseOption("config", "--sys", "--list")
	refuseOption("config", "--blob", "HEAD:x")
	refuseOption("config", "--blob=HEAD:x")
	refuseOption("config", "--bl", "HEAD:x")
	refuseOption("config", "-e")
	refuseOption("config", "--edit")
	refuseOption("config", "--ed")
	refuseWrite := func(key string, args ...string) {
		t.Helper()
		out, err := runInstalledWrap(t, wrap, repo, nil, args...)
		if err == nil || !strings.Contains(out, configDenied) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if !strings.Contains(out, key) {
			t.Fatalf("%v did not name %s\n%s", args, key, out)
		}
		if _, ok := gitLocalGet(repo, key); ok {
			t.Fatalf("%v wrote %s", args, key)
		}
	}
	refuseWrite("alias.x", "config", "--add", "alias.x", "y")
	refuseWrite("core.hooksPath", "config", "--replace-all", "core.hooksPath", "/x")
	refuseWrite("core.sshCommand", "config", "core.sshCommand", "x")
	if hostGitAtLeast(t, 2, 46) {
		refuseWrite("core.fsmonitor", "config", "set", "core.fsmonitor", "x")
		refuseWrite("include.path", "config", "add", "include.path", "x")
	}

	gitCmd(t, repo, "config", "alias.x", "status")
	out, err := runInstalledWrap(t, wrap, repo, nil, "config", "--unset-all", "alias.x")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("unset-all alias.x: %v\n%s", err, out)
	}
	if _, ok := gitLocalGet(repo, "alias.x"); ok {
		t.Fatal("alias.x still set")
	}
	gitCmd(t, repo, "config", "alias.x", "status")
	out, err = runInstalledWrap(t, wrap, repo, nil, "config", "--remove-section", "alias")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("remove-section alias: %v\n%s", err, out)
	}
	gitCmd(t, repo, "config", "core.hooksPath", "/x")
	out, err = runInstalledWrap(t, wrap, repo, nil, "config", "--unset", "core.hooksPath")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("unset core.hooksPath: %v\n%s", err, out)
	}
	gitCmd(t, repo, "config", "core.fsmonitor", "/x")
	gitCmd(t, repo, "config", "url.x.insteadOf", "y")
	if hostGitAtLeast(t, 2, 46) {
		out, err = runInstalledWrap(t, wrap, repo, nil, "config", "unset", "core.fsmonitor")
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("config unset core.fsmonitor: %v\n%s", err, out)
		}
		out, err = runInstalledWrap(t, wrap, repo, nil, "config", "remove-section", "url.x")
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("config remove-section url.x: %v\n%s", err, out)
		}
	} else {
		out, err = runInstalledWrap(t, wrap, repo, nil, "config", "--unset", "core.fsmonitor")
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("unset core.fsmonitor: %v\n%s", err, out)
		}
		out, err = runInstalledWrap(t, wrap, repo, nil, "config", "--remove-section", "url.x")
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("remove-section url.x: %v\n%s", err, out)
		}
	}

	out, err = runInstalledWrap(t, wrap, repo, nil, "config", "user.name", "x")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("config user.name: %v\n%s", err, out)
	}
	if got, ok := gitLocalGet(repo, "user.name"); !ok || got != "x" {
		t.Fatalf("user.name not written: %q %v", got, ok)
	}
	out, err = runInstalledWrap(t, wrap, repo, nil, "config", "pull.rebase", "true")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("config pull.rebase: %v\n%s", err, out)
	}
	if got, ok := gitLocalGet(repo, "pull.rebase"); !ok || got != "true" {
		t.Fatalf("pull.rebase not written: %q %v", got, ok)
	}
	out, err = runInstalledWrap(t, wrap, repo, nil, "config", "--get", "remote.origin.url")
	if err != nil || !strings.Contains(out, "file://") {
		t.Fatalf("config --get: %v\n%s", err, out)
	}
	out, err = runInstalledWrap(t, wrap, repo, nil, "config", "--list")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("config --list: %v\n%s", err, out)
	}
	if hostGitAtLeast(t, 2, 46) {
		out, err = runInstalledWrap(t, wrap, repo, nil, "config", "get", "remote.origin.url")
		if err != nil || !strings.Contains(out, "file://") {
			t.Fatalf("config get: %v\n%s", err, out)
		}
		out, err = runInstalledWrap(t, wrap, repo, nil, "config", "list")
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("config list: %v\n%s", err, out)
		}
		out, err = runInstalledWrap(t, wrap, repo, nil, "config", "set", "user.email", "x@x")
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("config set user.email: %v\n%s", err, out)
		}
	}
	out, err = runInstalledWrap(t, wrap, repo, nil, "status")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("status after config: %v\n%s", err, out)
	}
}

func TestGitWrapR4FetchUpdateHeadVetsURL(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	if strings.Contains(script, "-u) prev=skip") {
		t.Fatal("fetch -u still skips the next word")
	}
	head := script
	if i := strings.Index(script, "sub="); i >= 0 {
		head = script[i:]
		if j := strings.Index(head, "GHPORT="); j >= 0 {
			head = head[:j]
		}
	}
	if strings.Contains(head, "-u") && strings.Contains(head, "prev=") && strings.Contains(head, "-u)") {
		t.Fatal("first scan loop skips a value after -u")
	}
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	inside := filepath.Join(work, "inside")
	insideSHA := commitRepo(t, inside, "i.txt", "inside\n")
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "repo\n")
	gitCmd(t, repo, "remote", "add", "origin", "file://"+inside)
	wrap := installGitWrap(t, work)
	outside := t.TempDir()
	out, err := runWrapTimeout(t, wrap, repo, nil, 15*time.Second, "fetch", "-u", "https://github.com/someone/else.git")
	if err == nil || !strings.Contains(out, RepoNotAvailable) {
		t.Fatalf("fetch -u https: %v\n%s", err, out)
	}
	out, err = runInstalledWrap(t, wrap, repo, nil, "fetch", "-u", outside)
	if err == nil || !(strings.Contains(out, "local path is outside the workspace") || strings.Contains(out, RepoNotAvailable)) {
		t.Fatalf("fetch -u outside: %v\n%s", err, out)
	}
	out, err = runInstalledWrap(t, wrap, repo, nil, "fetch", "-u", "origin")
	if err != nil || strings.Contains(out, RepoNotAvailable) {
		t.Fatalf("fetch -u origin: %v\n%s", err, out)
	}
	if !gitHasObject(filepath.Join(repo, ".git"), insideSHA) {
		t.Fatal("fetch -u origin did not store the workspace commit")
	}
}

func TestGitWrapR4CommonKeysStayAllowed(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	wrap := installGitWrap(t, work)
	configDenied := "configuration is not allowed"
	dir := filepath.Join(work, "allowed")
	commitRepo(t, dir, "f.txt", "f\n")
	for _, kv := range [][2]string{
		{"core.autocrlf", "true"},
		{"core.eol", "lf"},
		{"core.safecrlf", "warn"},
		{"core.whitespace", "trailing-space"},
		{"core.abbrev", "7"},
		{"core.quotepath", "false"},
		{"core.longpaths", "true"},
		{"core.untrackedCache", "true"},
		{"pull.rebase", "true"},
		{"pull.ff", "true"},
		{"init.defaultBranch", "main"},
		{"push.default", "simple"},
		{"push.autoSetupRemote", "true"},
		{"push.followTags", "true"},
		{"fetch.prune", "true"},
		{"fetch.pruneTags", "true"},
		{"fetch.parallel", "1"},
		{"merge.ff", "true"},
		{"merge.conflictStyle", "diff3"},
		{"rebase.autoStash", "true"},
		{"rebase.autoSquash", "true"},
		{"status.showUntrackedFiles", "normal"},
		{"status.branch", "true"},
		{"status.short", "true"},
		{"log.date", "iso"},
		{"diff.algorithm", "histogram"},
		{"rerere.enabled", "true"},
		{"branch.autoSetupMerge", "true"},
		{"branch.autoSetupRebase", "always"},
		{"color.ui", "false"},
		{"color.status", "false"},
		{"advice.detachedHead", "false"},
		{"gc.auto", "0"},
		{"tag.sort", "version:refname"},
		{"help.autocorrect", "never"},
		{"commit.gpgsign", "false"},
		{"pack.threads", "1"},
	} {
		gitCmd(t, dir, "config", kv[0], kv[1])
	}
	out, err := runInstalledWrap(t, wrap, dir, nil, "status")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("allowed keys status: %v\n%s", err, out)
	}
	out, err = runInstalledWrap(t, wrap, dir, nil, "log", "-1")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("allowed keys log: %v\n%s", err, out)
	}

	for _, kv := range [][2]string{
		{"core.fsmonitor", "/x"},
		{"core.hooksPath", "/x"},
		{"core.pager", "/x"},
		{"core.editor", "/x"},
		{"core.sshCommand", "/x"},
		{"core.excludesFile", "/x"},
		{"core.attributesFile", "/x"},
		{"filter.x.clean", "/x"},
		{"merge.x.driver", "/x"},
		{"diff.x.textconv", "/x"},
		{"credential.helper", "/x"},
		{"http.proxy", "http://127.0.0.1:9"},
		{"url.x.insteadOf", "y"},
		{"alias.x", "status"},
		{"include.path", "/x"},
		{"includeIf.onbranch:main.path", "/x"},
		{"diff.external", "/x"},
		{"pager.log", "/x"},
		{"sequence.editor", "/x"},
		{"gpg.program", "/x"},
		{"safe.directory", "/x"},
		{"protocol.file.allow", "always"},
		{"submodule.recurse", "true"},
		{"fetch.recurseSubmodules", "true"},
		{"extensions.partialclone", "origin"},
		{"merge.tool", "vimdiff"},
		{"mergetool.x.path", "/x"},
		{"difftool.x.cmd", "/x"},
		{"user.signingkey", "abc"},
		{"commit.template", "/x"},
		{"format.pretty", "fuller"},
		{"help.autocorrect", "1"},
		{"commit.gpgsign", "true"},
		{"tag.gpgsign", "true"},
	} {
		t.Run("deny-"+kv[0], func(t *testing.T) {
			d := filepath.Join(work, "deny-"+strings.ReplaceAll(kv[0], ".", "-"))
			commitRepo(t, d, "f.txt", "f\n")
			gitCmd(t, d, "config", kv[0], kv[1])
			out, err := runInstalledWrap(t, wrap, d, nil, "status")
			if err == nil || !strings.Contains(out, configDenied) {
				t.Fatalf("%s: %v\n%s", kv[0], err, out)
			}
		})
	}

	sparse := filepath.Join(work, "sparse-cone")
	commitRepo(t, sparse, "s.txt", "s\n")
	gitCmd(t, sparse, "sparse-checkout", "init", "--cone")
	gitCmd(t, sparse, "config", "index.sparse", "true")
	out, err = runInstalledWrap(t, wrap, sparse, nil, "status")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("sparse-checkout init cone: %v\n%s", err, out)
	}
}

func TestGitWrapR4DenialNamesKey(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	if !strings.Contains(script, "say_config_key()") {
		t.Fatal("say_config_key is missing")
	}
	text := runGitWrap(t, script, "-c", "alias.x\nhostile=/secret/path", "status")
	if !strings.Contains(text, "configuration is not allowed:") {
		t.Fatalf("missing key prefix: %s", text)
	}
	if strings.Contains(text, "\nhostile") || strings.Contains(text, "/secret/path") {
		t.Fatalf("message kept control characters or a path: %s", text)
	}
	if strings.Contains(text, string(rune(10))+"hostile") {
		t.Fatalf("message kept a newline in the key: %s", text)
	}
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "f.txt", "f\n")
	gitCmd(t, repo, "config", "alias.x", "!/tmp/secret-helper")
	wrap := installGitWrap(t, work)
	out, err := runInstalledWrap(t, wrap, repo, nil, "status")
	if err == nil || !strings.Contains(out, "configuration is not allowed: alias.x") {
		t.Fatalf("alias.x: %v\n%s", err, out)
	}
	if strings.Contains(out, "/tmp/secret-helper") || strings.Contains(out, work) {
		t.Fatalf("message named a path: %s", out)
	}
}

func TestGitWrapR4AttrSourceRefused(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	optionDenied := "option is not allowed"
	for _, args := range [][]string{
		{"--attr-source", "HEAD", "status"},
		{"--attr-source=HEAD", "status"},
		{"status", "--attr-source", "HEAD"},
		{"status", "--attr-source=HEAD"},
	} {
		text := runGitWrap(t, script, args...)
		if !strings.Contains(text, optionDenied) {
			t.Fatalf("%v: %s", args, text)
		}
	}
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "f.txt", "f\n")
	wrap := installGitWrap(t, work)
	out, err := runInstalledWrap(t, wrap, repo, nil, "status")
	if err != nil || strings.Contains(out, optionDenied) {
		t.Fatalf("status: %v\n%s", err, out)
	}
}

func TestGitWrapR4EditorEnvUnset(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	if !strings.Contains(script, "unset GIT_EDITOR VISUAL EDITOR GIT_SEQUENCE_EDITOR") {
		t.Fatal("editor variables are not unset")
	}
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "f.txt", "f\n")
	marker := filepath.Join(work, "editor-ran")
	editor := filepath.Join(work, "editor.sh")
	writeMarkerHook(t, editor, marker)
	dump := filepath.Join(work, "env.dump")
	real, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	real, err = filepath.Abs(real)
	if err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(work, "real-git")
	body := "#!/bin/sh\nenv > '" + dump + "'\nexec '" + real + "' \"$@\"\n"
	if err := os.WriteFile(fake, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrapReal(t, work, fake, gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	extra := []string{
		"GIT_EDITOR=" + editor,
		"VISUAL=" + editor,
		"EDITOR=" + editor,
		"GIT_SEQUENCE_EDITOR=" + editor,
	}
	out, err := runInstalledWrap(t, wrap, repo, extra, "config", "-e")
	if err == nil || !strings.Contains(out, "option is not allowed") {
		t.Fatalf("config -e: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("config -e ran the editor\n%s", out)
	}
	out, err = runInstalledWrap(t, wrap, repo, extra, "status")
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	dumpBody, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	envText := string(dumpBody)
	for _, name := range []string{"GIT_EDITOR=", "VISUAL=", "EDITOR=", "GIT_SEQUENCE_EDITOR="} {
		if strings.Contains(envText, name) {
			t.Fatalf("real git still saw %s\n%s", name, envText)
		}
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatal("editor marker was created")
	}
}

func TestGitWrapR4RemoteVetsEveryURLWord(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	inside := filepath.Join(work, "inside")
	commitRepo(t, inside, "i.txt", "inside\n")
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "repo\n")
	gitCmd(t, repo, "remote", "add", "origin", "file://"+inside)
	gitCmd(t, repo, "remote", "add", "e", "file://"+inside)
	outside := t.TempDir()
	wrap := installGitWrapWith(t, work, gitWrapOpts{
		Grant: true, Name: "Ada", Email: "bot@localhost",
		Repos: []string{"acme/widgets"},
	})
	deniedRepo := RepoNotAvailable
	outsidePath := "local path is outside the workspace"
	refuse := func(args ...string) {
		t.Helper()
		out, err := runInstalledWrap(t, wrap, repo, nil, args...)
		if err == nil {
			t.Fatalf("allowed %v\n%s", args, out)
		}
		if !strings.Contains(out, deniedRepo) && !strings.Contains(out, outsidePath) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	// A named remote whose url points outside is refused wherever it appears.
	outRepo := filepath.Join(outside, "o")
	commitRepo(t, outRepo, "o.txt", "outside\n")
	gitCmd(t, repo, "remote", "add", "eo", "file://"+outRepo)
	refuse("remote", "prune", "file://"+inside, "eo")
	refuse("remote", "prune", "origin", "eo")
	refuse("remote", "prune", "eo", "origin")
	refuse("remote", "show", "origin", "eo")
	refuse("remote", "update", "origin", "eo")
	refuse("remote", "prune", "file://"+outside+"/x", "e")
	refuse("remote", "prune", "e", "file://"+outside+"/x")
	refuse("remote", "add", "n", "https://github.com/someone/else.git")
	refuse("remote", "set-url", "n", outside)
	out, err := runInstalledWrap(t, wrap, repo, nil, "remote", "-v")
	if err != nil {
		t.Fatalf("remote -v: %v\n%s", err, out)
	}
	out, err = runInstalledWrap(t, wrap, repo, nil, "remote", "prune", "origin")
	if err != nil {
		t.Fatalf("remote prune origin: %v\n%s", err, out)
	}
	out, err = runInstalledWrap(t, wrap, repo, nil, "remote", "add", "listed", "https://github.com/acme/widgets.git")
	if err != nil || strings.Contains(out, deniedRepo) {
		t.Fatalf("remote add listed: %v\n%s", err, out)
	}
}

func TestGitWrapR5CoreWorktreeSymlinkDotDot(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	phys := filepath.Join(base, "wt")
	for _, dir := range []string{work, outside, phys} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(phys, "secret.txt")
	if err := os.WriteFile(secret, []byte("SECRETOUT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	configDenied := "configuration is not allowed"
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		return runInstalledWrap(t, wrap, dir, []string{"GIT_TERMINAL_PROMPT=0"}, args...)
	}
	refuse := func(dir string, args ...string) {
		t.Helper()
		out, err := run(dir, args...)
		if err == nil || !strings.Contains(out, configDenied) || !strings.Contains(out, "core.worktree") {
			t.Fatalf("%s %v: %v\n%s", dir, args, err, out)
		}
		body, readErr := os.ReadFile(secret)
		if readErr != nil || string(body) != "SECRETOUT\n" {
			t.Fatalf("outside file changed: %q %v", body, readErr)
		}
		if treeHas(t, dir, "SECRETOUT") {
			t.Fatalf("outside content reached the workspace\n%s", out)
		}
	}

	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "a.txt", "a\n")
	if err := os.MkdirAll(filepath.Join(repo, "wt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(repo, "lnd")); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "config", "core.worktree", "../lnd/../wt")
	refuse(repo, "status")
	refuse(repo, "add", "a.txt")

	inner := filepath.Join(work, "inner-repo")
	commitRepo(t, inner, "i.txt", "i\n")
	if err := os.MkdirAll(filepath.Join(inner, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, inner, "config", "core.worktree", "../inner")
	out, err := run(inner, "status")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("relative worktree: %v\n%s", err, out)
	}

	linked := filepath.Join(work, "linked")
	commitRepo(t, linked, "l.txt", "l\n")
	if err := os.Rename(filepath.Join(linked, ".git"), filepath.Join(linked, "gitdir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("gitdir", filepath.Join(linked, ".git")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(linked, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, linked, "config", "core.worktree", "../inner")
	out, err = run(linked, "status")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("symlink gitdir: %v\n%s", err, out)
	}

	gf := filepath.Join(work, "gf")
	gfGit := filepath.Join(work, "gf.git")
	gitCmd(t, work, "init", "-b", "main", "--separate-git-dir", gfGit, gf)
	if err := os.MkdirAll(filepath.Join(gf, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, work, "config", "--file", filepath.Join(gfGit, "config"), "core.worktree", "../gf/inner")
	out, err = run(gf, "status")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("gitfile gitdir: %v\n%s", err, out)
	}

	t.Run("worktree-config", func(t *testing.T) {
		dir := filepath.Join(work, "wtcfg")
		commitRepo(t, dir, "w.txt", "w\n")
		if err := os.MkdirAll(filepath.Join(dir, "wt"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, "lnd")); err != nil {
			t.Fatal(err)
		}
		gitCmd(t, dir, "config", "extensions.worktreeConfig", "true")
		gitCmd(t, dir, "config", "--worktree", "core.worktree", "../lnd/../wt")
		refuse(dir, "status")
	})
}

func TestGitWrapR5BranchRemotePlainName(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(work, "inside")
	commitRepo(t, inside, "i.txt", "inside\n")
	wrap := installGitWrap(t, work)
	configDenied := "configuration is not allowed"
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		return runInstalledWrap(t, wrap, dir, []string{"GIT_TERMINAL_PROMPT=0"}, args...)
	}
	badValues := []string{
		"file:///outside/x",
		"/tmp/outside",
		"https://github.com/someone/else.git",
		"git@host:x.git",
	}
	for _, key := range []string{"branch.main.remote", "branch.main.pushremote"} {
		for _, val := range badValues {
			dir := filepath.Join(work, "bad-"+strings.ReplaceAll(key, ".", "-")+"-"+strconv.Itoa(len(val)))
			commitRepo(t, dir, "f.txt", "f\n")
			gitCmd(t, dir, "config", key, val)
			out, err := run(dir, "status")
			if err == nil || !strings.Contains(out, configDenied) || !strings.Contains(out, key) {
				t.Fatalf("status %s=%s: %v\n%s", key, val, err, out)
			}
		}
	}

	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "r\n")
	out, err := run(repo, "config", "branch.main.remote", "origin")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("write origin: %v\n%s", err, out)
	}
	if got, ok := gitLocalGet(repo, "branch.main.remote"); !ok || got != "origin" {
		t.Fatalf("branch.main.remote=%q ok=%v", got, ok)
	}
	out, err = run(repo, "config", "branch.main.pushremote", "origin")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("write pushremote: %v\n%s", err, out)
	}
	out, err = run(repo, "config", "branch.main.merge", "refs/heads/main")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("write merge: %v\n%s", err, out)
	}
	for _, val := range badValues {
		out, err = run(repo, "config", "branch.main.remote", val)
		if err == nil || !strings.Contains(out, configDenied) || !strings.Contains(out, "branch.main.remote") {
			t.Fatalf("write %s: %v\n%s", val, err, out)
		}
		if got, ok := gitLocalGet(repo, "branch.main.remote"); !ok || got != "origin" {
			t.Fatalf("value changed to %q after %s", got, val)
		}
	}
	out, err = run(repo, "status")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("status after plain name: %v\n%s", err, out)
	}

	out, err = run(repo, "remote", "add", "origin", "file://"+inside)
	if err != nil {
		t.Fatalf("remote add: %v\n%s", err, out)
	}
	out, err = run(repo, "fetch", "origin")
	if err != nil {
		t.Fatalf("fetch origin: %v\n%s", err, out)
	}
	out, err = run(repo, "checkout", "-b", "side")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("checkout -b: %v\n%s", err, out)
	}
	out, err = run(repo, "branch", "--set-upstream-to=origin/main")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("set-upstream: %v\n%s", err, out)
	}
	if got, ok := gitLocalGet(repo, "branch.side.remote"); !ok || got != "origin" {
		t.Fatalf("branch.side.remote=%q ok=%v", got, ok)
	}
	out, err = run(repo, "status")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("status after upstream: %v\n%s", err, out)
	}
}

func TestGitWrapR5NoArmFromOptionValue(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("SECRETOUT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(work, "inside")
	commitRepo(t, inside, "i.txt", "inside\n")
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "repo\n")
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
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + logPath + "'\nexec '" + real + "' \"$@\"\n"
	if err := os.WriteFile(fake, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrapReal(t, work, fake, gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	resetLog := func() {
		t.Helper()
		if err := os.WriteFile(logPath, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	logText := func() string {
		t.Helper()
		b, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		return runInstalledWrap(t, wrap, dir, []string{"GIT_TERMINAL_PROMPT=0"}, args...)
	}

	resetLog()
	out, err := run(repo, "fetch", "file://"+inside)
	if err != nil {
		t.Fatalf("fetch file: %v\n%s", err, out)
	}
	if !strings.Contains(logText(), "protocol.file.allow=user") {
		t.Fatalf("positional file URL did not arm\n%s", logText())
	}

	bare := filepath.Join(work, "bare-remote")
	commitRepo(t, bare, "b.txt", "b\n")
	resetLog()
	out, err = run(bare, "fetch", "-o", "file://"+inside)
	if strings.Contains(logText(), "protocol.file.allow=user") {
		t.Fatalf("option value armed file\n%s\n%s", out, logText())
	}
	if !strings.Contains(logText(), "protocol.file.allow=never") {
		t.Fatalf("option value did not keep file off\n%s\n%s", out, logText())
	}

	resetLog()
	out, err = run(bare, "fetch", "-o", "file://"+outside+"/x")
	if err == nil || !strings.Contains(out, "local path is outside the workspace") {
		t.Fatalf("fetch -o outside: %v\n%s", err, out)
	}
	if strings.Contains(logText(), "protocol.file.allow=user") {
		t.Fatalf("outside option armed file\n%s", logText())
	}
	bodyOut, readErr := os.ReadFile(secret)
	if readErr != nil || string(bodyOut) != "SECRETOUT\n" {
		t.Fatalf("outside file changed: %q %v", bodyOut, readErr)
	}
	if treeHas(t, bare, "SECRETOUT") {
		t.Fatal("outside content reached the workspace")
	}

	resetLog()
	cloneDest := filepath.Join(work, "cloned")
	out, err = run(work, "clone", "file://"+inside, cloneDest)
	if err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	if !strings.Contains(logText(), "protocol.file.allow=user") {
		t.Fatalf("clone did not arm\n%s", logText())
	}

	resetLog()
	out, err = run(work, "ls-remote", "file://"+inside)
	if err != nil || !strings.Contains(out, "refs/heads/main") {
		t.Fatalf("ls-remote: %v\n%s", err, out)
	}
	if !strings.Contains(logText(), "protocol.file.allow=user") {
		t.Fatalf("ls-remote did not arm\n%s", logText())
	}

	resetLog()
	out, err = run(repo, "remote", "add", "-f", "n", "file://"+inside)
	if err != nil {
		t.Fatalf("remote add -f: %v\n%s", err, out)
	}
	if !strings.Contains(logText(), "protocol.file.allow=user") {
		t.Fatalf("remote add -f did not arm\n%s", logText())
	}

	subRepo := filepath.Join(work, "super")
	commitRepo(t, subRepo, "s.txt", "s\n")
	resetLog()
	out, err = run(subRepo, "submodule", "add", "file://"+inside, "p")
	if err != nil {
		t.Fatalf("submodule add: %v\n%s", err, out)
	}
	if !strings.Contains(logText(), "protocol.file.allow=user") {
		t.Fatalf("submodule add did not arm\n%s", logText())
	}

	pulled := filepath.Join(work, "pulled")
	gitCmd(t, work, "-c", "protocol.file.allow=always", "clone", "file://"+inside, pulled)
	if err := os.WriteFile(filepath.Join(inside, "more.txt"), []byte("more\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, inside, "add", "--", "more.txt")
	gitCmd(t, inside, "commit", "-m", "more")
	resetLog()
	out, err = run(pulled, "pull", "file://"+inside, "main")
	if err != nil {
		t.Fatalf("pull: %v\n%s", err, out)
	}
	if !strings.Contains(logText(), "protocol.file.allow=user") {
		t.Fatalf("pull did not arm\n%s", logText())
	}
}

func TestGitWrapR5NoArgFetchResolvesBranchRemote(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("SECRETOUT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok := filepath.Join(work, "ok")
	commitRepo(t, ok, "o.txt", "ok\n")
	inside := filepath.Join(work, "inside")
	insideSHA := commitRepo(t, inside, "i.txt", "inside\n")
	wrap := installGitWrap(t, work)
	runT := func(dir string, args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, dir, nil, 15*time.Second, args...)
	}
	refused := func(dir string, args ...string) {
		t.Helper()
		out, err := runT(dir, args...)
		if err == nil {
			t.Fatalf("allowed %s %v\n%s", dir, args, out)
		}
		if treeHas(t, dir, "SECRETOUT") {
			t.Fatalf("outside content reached %s\n%s", dir, out)
		}
	}
	for _, val := range []string{
		"file://" + outside + "/x",
		"/tmp/outside",
		"https://github.com/someone/else.git",
	} {
		dir := filepath.Join(work, "v"+strconv.Itoa(len(val)))
		commitRepo(t, dir, "f.txt", "f\n")
		gitCmd(t, dir, "config", "branch.main.remote", val)
		gitCmd(t, dir, "config", "branch.main.merge", "refs/heads/main")
		refused(dir, "fetch")
		refused(dir, "pull")
		refused(dir, "ls-remote")
		refused(dir, "fetch", "-o", "file://"+ok)
	}
	body, err := os.ReadFile(secret)
	if err != nil || string(body) != "SECRETOUT\n" {
		t.Fatalf("outside file changed: %q %v", body, err)
	}

	good := filepath.Join(work, "good")
	commitRepo(t, good, "g.txt", "g\n")
	gitCmd(t, good, "remote", "add", "origin", "file://"+inside)
	gitCmd(t, good, "config", "branch.main.remote", "origin")
	gitCmd(t, good, "config", "branch.main.merge", "refs/heads/main")
	out, err := runT(good, "fetch")
	if err != nil {
		t.Fatalf("fetch origin: %v\n%s", err, out)
	}
	if !gitHasObject(filepath.Join(good, ".git"), insideSHA) {
		t.Fatal("no-arg fetch did not store the workspace commit")
	}
	out, err = runT(good, "ls-remote")
	if err != nil || !strings.Contains(out, insideSHA) {
		t.Fatalf("ls-remote origin: %v\n%s", err, out)
	}

	bad := filepath.Join(work, "bad-origin")
	commitRepo(t, bad, "b.txt", "b\n")
	gitCmd(t, bad, "remote", "add", "origin", "https://github.com/someone/else.git")
	gitCmd(t, bad, "config", "branch.main.remote", "origin")
	gitCmd(t, bad, "config", "branch.main.merge", "refs/heads/main")
	out, err = runT(bad, "ls-remote")
	if err == nil || !strings.Contains(out, RepoNotAvailable) {
		t.Fatalf("ls-remote branch remote: %v\n%s", err, out)
	}
	out, err = runT(bad, "push")
	if err == nil || !strings.Contains(out, RepoNotAvailable) {
		t.Fatalf("push branch remote: %v\n%s", err, out)
	}

	// a push-only branch remote is vetted like the branch remote
	pr := filepath.Join(work, "pushremote")
	commitRepo(t, pr, "p.txt", "p\n")
	gitCmd(t, pr, "remote", "add", "origin", "file://"+inside)
	gitCmd(t, pr, "remote", "add", "evil", "https://github.com/someone/else.git")
	gitCmd(t, pr, "config", "branch.main.pushremote", "evil")
	out, err = runT(pr, "push")
	if err == nil || !strings.Contains(out, RepoNotAvailable) {
		t.Fatalf("push pushremote: %v\n%s", err, out)
	}
}

func TestGitWrapR5ConfigAbbrevOptions(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	wrap := installGitWrap(t, work)
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "f.txt", "f\n")
	optionDenied := "option is not allowed"
	refuse := func(args ...string) {
		t.Helper()
		out, err := runInstalledWrap(t, wrap, repo, []string{"GIT_TERMINAL_PROMPT=0"}, args...)
		if err == nil || !strings.Contains(out, optionDenied) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	absent := func(key string) {
		t.Helper()
		if got, ok := gitLocalGet(repo, key); ok {
			t.Fatalf("%s was written: %s", key, got)
		}
	}
	refuse("config", "--comm", "core.autocrlf", "core.hooksPath", "/dev/null")
	absent("core.hooksPath")
	absent("core.autocrlf")
	refuse("config", "--typ", "bool", "pull.ff", "true")
	absent("pull.ff")
	refuse("config", "--def", "x", "pull.rebase", "true")
	absent("pull.rebase")
	refuse("config", "--val", "x", "pull.rebase", "true")
	absent("pull.rebase")
	refuse("config", "--ur", "x", "pull.rebase", "true")
	absent("pull.rebase")
	if hostGitAtLeast(t, 2, 46) {
		refuse("config", "set", "--comm", "hi", "core.sshCommand", "/bin/false")
		absent("core.sshCommand")
	}
	out, err := runInstalledWrap(t, wrap, repo, []string{"GIT_TERMINAL_PROMPT=0"}, "config", "--type=bool", "pull.rebase", "true")
	if err != nil || strings.Contains(out, optionDenied) {
		t.Fatalf("exact --type: %v\n%s", err, out)
	}
	if got, ok := gitLocalGet(repo, "pull.rebase"); !ok || got != "true" {
		t.Fatalf("pull.rebase=%q ok=%v", got, ok)
	}
}

func TestGitWrapR5ConfigUnsetWithBadWorktree(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "a.txt", "a\n")
	if err := os.MkdirAll(filepath.Join(repo, "wt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(repo, "lnd")); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(repo, ".git", "config")
	wrap := installGitWrap(t, work)
	configDenied := "configuration is not allowed"
	run := func(args ...string) (string, error) {
		t.Helper()
		return runInstalledWrap(t, wrap, repo, []string{"GIT_TERMINAL_PROMPT=0"}, args...)
	}
	setWorktree := func(val string) {
		t.Helper()
		gitCmd(t, work, "config", "--file", cfg, "core.worktree", val)
	}
	unsetAndStatus := func(args ...string) {
		t.Helper()
		out, err := run(args...)
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if got, ok := gitConfigFileGet(cfg, "core.worktree"); ok {
			t.Fatalf("%v left core.worktree=%s\n%s", args, got, out)
		}
		out, err = run("status")
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("status after %v: %v\n%s", args, err, out)
		}
	}

	setWorktree("../nope")
	out, err := run("config", "core.hooksPath", "/x")
	if err == nil || !strings.Contains(out, configDenied) || !strings.Contains(out, "core.hooksPath") {
		t.Fatalf("hooksPath write: %v\n%s", err, out)
	}
	if _, ok := gitConfigFileGet(cfg, "core.hooksPath"); ok {
		t.Fatal("core.hooksPath was written")
	}
	unsetAndStatus("config", "--unset", "core.worktree")

	setWorktree("../lnd/../wt")
	unsetAndStatus("config", "--unset-all", "core.worktree")

	setWorktree("../nope")
	unsetAndStatus("config", "--remove-section", "core")

	if hostGitAtLeast(t, 2, 46) {
		setWorktree("../nope")
		unsetAndStatus("config", "unset", "core.worktree")
		setWorktree("../lnd/../wt")
		unsetAndStatus("config", "remove-section", "core")
	}
}

func TestGitWrapR5LsRemoteOptionValues(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(work, "inside")
	insideSHA := commitRepo(t, inside, "i.txt", "inside\n")
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "repo\n")
	gitCmd(t, repo, "remote", "add", "origin", "file://"+inside)
	wrap := installGitWrap(t, work)
	refuse := func(want string, args ...string) {
		t.Helper()
		out, err := runWrapTimeout(t, wrap, repo, nil, 15*time.Second, args...)
		if err == nil || !strings.Contains(out, want) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	for _, sub := range []string{"ls-remote", "fetch"} {
		refuse("local path is outside the workspace", sub, "-o", "file://"+outside+"/x")
		refuse("local path is outside the workspace", sub, "-o", outside)
		refuse(RepoNotAvailable, sub, "-o", "https://github.com/someone/else.git")
		// attached short form and --server-option=VALUE are option values too
		refuse("local path is outside the workspace", sub, "-ofile://"+outside+"/x")
		refuse("local path is outside the workspace", sub, "-o"+outside)
		refuse(RepoNotAvailable, sub, "-ohttps://github.com/someone/else.git")
		refuse("local path is outside the workspace", sub, "--server-option="+outside)
		refuse(RepoNotAvailable, sub, "--server-option=https://github.com/someone/else.git")
	}
	out, err := runInstalledWrap(t, wrap, repo, []string{"GIT_TERMINAL_PROMPT=0"}, "ls-remote", "-o", "x", "origin")
	if err != nil || !strings.Contains(out, insideSHA) {
		t.Fatalf("ls-remote -o x origin: %v\n%s", err, out)
	}
	out, err = runInstalledWrap(t, wrap, repo, []string{"GIT_TERMINAL_PROMPT=0"}, "fetch", "-o", "x", "origin")
	if err != nil {
		t.Fatalf("fetch -o x origin: %v\n%s", err, out)
	}
	if !gitHasObject(filepath.Join(repo, ".git"), insideSHA) {
		t.Fatal("fetch -o x origin did not store the workspace commit")
	}
}

func TestGitWrapR5InitConfinedToWork(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	outsidePath := "local path is outside the workspace"
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		return runInstalledWrap(t, wrap, dir, []string{"GIT_TERMINAL_PROMPT=0"}, args...)
	}
	refuse := func(dir string, args ...string) {
		t.Helper()
		out, err := run(dir, args...)
		if err == nil || !strings.Contains(out, outsidePath) {
			t.Fatalf("%s %v: %v\n%s", dir, args, err, out)
		}
	}
	cwd := filepath.Join(work, "cwd")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := run(cwd, "init")
	if err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(cwd, ".git")); err != nil {
		t.Fatalf("init did not create .git: %v", err)
	}
	out, err = run(cwd, "init", "sub")
	if err != nil {
		t.Fatalf("init sub: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(cwd, "sub", ".git")); err != nil {
		t.Fatalf("init sub did not create .git: %v", err)
	}
	out, err = run(cwd, "init", "--shared", "shared-dest")
	if err != nil {
		t.Fatalf("init --shared: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(cwd, "shared-dest", ".git")); err != nil {
		t.Fatalf("init --shared did not create the directory: %v", err)
	}

	absOut := filepath.Join(base, "abs-out")
	refuse(cwd, "init", absOut)
	if _, err := os.Stat(absOut); !os.IsNotExist(err) {
		t.Fatalf("absolute init target exists: %v", err)
	}
	nested := filepath.Join(work, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	dotOut := filepath.Join(base, "dot-out")
	refuse(nested, "init", "../../../dot-out")
	if _, err := os.Stat(dotOut); !os.IsNotExist(err) {
		t.Fatalf("dotdot init target exists: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(work, "link")); err != nil {
		t.Fatal(err)
	}
	refuse(work, "init", "link")
	if _, err := os.Stat(filepath.Join(outside, ".git")); !os.IsNotExist(err) {
		t.Fatalf("symlink init wrote outside: %v", err)
	}

	sepOut := filepath.Join(base, "sep-out.git")
	refuse(work, "init", "--separate-git-dir", sepOut, filepath.Join(work, "sep-denied"))
	refuse(work, "init", "--separate-git-dir="+sepOut, filepath.Join(work, "sep-denied-eq"))
	if _, err := os.Stat(sepOut); !os.IsNotExist(err) {
		t.Fatalf("separate git dir exists: %v", err)
	}
	refuse(work, "init", "--template", outside, filepath.Join(work, "tmpl-denied"))
	if _, err := os.Stat(filepath.Join(work, "tmpl-denied")); !os.IsNotExist(err) {
		t.Fatalf("template init created a target: %v", err)
	}

	sepIn := filepath.Join(work, "sep.git")
	sepRepo := filepath.Join(work, "sep-repo")
	out, err = run(work, "init", "--separate-git-dir", sepIn, sepRepo)
	if err != nil {
		t.Fatalf("separate inside: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(sepIn, "HEAD")); err != nil {
		t.Fatalf("separate git dir missing: %v", err)
	}
	tmpl := filepath.Join(work, "tmpl")
	copyGitTemplates(t, tmpl)
	tmplRepo := filepath.Join(work, "tmpl-repo")
	out, err = run(work, "init", "--template", tmpl, tmplRepo)
	if err != nil {
		t.Fatalf("template inside: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(tmplRepo, ".git")); err != nil {
		t.Fatalf("template init missing .git: %v", err)
	}
	out, err = run(work, "init", "--template="+tmpl, filepath.Join(work, "tmpl-eq"))
	if err != nil {
		t.Fatalf("template equals: %v\n%s", err, out)
	}
}

func copyGitTemplates(t *testing.T, dst string) {
	t.Helper()
	candidates := []string{"/usr/share/git-core/templates"}
	if out, err := exec.Command("git", "--exec-path").Output(); err == nil {
		execPath := strings.TrimSpace(string(out))
		candidates = append([]string{
			filepath.Join(filepath.Dir(execPath), "share", "git-core", "templates"),
			filepath.Join(execPath, "templates"),
		}, candidates...)
	}
	var src string
	for _, cand := range candidates {
		st, err := os.Stat(cand)
		if err == nil && st.IsDir() {
			src = cand
			break
		}
	}
	if src == "" {
		t.Fatal("git template directory not found")
	}
	if out, err := exec.Command("cp", "-a", src, dst).CombinedOutput(); err != nil {
		t.Fatalf("copy templates: %v\n%s", err, out)
	}
}

func TestGitWrapR5TagSortDashValue(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	wrap := installGitWrap(t, work)
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "f.txt", "f\n")
	run := func(args ...string) (string, error) {
		t.Helper()
		return runInstalledWrap(t, wrap, repo, []string{"GIT_TERMINAL_PROMPT=0"}, args...)
	}
	out, err := run("config", "tag.sort", "-version:refname")
	if err != nil {
		t.Fatalf("tag.sort: %v\n%s", err, out)
	}
	if got, ok := gitLocalGet(repo, "tag.sort"); !ok || got != "-version:refname" {
		t.Fatalf("tag.sort=%q ok=%v", got, ok)
	}
	out, err = run("config", "--add", "tag.sort", "-x")
	if err != nil {
		t.Fatalf("add tag.sort: %v\n%s", err, out)
	}
	all := gitCmdOut(t, repo, "config", "--local", "--get-all", "tag.sort")
	if !strings.Contains(all, "-version:refname") || !strings.Contains(all, "-x") {
		t.Fatalf("tag.sort values: %s", all)
	}
	if hostGitAtLeast(t, 2, 46) {
		setRepo := filepath.Join(work, "set-repo")
		commitRepo(t, setRepo, "s.txt", "s\n")
		out, err = runInstalledWrap(t, wrap, setRepo, []string{"GIT_TERMINAL_PROMPT=0"}, "config", "set", "tag.sort", "-v:refname")
		if err != nil {
			t.Fatalf("config set: %v\n%s", err, out)
		}
		if got, ok := gitLocalGet(setRepo, "tag.sort"); !ok || got != "-v:refname" {
			t.Fatalf("set tag.sort=%q ok=%v", got, ok)
		}
	}
	out, err = run("config", "--file", filepath.Join(work, "x"), "tag.sort", "-version:refname")
	if err == nil || !strings.Contains(out, "option is not allowed") {
		t.Fatalf("--file: %v\n%s", err, out)
	}
	out, err = run("config", "core.hooksPath", "-x")
	if err == nil || !strings.Contains(out, "configuration is not allowed") || !strings.Contains(out, "core.hooksPath") {
		t.Fatalf("hooksPath dash: %v\n%s", err, out)
	}
	if _, ok := gitLocalGet(repo, "core.hooksPath"); ok {
		t.Fatal("core.hooksPath was written")
	}
}

func TestGitWrapR5SubmoduleURLVetted(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	ok := filepath.Join(work, "ok")
	if err := os.MkdirAll(ok, 0o755); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrapWith(t, work, gitWrapOpts{
		Grant: true, Name: "Ada", Email: "bot@localhost",
		Repos: []string{"acme/widgets"},
	})
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "f.txt", "f\n")
	configDenied := "configuration is not allowed"
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		return runInstalledWrap(t, wrap, dir, []string{"GIT_TERMINAL_PROMPT=0"}, args...)
	}
	acceptWrite := func(key, val string) {
		t.Helper()
		out, err := run(repo, "config", key, val)
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("write %s=%s: %v\n%s", key, val, err, out)
		}
		out, err = run(repo, "status")
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("status %s=%s: %v\n%s", key, val, err, out)
		}
		gitCmd(t, repo, "config", "--unset", key)
	}
	acceptWrite("submodule.x.url", "https://github.com/acme/widgets.git")
	acceptWrite("submodule.x.url", "file://"+ok)
	acceptWrite("submodule.x.url", "./mod")
	acceptWrite("submodule.x.active", "true")
	out, err := run(repo, "config", "remote.origin.url", "https://github.com/someone/else.git")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("remote url write: %v\n%s", err, out)
	}
	out, err = run(repo, "status")
	if err != nil || strings.Contains(out, configDenied) {
		t.Fatalf("status with remote url: %v\n%s", err, out)
	}
	gitCmd(t, repo, "config", "--unset", "remote.origin.url")

	bad := []string{
		outside,
		"https://github.com/someone/else.git",
		"git@host:x.git",
		"file://" + outside + "/x",
		"../x",
	}
	for _, val := range bad {
		out, err = run(repo, "config", "submodule.x.url", val)
		if err == nil || !strings.Contains(out, configDenied) || !strings.Contains(out, "submodule.x.url") {
			t.Fatalf("write %s: %v\n%s", val, err, out)
		}
		if _, ok := gitLocalGet(repo, "submodule.x.url"); ok {
			t.Fatalf("submodule.x.url stored %s", val)
		}
		dir := filepath.Join(work, "planted-"+strconv.Itoa(len(val)))
		commitRepo(t, dir, "p.txt", "p\n")
		gitCmd(t, dir, "config", "submodule.x.url", val)
		out, err = run(dir, "status")
		if err == nil || !strings.Contains(out, configDenied) || !strings.Contains(out, "submodule.x.url") {
			t.Fatalf("status planted %s: %v\n%s", val, err, out)
		}
	}
}

func TestGitWrapR5HarmlessKeys(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	wrap := installGitWrap(t, work)
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "f.txt", "f\n")
	configDenied := "configuration is not allowed"
	run := func(args ...string) (string, error) {
		t.Helper()
		return runInstalledWrap(t, wrap, repo, []string{"GIT_TERMINAL_PROMPT=0"}, args...)
	}
	good := [][2]string{
		{"help.autocorrect", "0"},
		{"help.autocorrect", "never"},
		{"help.autocorrect", "false"},
		{"help.autocorrect", "no"},
		{"help.autocorrect", "off"},
		{"commit.gpgsign", "false"},
		{"commit.gpgsign", "no"},
		{"commit.gpgsign", "off"},
		{"commit.gpgsign", "0"},
		{"pack.threads", "0"},
		{"pack.threads", "1"},
		{"pack.threads", "42"},
	}
	for _, kv := range good {
		out, err := run("config", kv[0], kv[1])
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("write %s=%s: %v\n%s", kv[0], kv[1], err, out)
		}
		out, err = run("status")
		if err != nil || strings.Contains(out, configDenied) {
			t.Fatalf("status %s=%s: %v\n%s", kv[0], kv[1], err, out)
		}
		gitCmd(t, repo, "config", "--unset", kv[0])
	}
	bad := [][2]string{
		{"help.autocorrect", "1"},
		{"help.autocorrect", "immediate"},
		{"help.autocorrect", "prompt"},
		{"help.autocorrect", "show"},
		{"help.autocorrect", "2"},
		{"commit.gpgsign", "true"},
		{"commit.gpgsign", "yes"},
		{"pack.threads", "-1"},
		{"pack.threads", "1.5"},
		{"pack.threads", "abc"},
	}
	for _, kv := range bad {
		out, err := run("config", kv[0], kv[1])
		if err == nil || !strings.Contains(out, configDenied) || !strings.Contains(out, kv[0]) {
			t.Fatalf("write %s=%s: %v\n%s", kv[0], kv[1], err, out)
		}
		if _, ok := gitLocalGet(repo, kv[0]); ok {
			t.Fatalf("%s=%s was stored", kv[0], kv[1])
		}
		dir := filepath.Join(work, "bad-"+strings.ReplaceAll(kv[0], ".", "-")+"-"+kv[1])
		commitRepo(t, dir, "b.txt", "b\n")
		gitCmd(t, dir, "config", kv[0], kv[1])
		out, err = runInstalledWrap(t, wrap, dir, []string{"GIT_TERMINAL_PROMPT=0"}, "status")
		if err == nil || !strings.Contains(out, configDenied) || !strings.Contains(out, kv[0]) {
			t.Fatalf("status %s=%s: %v\n%s", kv[0], kv[1], err, out)
		}
	}
	for _, kv := range [][2]string{
		{"tag.gpgsign", "true"},
		{"commit.template", "/x"},
		{"user.signingkey", "abc"},
		{"gpg.program", "/x"},
	} {
		out, err := run("config", kv[0], kv[1])
		if err == nil || !strings.Contains(out, configDenied) || !strings.Contains(out, kv[0]) {
			t.Fatalf("write %s: %v\n%s", kv[0], err, out)
		}
		if _, ok := gitLocalGet(repo, kv[0]); ok {
			t.Fatalf("%s was stored", kv[0])
		}
	}
}

func TestGitWrapR5PromisorPinned(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	if !strings.Contains(script, "export GIT_NO_LAZY_FETCH=1") {
		t.Fatal("GIT_NO_LAZY_FETCH is not exported")
	}
	if strings.Contains(script, "remote.*.promisor") || strings.Contains(script, "partialclonefilter") {
		t.Fatal("promisor keys are still on the allowlist")
	}
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	wrap := installGitWrap(t, work)
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "f.txt", "f\n")
	configDenied := "configuration is not allowed"
	refuse := func(key string, args ...string) {
		t.Helper()
		out, err := runInstalledWrap(t, wrap, repo, []string{"GIT_TERMINAL_PROMPT=0"}, args...)
		if err == nil || !strings.Contains(out, configDenied) || !strings.Contains(out, key) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if _, ok := gitLocalGet(repo, key); ok {
			t.Fatalf("%v wrote %s", args, key)
		}
	}
	refuse("remote.x.promisor", "config", "remote.x.promisor", "true")
	refuse("remote.x.promisor", "config", "--add", "remote.x.promisor", "true")
	refuse("remote.x.partialclonefilter", "config", "--replace-all", "remote.x.partialclonefilter", "blob:none")
	refuse("extensions.partialclone", "config", "extensions.partialclone", "origin")
	if hostGitAtLeast(t, 2, 46) {
		refuse("remote.x.promisor", "config", "set", "remote.x.promisor", "true")
	}
}
