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
		"unset SSH_AUTH_SOCK http_proxy https_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY no_proxy",
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("missing %s", needle)
		}
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
