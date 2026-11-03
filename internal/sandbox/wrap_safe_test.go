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

func TestGitWrapDenialNamesMissingList(t *testing.T) {
	run := func(t *testing.T, opts gitWrapOpts, remote, want string, absent ...string) {
		t.Helper()
		script := gitWrap(opts)
		dir := t.TempDir()
		path := filepath.Join(dir, "gitwrap")
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
			t.Fatalf("sh -n: %v\n%s", err, out)
		}
		cmd := exec.Command(path, "clone", remote, "dest")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("allowed %s: %s", remote, out)
		}
		text := string(out)
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q\n%s", want, text)
		}
		for _, bad := range absent {
			if strings.Contains(text, bad) {
				t.Fatalf("message names %q\n%s", bad, text)
			}
		}
		if !strings.Contains(text, "not allowlisted") {
			t.Fatalf("message: %s", text)
		}
	}
	both := "the policy [github].repos ceiling and the bot's github_allow"
	ceiling := "the policy [github].repos ceiling"
	bot := "the bot's github_allow"
	run(t, gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"}, "https://github.com/missing/repo.git", "missing from "+both)
	run(t, gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost", BotRepos: []string{"onlybot/repo"}}, "https://github.com/onlybot/repo.git", "missing from "+ceiling, "bot's github_allow")
	run(t, gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost", PolicyRepos: []string{"onlypol/repo"}}, "https://github.com/OnlyPol/repo.git", "missing from "+bot, ceiling)
	run(t, gitWrapOpts{
		Grant: true, Name: "Ada", Email: "bot@localhost",
		Repos: []string{"acme/widgets"}, PolicyRepos: []string{"acme/widgets"}, BotRepos: []string{"acme/widgets"},
	}, "git@github.com:acme/widgets.git", "repository is not allowlisted", "missing from")
}
