package policy

import (
	"strings"
	"testing"
)

func TestGitHubMerge(t *testing.T) {
	plain := writePolicyFile(t, "policy.toml", "[backend]\nbackend = \"ollama\"\n")
	p, err := Load(Options{Path: plain})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.GitHub.Repos) != 0 || p.GitHub.Source != "default" {
		t.Fatalf("default %#v", p.GitHub)
	}
	if len(p.EffectiveGitHubRepos(nil)) != 0 || len(p.EffectiveGitHubRepos([]string{})) != 0 {
		t.Fatal("empty bot allow inherited the ceiling")
	}

	localOnly := writePolicyFile(t, "policy.toml", `
[backend]
backend = "ollama"
[github]
token_file = "/etc/local-grok-bots/github.token"
repos = ["Acme/Widgets", "acme/other"]
author_email = "{name}@users.noreply"
author_name = "ci-bot"
`)
	p, err = Load(Options{Path: localOnly})
	if err != nil {
		t.Fatal(err)
	}
	if p.GitHub.Source != "local" || strings.Join(p.GitHub.Repos, ",") != "acme/widgets,acme/other" {
		t.Fatalf("local %#v", p.GitHub)
	}
	if p.GitHub.TokenFile != "/etc/local-grok-bots/github.token" || p.GitHub.AuthorName != "ci-bot" || p.GitHub.AuthorEmail != "{name}@users.noreply" {
		t.Fatalf("scalars %#v", p.GitHub)
	}
	eff := p.EffectiveGitHubRepos([]string{"acme/widgets", "elsewhere/nope"})
	if strings.Join(eff, ",") != "acme/widgets" {
		t.Fatalf("bot narrow %#v", eff)
	}

	managed := writePolicyFile(t, "managed.json", `{"github":{"repos":["acme/widgets","acme/other"],"token_file":"/run/token"}}`)
	localWide := writePolicyFile(t, "policy.toml", `
[backend]
backend = "ollama"
[github]
repos = ["acme/widgets", "outside/repo"]
token_file = "/etc/local-token"
`)
	p, err = Load(Options{Path: localWide, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.GitHub.Repos, ",") != "acme/widgets" || p.GitHub.Source != "local" {
		t.Fatalf("ceiling %#v", p.GitHub)
	}
	if p.GitHub.TokenFile != "/run/token" {
		t.Fatalf("managed token lost: %s", p.GitHub.TokenFile)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "outside/repo") {
		t.Fatalf("warnings %#v", p.Warnings)
	}

	localEmpty := writePolicyFile(t, "policy.toml", "[backend]\nbackend = \"ollama\"\n[github]\nrepos = []\n")
	p, err = Load(Options{Path: localEmpty, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.GitHub.Repos) != 0 || p.GitHub.Source != "local" {
		t.Fatalf("empty local %#v", p.GitHub)
	}

	bad := writePolicyFile(t, "policy.toml", "[backend]\nbackend = \"ollama\"\n[github]\nrepos = [\"not a repo\"]\ntoken_file = \"/etc/token\"\n")
	p, err = Load(Options{Path: bad})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.GitHub.Repos) != 0 || p.GitHub.TokenFile != "" || p.GitHub.Source != "default" {
		t.Fatalf("bad local turned GitHub on: %#v", p.GitHub)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "disabled") {
		t.Fatalf("warnings %#v", p.Warnings)
	}

	goodLocal := writePolicyFile(t, "policy.toml", "[backend]\nbackend = \"ollama\"\n[github]\nrepos = [\"acme/widgets\"]\n")
	badManaged := writePolicyFile(t, "managed.json", `{"github":{"repos":["../etc"]}}`)
	p, err = Load(Options{Path: goodLocal, ManagedPath: badManaged})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.GitHub.Repos) != 0 || p.GitHub.Source != "disabled" {
		t.Fatalf("bad managed did not fail closed: %#v", p.GitHub)
	}
}
