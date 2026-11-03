package daemon

import (
	"os"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestGitHubWarningEmptyCeiling(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	app.editPol(func(p *policy.Policy) { p.GitHub.Repos = nil })
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Ceil")
	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"github_allow": []string{"acme/widgets", "other/nope"}}, "")
	if res.StatusCode != 200 {
		t.Fatalf("patch %d %s", res.StatusCode, b)
	}
	got := fetchBot(t, srv.URL, bot.ID)
	joined := strings.Join(got.Warnings, "\n")
	if !strings.Contains(joined, "policy [github].repos ceiling is empty") || !strings.Contains(joined, "acme/widgets") || !strings.Contains(joined, "other/nope") {
		t.Fatalf("warnings %q", got.Warnings)
	}
	res, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/state", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("state %d %s", res.StatusCode, b)
	}
	var st botState
	decodeJSON(t, b, &st)
	if !strings.Contains(strings.Join(st.Warnings, "\n"), "ceiling is empty") {
		t.Fatalf("state warnings %q", st.Warnings)
	}
}

func TestGitHubWarningRepoNotInCeiling(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	app.editPol(func(p *policy.Policy) { p.GitHub.Repos = []string{"acme/widgets"} })
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Gap")
	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"github_allow": []string{"acme/widgets", "other/nope"}}, "")
	if res.StatusCode != 200 {
		t.Fatalf("patch %d %s", res.StatusCode, b)
	}
	got := fetchBot(t, srv.URL, bot.ID)
	joined := strings.Join(got.Warnings, "\n")
	if !strings.Contains(joined, "does not include other/nope") || strings.Contains(joined, "acme/widgets") {
		t.Fatalf("warnings %q", got.Warnings)
	}
}

func TestGitHubWarningTokenMissing(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	missing := t.TempDir() + "/no-such-token"
	app.editPol(func(p *policy.Policy) {
		p.GitHub.Repos = []string{"acme/widgets"}
		p.GitHub.TokenFile = missing
	})
	srv := serve(t, app)
	plain := createBot(t, srv.URL, "Plain")
	if w := fetchBot(t, srv.URL, plain.ID).Warnings; len(w) != 0 {
		t.Fatalf("token warning without github_allow or grant: %q", w)
	}
	bot := createBot(t, srv.URL, "Tok")
	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"github_allow": []string{"acme/widgets"}}, "")
	if res.StatusCode != 200 {
		t.Fatalf("patch %d %s", res.StatusCode, b)
	}
	joined := strings.Join(fetchBot(t, srv.URL, bot.ID).Warnings, "\n")
	if !strings.Contains(joined, missing) || !strings.Contains(joined, "missing") {
		t.Fatalf("warnings %q", joined)
	}
}

func TestGitHubWarningTokenMode(t *testing.T) {
	const canary = "ghp_CANARYSECRETVALUE"
	app := newApp(t, "", fakeModel{})
	path := t.TempDir() + "/token"
	if err := os.WriteFile(path, []byte(canary+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app.editPol(func(p *policy.Policy) {
		p.GitHub.Repos = []string{"acme/widgets"}
		p.GitHub.TokenFile = path
	})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Mode")
	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"github_allow": []string{"acme/widgets"}}, "")
	if res.StatusCode != 200 {
		t.Fatalf("patch %d %s", res.StatusCode, b)
	}
	joined := strings.Join(fetchBot(t, srv.URL, bot.ID).Warnings, "\n")
	if !strings.Contains(joined, "not mode 0600") || !strings.Contains(joined, path) {
		t.Fatalf("warnings %q", joined)
	}
	if strings.Contains(joined, canary) || strings.Contains(joined, "github token refused") {
		t.Fatalf("warning leaked token details: %q", joined)
	}
	if err := os.WriteFile(path, []byte(canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(fetchBot(t, srv.URL, bot.ID).Warnings, "\n")
	if strings.Contains(joined, "token_file") || strings.Contains(joined, canary) {
		t.Fatalf("valid token still warned: %q", joined)
	}
}

func TestGitPushDenialNamesMissingList(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	app.editPol(func(p *policy.Policy) { p.GitHub.Repos = []string{"acme/widgets"} })
	bot := store.Bot{ID: "bot_1", Grants: []string{"git", "github"}, GitHubAllow: []string{"other/nope"}}
	res := app.handleGitPush(t.Context(), t.Context(), bot, nil, ".", []string{
		"git", "push", "https://github.com/other/nope.git", "feature",
	})
	if res.Code == 0 || !strings.Contains(res.Stderr, "missing from the policy [github].repos ceiling") {
		t.Fatalf("stderr %q", res.Stderr)
	}
	if strings.Contains(res.Stderr, "bot's github_allow") {
		t.Fatalf("named the bot list too: %q", res.Stderr)
	}
	if len(res.Events) != 1 || res.Events[0].Detail != "push allowlist (claimed other/nope from argv)" {
		t.Fatalf("detail %+v", res.Events)
	}
}
