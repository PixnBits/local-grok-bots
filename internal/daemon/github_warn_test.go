package daemon

import (
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
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
	if err := os.Chmod(path, 0o644); err != nil {
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

func TestGitPushDenialIsGeneric(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	const url = "https://github.com/other/nope.git"
	push := func(policyRepos, allow []string) sandbox.PushResult {
		t.Helper()
		app.editPol(func(p *policy.Policy) { p.GitHub.Repos = policyRepos })
		bot := store.Bot{ID: "bot_1", Grants: []string{"git", "github"}, GitHubAllow: allow}
		return app.handleGitPush(t.Context(), t.Context(), bot, nil, ".", []string{
			"git", "push", url, "feature",
		})
	}
	wantStderr := "git push denied: " + sandbox.RepoNotAvailable + "\n"
	check := func(res sandbox.PushResult, where string, stderrLeak, detailLeak string) {
		t.Helper()
		if res.Code == 0 || res.Stderr != wantStderr {
			t.Fatalf("stderr %q", res.Stderr)
		}
		for _, leaked := range []string{"allowlist", "missing from", "not allowlisted", "ceiling", "github_allow", stderrLeak} {
			if leaked != "" && strings.Contains(res.Stderr, leaked) {
				t.Fatalf("stderr contains %q: %q", leaked, res.Stderr)
			}
		}
		want := "push allowlist (claimed other/nope from argv) (" + where + ")"
		if len(res.Events) != 1 || res.Events[0].Detail != want {
			t.Fatalf("detail %+v", res.Events)
		}
		if detailLeak != "" && strings.Contains(res.Events[0].Detail, detailLeak) {
			t.Fatalf("detail names %q: %q", detailLeak, res.Events[0].Detail)
		}
	}
	// The repository is on the bot list and absent from the policy ceiling.
	t.Run("bot-only", func(t *testing.T) {
		check(push([]string{"acme/widgets"}, []string{"other/nope"}), "the policy [github].repos ceiling", "bot's github_allow", "bot's github_allow")
	})
	// The repository is on the policy ceiling and absent from the bot list.
	t.Run("policy-only", func(t *testing.T) {
		check(push([]string{"other/nope"}, []string{"acme/widgets"}), "the bot's github_allow", "ceiling", "ceiling")
	})
	t.Run("neither", func(t *testing.T) {
		check(push([]string{"acme/widgets"}, []string{"acme/widgets"}), "the policy [github].repos ceiling and the bot's github_allow", "", "")
	})
}

func TestGitPushGitHubAccessMessages(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	app.editPol(func(p *policy.Policy) { p.GitHub.Repos = []string{"acme/widgets"} })
	args := []string{"git", "push", "https://github.com/acme/widgets.git", "feature"}
	t.Run("grant off", func(t *testing.T) {
		bot := store.Bot{ID: "bot_1", Grants: []string{"git"}, GitHubAllow: []string{"acme/widgets"}}
		res := app.handleGitPush(t.Context(), t.Context(), bot, nil, ".", args)
		want := "git push denied: " + sandbox.GitHubGrantOff + "\n"
		if res.Code == 0 || res.Stderr != want {
			t.Fatalf("stderr %q", res.Stderr)
		}
		if strings.Contains(res.Stderr, sandbox.RepoNotAvailable) || strings.Contains(res.Stderr, "not allowlisted") || strings.Contains(res.Stderr, "allowlist") {
			t.Fatalf("grant-off denial used the allowlist sentence: %q", res.Stderr)
		}
		if len(res.Events) != 1 || res.Events[0].Detail != "push missing grant (claimed acme/widgets from argv)" {
			t.Fatalf("detail %+v", res.Events)
		}
	})
	t.Run("grant off and not in list", func(t *testing.T) {
		bot := store.Bot{ID: "bot_1", Grants: []string{"git"}, GitHubAllow: []string{"acme/widgets"}}
		res := app.handleGitPush(t.Context(), t.Context(), bot, nil, ".", []string{
			"git", "push", "https://github.com/other/nope.git", "feature",
		})
		want := "git push denied: " + sandbox.RepoNotAvailable + "\n"
		if res.Code == 0 || res.Stderr != want || strings.Contains(res.Stderr, sandbox.GitHubGrantOff) {
			t.Fatalf("stderr %q", res.Stderr)
		}
	})
	t.Run("bridge down", func(t *testing.T) {
		bot := store.Bot{ID: "bot_1", Grants: []string{"git", "github"}, GitHubAllow: []string{"acme/widgets"}}
		res := app.handleGitPush(t.Context(), t.Context(), bot, nil, ".", args)
		want := "git push denied: " + sandbox.GitHubBridgeDown + "\n"
		if res.Code == 0 || res.Stderr != want {
			t.Fatalf("stderr %q", res.Stderr)
		}
		if strings.Contains(res.Stderr, sandbox.RepoNotAvailable) || strings.Contains(res.Stderr, "not allowlisted") || strings.Contains(res.Stderr, sandbox.GitHubGrantOff) {
			t.Fatalf("bridge denial used another sentence: %q", res.Stderr)
		}
		if len(res.Events) != 1 || res.Events[0].Detail != "push proxy unavailable (claimed acme/widgets from argv)" {
			t.Fatalf("detail %+v", res.Events)
		}
	})
}

func TestGitHubWarningTokenGrantEmptyAllow(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	missing := t.TempDir() + "/no-such-token"
	app.editPol(func(p *policy.Policy) {
		p.GitHub.Repos = nil
		p.GitHub.TokenFile = missing
	})
	srv := serve(t, app)
	bot := createGrantedBot(t, srv.URL, "Grant", []string{"github"})
	joined := strings.Join(fetchBot(t, srv.URL, bot.ID).Warnings, "\n")
	if !strings.Contains(joined, missing) || !strings.Contains(joined, "missing") {
		t.Fatalf("warnings %q", joined)
	}
}

func TestTokenWarningCachedUntilChange(t *testing.T) {
	var reads atomic.Int32
	prev := readTokenForWarn
	readTokenForWarn = func(path string) (string, error) {
		reads.Add(1)
		return prev(path)
	}
	t.Cleanup(func() { readTokenForWarn = prev })

	const canary = "ghp_CANARYSECRETVALUE"
	path := t.TempDir() + "/token"
	if err := os.WriteFile(path, []byte(canary+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	first := tokenFileWarning(path)
	second := tokenFileWarning(path)
	if reads.Load() != 1 {
		t.Fatalf("reads after two warnings: %d", reads.Load())
	}
	if first != second || !strings.Contains(first, "not mode 0600") || strings.Contains(first, canary) {
		t.Fatalf("mode warning %q", first)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	cleared := tokenFileWarning(path)
	if reads.Load() != 2 {
		t.Fatalf("reads after chmod: %d", reads.Load())
	}
	if cleared != "" || strings.Contains(cleared, canary) {
		t.Fatalf("valid file warned: %q", cleared)
	}
	if err := os.WriteFile(path, []byte("bad token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	shaped := tokenFileWarning(path)
	if reads.Load() != 3 {
		t.Fatalf("reads after rewrite: %d", reads.Load())
	}
	if !strings.Contains(shaped, "not a valid token file") || strings.Contains(shaped, "bad token") || strings.Contains(shaped, canary) {
		t.Fatalf("shape warning %q", shaped)
	}
}

func TestTokenWarningRefreshesWhenCtimeChanges(t *testing.T) {
	const valid = "ghp_CANARYSECRETVALUE"
	path := t.TempDir() + "/token"
	body := []byte(valid + "\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if msg := tokenFileWarning(path); msg != "" {
		t.Fatalf("valid file warned: %q", msg)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	next := []byte("ghp CANARYSECRETVALUE\n")
	if len(next) != len(body) {
		t.Fatalf("length %d %d", len(next), len(body))
	}
	if err := os.WriteFile(path, next, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	msg := tokenFileWarning(path)
	if !strings.Contains(msg, "not a valid token file") || strings.Contains(msg, "ghp ") {
		t.Fatalf("warning %q", msg)
	}
}

func TestTokenWarningExpires(t *testing.T) {
	path := t.TempDir() + "/token"
	if err := os.WriteFile(path, []byte("ghp_CANARYSECRETVALUE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	var reads atomic.Int32
	prev := readTokenForWarn
	readTokenForWarn = func(p string) (string, error) {
		reads.Add(1)
		return prev(p)
	}
	t.Cleanup(func() { readTokenForWarn = prev })
	if msg := tokenFileWarning(path); msg != "" {
		t.Fatalf("valid file warned: %q", msg)
	}
	if reads.Load() != 1 {
		t.Fatalf("reads %d", reads.Load())
	}
	tokenWarnMu.Lock()
	ent := tokenWarns[path]
	ent.at = time.Now().Add(-61 * time.Second)
	tokenWarns[path] = ent
	tokenWarnMu.Unlock()
	if msg := tokenFileWarning(path); msg != "" {
		t.Fatalf("valid file warned after expiry: %q", msg)
	}
	if reads.Load() != 2 {
		t.Fatalf("reads after expiry %d", reads.Load())
	}
}
