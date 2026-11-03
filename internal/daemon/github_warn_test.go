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
	const want = "The policy allows no GitHub repositories, so this bot can't use acme/widgets, other/nope. Add them to `repos` under `[github]` in policy.toml."
	if len(got.Warnings) != 1 || got.Warnings[0].Field != "github_allow" || got.Warnings[0].Text != want {
		t.Fatalf("warnings %+v", got.Warnings)
	}
	res, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/state", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("state %d %s", res.StatusCode, b)
	}
	var st botState
	decodeJSON(t, b, &st)
	if len(st.Warnings) != 1 || st.Warnings[0].Field != "github_allow" || st.Warnings[0].Text != want {
		t.Fatalf("state warnings %+v", st.Warnings)
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
	const want = "other/nope isn't in the policy's GitHub repository list, so this bot can't use it. Add it to `repos` under `[github]` in policy.toml, or remove it here."
	if len(got.Warnings) != 1 || got.Warnings[0].Field != "github_allow" || got.Warnings[0].Text != want {
		t.Fatalf("warnings %+v", got.Warnings)
	}
	if strings.Contains(got.Warnings[0].Text, "acme/widgets") || strings.Contains(got.Warnings[0].Text, "Saving still works") {
		t.Fatalf("warnings %+v", got.Warnings)
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
		t.Fatalf("token warning without github_allow or grant: %+v", w)
	}
	bot := createBot(t, srv.URL, "Tok")
	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"github_allow": []string{"acme/widgets"}}, "")
	if res.StatusCode != 200 {
		t.Fatalf("patch %d %s", res.StatusCode, b)
	}
	got := fetchBot(t, srv.URL, bot.ID)
	want := "The GitHub token file " + missing + " doesn't exist. Create it, or fix `token_file` in policy.toml. GitHub actions fail until then. This applies to every bot with GitHub access."
	if len(got.Warnings) != 1 || got.Warnings[0].Field != "github_token" || got.Warnings[0].Text != want {
		t.Fatalf("warnings %+v", got.Warnings)
	}
	if strings.Contains(got.Warnings[0].Text, "Saving still works") {
		t.Fatalf("config warning %q", got.Warnings[0].Text)
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
	got := fetchBot(t, srv.URL, bot.ID)
	want := "The GitHub token file " + path + " can be read by other users. Run `chmod 600 " + path + "`. This applies to every bot with GitHub access."
	if len(got.Warnings) != 1 || got.Warnings[0].Field != "github_token" || got.Warnings[0].Text != want {
		t.Fatalf("warnings %+v", got.Warnings)
	}
	if strings.Contains(got.Warnings[0].Text, canary) || strings.Contains(got.Warnings[0].Text, "github token refused") || strings.Contains(got.Warnings[0].Text, "Saving still works") {
		t.Fatalf("warning leaked token details: %q", got.Warnings[0].Text)
	}
	if err := os.WriteFile(path, []byte(canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	cleared := fetchBot(t, srv.URL, bot.ID).Warnings
	if len(cleared) != 0 {
		t.Fatalf("valid token still warned: %+v", cleared)
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
	got := fetchBot(t, srv.URL, bot.ID)
	if len(got.Warnings) != 1 || got.Warnings[0].Field != "github_token" || !strings.Contains(got.Warnings[0].Text, missing) || !strings.Contains(got.Warnings[0].Text, "doesn't exist") {
		t.Fatalf("warnings %+v", got.Warnings)
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
	if first != second || !strings.Contains(first, "can be read by other users") || strings.Contains(first, canary) || strings.Contains(first, "Saving still works") {
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
	if !strings.Contains(shaped, "doesn't hold a valid token") || strings.Contains(shaped, "bad token") || strings.Contains(shaped, canary) {
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
	if !strings.Contains(msg, "doesn't hold a valid token") || strings.Contains(msg, "ghp ") {
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

func TestGitHubConfigWarningCopy(t *testing.T) {
	var pol policy.Policy
	oneEmpty := githubConfigWarnings(pol, nil, []string{"example-org/other-repo"})
	const emptyOne = "The policy allows no GitHub repositories, so this bot can't use example-org/other-repo. Add it to `repos` under `[github]` in policy.toml."
	if len(oneEmpty) != 1 || oneEmpty[0].Field != "github_allow" || oneEmpty[0].Text != emptyOne || oneEmpty[0].Link != nil {
		t.Fatalf("empty one %+v", oneEmpty)
	}
	manyEmpty := githubConfigWarnings(pol, nil, []string{"a/x", "b/y"})
	const emptyMany = "The policy allows no GitHub repositories, so this bot can't use a/x, b/y. Add them to `repos` under `[github]` in policy.toml."
	if len(manyEmpty) != 1 || manyEmpty[0].Field != "github_allow" || manyEmpty[0].Text != emptyMany {
		t.Fatalf("empty many %+v", manyEmpty)
	}
	pol.GitHub.Repos = []string{"example-org/allowed-repo"}
	one := githubConfigWarnings(pol, nil, []string{"example-org/allowed-repo", "example-org/other-repo"})
	const gapOne = "example-org/other-repo isn't in the policy's GitHub repository list, so this bot can't use it. Add it to `repos` under `[github]` in policy.toml, or remove it here."
	if len(one) != 1 || one[0].Field != "github_allow" || one[0].Text != gapOne || one[0].Link != nil {
		t.Fatalf("gap one %+v", one)
	}
	many := githubConfigWarnings(pol, nil, []string{"a/x", "b/y"})
	const gapMany = "a/x, b/y aren't in the policy's GitHub repository list, so this bot can't use them. Add them to `repos` under `[github]` in policy.toml, or remove them here."
	if len(many) != 1 || many[0].Field != "github_allow" || many[0].Text != gapMany {
		t.Fatalf("gap many %+v", many)
	}
	for _, w := range []store.Warning{oneEmpty[0], manyEmpty[0], one[0], many[0]} {
		if strings.Contains(w.Text, "Saving still works") {
			t.Fatalf("config suffix %q", w.Text)
		}
	}
}

func TestTokenWarningCopy(t *testing.T) {
	const path = "/var/empty/token"
	who := daemonUserName()
	const suffix = " This applies to every bot with GitHub access."
	cases := []struct {
		reason string
		size   int64
		want   string
	}{
		{"missing", 0, "The GitHub token file " + path + " doesn't exist. Create it, or fix `token_file` in policy.toml. GitHub actions fail until then." + suffix},
		{"mode", 0, "The GitHub token file " + path + " can be read by other users. Run `chmod 600 " + path + "`." + suffix},
		{"token file: not owned by daemon", 0, "The GitHub token file " + path + " belongs to another user. Run `sudo chown " + who + " " + path + "`, then `chmod 600 " + path + "`." + suffix},
		{"permission denied", 0, "The daemon can't open the GitHub token file " + path + ". Run `chmod 600 " + path + "`. If that doesn't help, make sure " + who + " can open the folder it's in." + suffix},
		{"type", 0, "The GitHub token file " + path + " is a folder, a link, or another special file. Point `token_file` in policy.toml at the token file itself." + suffix},
		{"shape", 0, "The GitHub token file " + path + " doesn't hold a valid token. Put just the token on one line, with no spaces." + suffix},
		{"size", 0, "The GitHub token file " + path + " is empty. Put your token in it." + suffix},
		{"size", 5000, "The GitHub token file " + path + " is too big to be a token. Put just one token in it." + suffix},
		{"read error", 0, "The daemon couldn't read the GitHub token file " + path + ". Check that the path is right and that the file is a plain file you own, then run `chmod 600 " + path + "`." + suffix},
		{"check", 0, "The daemon couldn't read the GitHub token file " + path + ". Check that the path is right and that the file is a plain file you own, then run `chmod 600 " + path + "`." + suffix},
		{"other", 0, "The daemon couldn't read the GitHub token file " + path + ". Check that the path is right and that the file is a plain file you own, then run `chmod 600 " + path + "`." + suffix},
	}
	for _, c := range cases {
		got := tokenWarningText(path, c.reason, c.size)
		if got != c.want {
			t.Errorf("reason %s size %d\n got %q\nwant %q", c.reason, c.size, got, c.want)
		}
		if c.reason == "permission denied" && (strings.Contains(got, "chown") || strings.Contains(strings.ReplaceAll(got, who, ""), "root") || !strings.Contains(got, who)) {
			t.Errorf("denied warning %q", got)
		}
		if strings.Contains(got, "Saving still works") {
			t.Errorf("config suffix on %s", c.reason)
		}
	}
	owner := tokenWarningText(path, "token file: not owned by daemon", 0)
	if !strings.Contains(owner, "sudo chown") {
		t.Fatalf("owner warning missing sudo chown: %q", owner)
	}
}

func TestTokenWarningSizeFile(t *testing.T) {
	const suffix = " This applies to every bot with GitHub access."
	write := func(body []byte) string {
		t.Helper()
		path := t.TempDir() + "/token"
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	emptyPath := write(nil)
	got := tokenFileWarning(emptyPath)
	want := "The GitHub token file " + emptyPath + " is empty. Put your token in it." + suffix
	if got != want {
		t.Fatalf("empty file %q", got)
	}
	bigPath := write(make([]byte, 5000))
	got = tokenFileWarning(bigPath)
	want = "The GitHub token file " + bigPath + " is too big to be a token. Put just one token in it." + suffix
	if got != want {
		t.Fatalf("big file %q", got)
	}
}

func TestTokenWarningUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read a mode 000 file")
	}
	path := t.TempDir() + "/token"
	if err := os.WriteFile(path, []byte("ghp_CANARYSECRETVALUE\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	msg := tokenFileWarning(path)
	who := daemonUserName()
	want := tokenWarningText(path, "permission denied", 0)
	if msg != want {
		t.Fatalf("got %q\nwant %q", msg, want)
	}
	if strings.Contains(msg, "chown") || strings.Contains(strings.ReplaceAll(msg, who, ""), "root") || !strings.Contains(msg, who) {
		t.Fatalf("unreadable warning %q", msg)
	}
}

func TestBotWarningFields(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	missing := t.TempDir() + "/no-such-token"
	app.editPol(func(p *policy.Policy) {
		p.GitHub.Repos = []string{"example-org/allowed-repo"}
		p.GitHub.TokenFile = missing
	})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "All")
	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{
		"net_allow":    []string{"storage.googleapis.com"},
		"github_allow": []string{"example-org/other-repo"},
	}, "")
	if res.StatusCode != 200 {
		t.Fatalf("patch %d %s", res.StatusCode, b)
	}
	var patched store.Bot
	decodeJSON(t, b, &patched)
	checkWarningFields(t, patched.Warnings, missing)
	checkWarningFields(t, fetchBot(t, srv.URL, bot.ID).Warnings, missing)
	res, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/state", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("state %d %s", res.StatusCode, b)
	}
	var st botState
	decodeJSON(t, b, &st)
	checkWarningFields(t, st.Warnings, missing)
}

func checkWarningFields(t *testing.T, got []store.Warning, tokenPath string) {
	t.Helper()
	if len(got) != 3 {
		t.Fatalf("warnings %+v", got)
	}
	if got[0].Field != "github_allow" || got[1].Field != "github_token" || got[2].Field != "net_allow" {
		t.Fatalf("fields %+v", got)
	}
	const gap = "example-org/other-repo isn't in the policy's GitHub repository list, so this bot can't use it. Add it to `repos` under `[github]` in policy.toml, or remove it here."
	if got[0].Text != gap || got[0].Link != nil {
		t.Fatalf("repo %+v", got[0])
	}
	token := "The GitHub token file " + tokenPath + " doesn't exist. Create it, or fix `token_file` in policy.toml. GitHub actions fail until then. This applies to every bot with GitHub access."
	if got[1].Text != token || got[1].Link != nil {
		t.Fatalf("token %+v", got[1])
	}
	const host = "storage.googleapis.com gives this bot access to all of Google Cloud Storage, not just your project. Remove it unless the bot needs it."
	if got[2].Text != host || got[2].Link == nil || got[2].Link.Href != "https://github.com/PixnBits/local-grok-bots/issues/33" || got[2].Link.Label != "Why this matters (GitHub issue #33)" {
		t.Fatalf("host %+v", got[2])
	}
	if strings.Contains(got[2].Text, "docs/sandbox.md") || strings.Contains(got[2].Text, "https://") {
		t.Fatalf("host text %q", got[2].Text)
	}
	for _, w := range got {
		if strings.Contains(w.Text, "Saving still works") {
			t.Fatalf("config suffix %q", w.Text)
		}
	}
}
