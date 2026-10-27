package daemon

import (
	"encoding/json"
	"errors"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestCreatePRAndStatus(t *testing.T) {
	const leak = "lgb-github-test-secret-value"
	var mu sync.Mutex
	var posts atomic.Int32
	var bodies []string
	var auths []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"default_branch":"main"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/widgets/pulls":
			posts.Add(1)
			b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			mu.Lock()
			bodies = append(bodies, string(b))
			mu.Unlock()
			if strings.Contains(string(b), "status-422") {
				w.WriteHeader(http.StatusUnprocessableEntity)
				io.WriteString(w, `{"message":"`+leak+`","html_url":"https://evil.example/x"}`)
				return
			}
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"html_url":"https://github.com/acme/widgets/pull/7","state":"open","draft":true,"head":{"ref":"feature","sha":"`+leak+`"},"base":{"ref":"main"},"body":"`+leak+`","title":"Add a widget"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/pulls/7":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"html_url":"https://github.com/acme/widgets/pull/7","state":"open","draft":true,"head":{"ref":"feature","sha":"`+leak+`"},"base":{"ref":"main","label":"`+leak+`"},"body":"`+leak+`"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)

	prev := readGitHubToken
	readGitHubToken = func(string) (string, error) { return leak, nil }
	t.Cleanup(func() { readGitHubToken = prev })

	type prApp struct {
		app   *App
		evals *atomic.Int32
		audit string
	}
	newPRApp := func(t *testing.T) prApp {
		t.Helper()
		app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
			return model.ChatResponse{Content: "no"}, nil
		}})
		app.githubAPIBase = upstream.URL
		app.editPol(func(p *policy.Policy) { p.GitHub.Repos = []string{"acme/widgets"} })
		app.editPol(func(p *policy.Policy) { p.GitHub.TokenFile = "/etc/local-grok-bots/github.token" })
		app.editPol(func(p *policy.Policy) { p.UIPrompts = true })
		app.editPol(func(p *policy.Policy) { p.PromptTimeout = 20 * time.Second })
		auditPath := filepath.Join(t.TempDir(), "audit.log")
		lg, err := audit.Open(auditPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lg.Close() })
		app.audit = lg
		var evals atomic.Int32
		var notForced atomic.Bool
		app.perm.AddHook(func(req permission.Request) permission.HookResult {
			if req.Tool == "create_pr" || req.Tool == "pr_status" {
				evals.Add(1)
				if req.Tool == "create_pr" && !req.ForceAsk {
					notForced.Store(true)
				}
			}
			return permission.HookResult{}
		})
		t.Cleanup(func() {
			if notForced.Load() {
				t.Error("create_pr was not ForceAsk")
			}
		})
		return prApp{app: app, evals: &evals, audit: auditPath}
	}
	allow := func(t *testing.T, app *App, repos []string) store.Bot {
		t.Helper()
		srv := serve(t, app)
		bot := createGrantedBot(t, srv.URL, "Ada", []string{"github"})
		if repos != nil {
			res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"github_allow": repos}, "")
			if res.StatusCode != 200 {
				t.Fatalf("allow %d %s", res.StatusCode, b)
			}
		}
		return bot
	}
	args := map[string]any{"repo": "acme/widgets", "head": "feature", "base": "main", "title": "Add a widget", "body": "Fixes the empty state."}

	t.Run("card and create", func(t *testing.T) {
		env := newPRApp(t)
		bot := allow(t, env.app, []string{"acme/widgets"})
		before := posts.Load()
		done := approveCard(env.app, bot.ID, "create_pr")
		out, err := env.app.dispatchTool(t.Context(), bot, "create_pr", args)
		if aerr := <-done; aerr != nil {
			t.Fatal(aerr)
		}
		if err != nil || out != `{"html_url":"https://github.com/acme/widgets/pull/7"}` {
			t.Fatalf("create: %v %s", err, out)
		}
		if env.evals.Load() == 0 || posts.Load() <= before {
			t.Fatalf("evals %d posts %d", env.evals.Load(), posts.Load())
		}
		mu.Lock()
		body := bodies[len(bodies)-1]
		gotAuth := append([]string(nil), auths...)
		mu.Unlock()
		var sent struct {
			Title, Head, Base, Body string
			Draft                   bool
		}
		if json.Unmarshal([]byte(body), &sent) != nil || sent.Title != "Add a widget" || sent.Head != "feature" || sent.Base != "main" || sent.Body != "Fixes the empty state." || !sent.Draft {
			t.Fatalf("posted %s", body)
		}
		for _, h := range gotAuth {
			if h != "Bearer "+leak {
				t.Fatalf("auth %q", h)
			}
		}
		raw := readAudit(t, env.audit)
		if !strings.Contains(raw, "github_pr_allowed") || strings.Contains(raw, leak) || strings.Contains(out, leak) {
			t.Fatalf("audit leak or missing allow\n%s", raw)
		}
	})

	t.Run("bypass still asks", func(t *testing.T) {
		env := newPRApp(t)
		env.app.editPol(func(p *policy.Policy) { p.PermissionMode = "bypassPermissions" })
		bot := allow(t, env.app, []string{"acme/widgets"})
		done := approveCard(env.app, bot.ID, "create_pr")
		out, err := env.app.dispatchTool(t.Context(), bot, "create_pr", map[string]any{
			"repo": "acme/widgets", "head": "feature", "base": "main", "title": "Bypass", "draft": false,
		})
		if aerr := <-done; aerr != nil {
			t.Fatal(aerr)
		}
		if err != nil || env.evals.Load() == 0 || !strings.Contains(out, "html_url") {
			t.Fatalf("bypass: %v evals=%d %s", err, env.evals.Load(), out)
		}
		mu.Lock()
		body := bodies[len(bodies)-1]
		mu.Unlock()
		if !strings.Contains(body, `"draft":false`) {
			t.Fatalf("draft was not false: %s", body)
		}
	})

	t.Run("managed allow still asks", func(t *testing.T) {
		env := newPRApp(t)
		env.app.editPol(func(p *policy.Policy) { p.ToolAllow = []string{"create_pr"} })
		bot := allow(t, env.app, []string{"acme/widgets"})
		done := approveCard(env.app, bot.ID, "create_pr")
		_, err := env.app.dispatchTool(t.Context(), bot, "create_pr", map[string]any{
			"repo": "acme/widgets", "head": "feature", "base": "main", "title": "Managed",
		})
		if aerr := <-done; aerr != nil {
			t.Fatal(aerr)
		}
		if err != nil || env.evals.Load() == 0 {
			t.Fatalf("managed allow skipped the card: %v evals=%d", err, env.evals.Load())
		}
	})

	t.Run("durable allow still asks", func(t *testing.T) {
		env := newPRApp(t)
		bot := allow(t, env.app, []string{"acme/widgets"})
		if _, err := env.app.st.InsertUserPermRule(store.UserPermRule{BotID: bot.ID, Effect: "allow", Pattern: "create_pr"}); err != nil {
			t.Fatal(err)
		}
		done := approveCard(env.app, bot.ID, "create_pr")
		_, err := env.app.dispatchTool(t.Context(), bot, "create_pr", map[string]any{
			"repo": "acme/widgets", "head": "feature", "base": "main", "title": "Durable",
		})
		if aerr := <-done; aerr != nil {
			t.Fatal(aerr)
		}
		if err != nil || env.evals.Load() == 0 {
			t.Fatalf("durable allow skipped the card: %v evals=%d", err, env.evals.Load())
		}
	})

	deny := func(t *testing.T, repos []string, call map[string]any, reason string, durable bool) {
		t.Helper()
		env := newPRApp(t)
		bot := allow(t, env.app, repos)
		if durable {
			if _, err := env.app.st.InsertUserPermRule(store.UserPermRule{BotID: bot.ID, Effect: "allow", Pattern: "create_pr"}); err != nil {
				t.Fatal(err)
			}
		}
		before := posts.Load()
		out, err := env.app.dispatchTool(t.Context(), bot, "create_pr", call)
		if err == nil || strings.Contains(out, "html_url") || strings.Contains(out, leak) || strings.Contains(err.Error(), leak) {
			t.Fatalf("created: %v %s", err, out)
		}
		if !strings.Contains(err.Error(), reason) {
			t.Fatalf("reason %s missing: %v", reason, err)
		}
		if env.evals.Load() != 0 || posts.Load() != before {
			t.Fatalf("deny %s called Evaluate or POST evals=%d", reason, env.evals.Load())
		}
		raw := readAudit(t, env.audit)
		if !strings.Contains(raw, "github_pr_denied") || strings.Contains(raw, leak) {
			t.Fatalf("audit %s", raw)
		}
	}

	t.Run("default branch", func(t *testing.T) {
		deny(t, []string{"acme/widgets"}, map[string]any{
			"repo": "acme/widgets", "head": "main", "base": "develop", "title": "Onto main",
		}, "default branch", true)
	})
	t.Run("default branch case", func(t *testing.T) {
		deny(t, []string{"acme/widgets"}, map[string]any{
			"repo": "acme/widgets", "head": "Main", "base": "develop", "title": "Onto Main",
		}, "default branch", true)
	})
	t.Run("base may match default case", func(t *testing.T) {
		env := newPRApp(t)
		bot := allow(t, env.app, []string{"acme/widgets"})
		before := posts.Load()
		done := approveCard(env.app, bot.ID, "create_pr")
		out, err := env.app.dispatchTool(t.Context(), bot, "create_pr", map[string]any{
			"repo": "acme/widgets", "head": "feature", "base": "MAIN", "title": "Add a widget",
		})
		if aerr := <-done; aerr != nil {
			t.Fatal(aerr)
		}
		if err != nil || !strings.Contains(out, "https://github.com/acme/widgets/pull/7") || env.evals.Load() == 0 || posts.Load() != before+1 {
			t.Fatalf("base MAIN: %v evals=%d posts=%d %s", err, env.evals.Load(), posts.Load(), out)
		}
	})
	t.Run("empty allowlist", func(t *testing.T) {
		deny(t, nil, args, "allowlist", false)
	})
	t.Run("outside ceiling", func(t *testing.T) {
		deny(t, []string{"other/nope"}, map[string]any{
			"repo": "other/nope", "head": "feature", "base": "main", "title": "Nope",
		}, "allowlist", false)
	})
	t.Run("bad head", func(t *testing.T) {
		deny(t, []string{"acme/widgets"}, map[string]any{
			"repo": "acme/widgets", "head": "refs/heads/feature", "base": "main", "title": "Bad",
		}, "invalid arguments", false)
	})
	t.Run("missing grant", func(t *testing.T) {
		env := newPRApp(t)
		srv := serve(t, env.app)
		bot := createGrantedBot(t, srv.URL, "Ada", []string{"git"})
		out, err := env.app.dispatchTool(t.Context(), bot, "create_pr", args)
		if err == nil || !strings.Contains(err.Error(), "grant") || env.evals.Load() != 0 || strings.Contains(out, leak) {
			t.Fatalf("missing grant: %v %s", err, out)
		}
	})
	t.Run("prompts off", func(t *testing.T) {
		env := newPRApp(t)
		env.app.editPol(func(p *policy.Policy) { p.UIPrompts = false })
		bot := allow(t, env.app, []string{"acme/widgets"})
		before := posts.Load()
		out, err := env.app.dispatchTool(t.Context(), bot, "create_pr", args)
		if err == nil || !strings.Contains(err.Error(), "prompts disabled") || env.evals.Load() == 0 || posts.Load() != before || strings.Contains(out, leak) {
			t.Fatalf("prompts off: %v evals=%d %s", err, env.evals.Load(), out)
		}
	})
	t.Run("status only", func(t *testing.T) {
		env := newPRApp(t)
		bot := allow(t, env.app, []string{"acme/widgets"})
		before := posts.Load()
		done := approveCard(env.app, bot.ID, "create_pr")
		out, err := env.app.dispatchTool(t.Context(), bot, "create_pr", map[string]any{
			"repo": "acme/widgets", "head": "feature", "base": "main", "title": "status-422",
		})
		if aerr := <-done; aerr != nil {
			t.Fatal(aerr)
		}
		if err == nil || err.Error() != "github status 422" || strings.Contains(err.Error(), leak) || strings.Contains(out, leak) || strings.Contains(out, "evil") {
			t.Fatalf("status: %v %s", err, out)
		}
		if posts.Load() != before+1 || env.evals.Load() == 0 {
			t.Fatalf("status path evals=%d posts=%d", env.evals.Load(), posts.Load())
		}
		raw := readAudit(t, env.audit)
		if strings.Contains(raw, leak) || strings.Contains(raw, "evil.example") {
			t.Fatalf("audit leaked the body\n%s", raw)
		}
	})
	t.Run("pr status", func(t *testing.T) {
		env := newPRApp(t)
		bot := allow(t, env.app, []string{"acme/widgets"})
		out, err := env.app.dispatchTool(t.Context(), bot, "pr_status", map[string]any{"repo": "acme/widgets", "number": float64(7)})
		if err != nil {
			t.Fatal(err)
		}
		if env.evals.Load() != 0 {
			t.Fatal("pr_status opened a card")
		}
		var got struct {
			URL   string `json:"html_url"`
			State string `json:"state"`
			Draft bool   `json:"draft"`
			Head  string `json:"head"`
			Base  string `json:"base"`
		}
		if json.Unmarshal([]byte(out), &got) != nil || got.URL != "https://github.com/acme/widgets/pull/7" || got.State != "open" || !got.Draft || got.Head != "feature" || got.Base != "main" {
			t.Fatalf("status projection %s", out)
		}
		if strings.Contains(out, leak) || strings.Count(out, "{") != 1 {
			t.Fatalf("raw json leaked: %s", out)
		}
		raw := readAudit(t, env.audit)
		if !strings.Contains(raw, "github_pr_status") || strings.Contains(raw, leak) {
			t.Fatalf("audit %s", raw)
		}
	})
}

func approveCard(app *App, botID, tool string) <-chan error {
	errc := make(chan error, 1)
	go func() {
		defer close(errc)
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			for _, card := range app.perm.Pending(botID) {
				if card["tool"] != tool {
					continue
				}
				id, _ := card["id"].(string)
				runID, _ := card["run_id"].(string)
				if app.writeProxyUp() {
					errc <- errors.New("write proxy reachable before approval")
					return
				}
				if err := app.perm.DecideFor(botID, runID, id, permission.AllowOnce); err != nil {
					errc <- err
				}
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
		errc <- errors.New("approval card did not appear")
	}()
	return errc
}
