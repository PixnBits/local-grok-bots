package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestGitHubIssueAndPRTools(t *testing.T) {
	const leak = "lgb-github-test-secret-value"
	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var mu sync.Mutex
	var mode atomic.Value
	mode.Store("ok")
	var hits atomic.Int32
	var tokenReads atomic.Int32
	type hit struct {
		method string
		path   string
		query  string
		body   string
	}
	var seen []hit
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		mu.Lock()
		seen = append(seen, hit{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, body: string(b)})
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+leak {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		if !strings.Contains(r.URL.Path, "/acme/widgets/") && r.URL.Path != "/repos/acme/widgets" && !strings.HasPrefix(r.URL.Path, "/repos/acme/widgets/") {
			http.NotFound(w, r)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		if per < 1 {
			per = 30
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/issues":
			if mode.Load() == "many" {
				writeIssuePage(w, page, per, "short")
				return
			}
			if mode.Load() == "huge" {
				fmt.Fprintf(w, `[{"number":1,"title":"Huge body","state":"open","body":%q,"html_url":"https://github.com/acme/widgets/issues/1","user":{"login":"ada"}}]`, strings.Repeat("B", 3000))
				return
			}
			if mode.Load() == "wide" {
				writeIssuePage(w, page, per, strings.Repeat("C", 1000))
				return
			}
			fmt.Fprintf(w, `[
				{"number":1,"title":"Empty state","state":"open","body":"the list is blank","html_url":"https://github.com/acme/widgets/issues/1","user":{"login":"ada"}},
				{"number":99,"title":"a pull","state":"open","pull_request":{"url":"x"},"html_url":"https://github.com/acme/widgets/issues/99","user":{"login":"ada"}},
				{"number":2,"title":"Second","state":"open","body":"also open","html_url":"https://github.com/acme/widgets/issues/2","user":{"login":"ada"}}
			]`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/issues/7":
			body := "the list is blank"
			if mode.Load() == "huge" {
				body = strings.Repeat("B", 3000)
			}
			fmt.Fprintf(w, `{"number":7,"title":"Empty state","state":"open","body":%q,"html_url":"https://github.com/acme/widgets/issues/7","user":{"login":"ada"}}`, body)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/issues/7/comments":
			if mode.Load() == "many" {
				writeCommentPage(w, page, per)
				return
			}
			fmt.Fprintf(w, `[{"id":11,"body":"please fix","html_url":"https://github.com/acme/widgets/issues/7#issuecomment-11","user":{"login":"bea"}}]`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/pulls/7":
			fmt.Fprintf(w, `{"html_url":"https://github.com/acme/widgets/pull/7","title":"Add a widget","body":"Fixes the empty state.","state":"open","head":{"ref":"feature","sha":"%s"},"base":{"ref":"main"}}`, sha)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/pulls/7/files":
			if mode.Load() == "many" {
				writeFilePage(w, page, per)
				return
			}
			fmt.Fprintf(w, `[{"filename":"a.go","status":"modified","additions":1,"deletions":0,"patch":"@@ -1 +1 @@\n-old\n+new"}]`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/pulls/7/reviews":
			fmt.Fprintf(w, `[{"user":{"login":"bea"},"state":"CHANGES_REQUESTED","body":"rename the helper"}]`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/pulls/7/comments":
			fmt.Fprintf(w, `[{"user":{"login":"bea"},"path":"a.go","line":3,"body":"nit","diff_hunk":"@@ context"}]`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/check-runs"):
			fmt.Fprintf(w, `{"total_count":1,"check_runs":[{"name":"ci","status":"completed","conclusion":"success"}]}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/status"):
			fmt.Fprintf(w, `{"state":"success","statuses":[{"context":"ci","state":"success"}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/widgets/issues":
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"number":4,"html_url":"https://github.com/acme/widgets/issues/4"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/widgets/issues/7/comments":
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"id":15,"html_url":"https://github.com/acme/widgets/issues/7#issuecomment-15"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)

	prev := readGitHubToken
	readGitHubToken = func(string) (string, error) {
		tokenReads.Add(1)
		return leak, nil
	}
	t.Cleanup(func() { readGitHubToken = prev })

	type env struct {
		app   *App
		bot   store.Bot
		evals *atomic.Int32
		audit string
	}
	newEnv := func(t *testing.T, repos []string) env {
		t.Helper()
		app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
			return model.ChatResponse{Content: "no"}, nil
		}})
		app.githubAPIBase = upstream.URL
		app.editPol(func(p *policy.Policy) { p.GitHub.Repos = []string{"acme/widgets"} })
		app.editPol(func(p *policy.Policy) { p.GitHub.TokenFile = "/etc/local-grok-bots/github.token" })
		app.editPol(func(p *policy.Policy) { p.UIPrompts = true })
		app.editPol(func(p *policy.Policy) { p.PromptTimeout = 15 * time.Second })
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
			switch req.Tool {
			case "create_issue", "create_comment", "list_issues", "read_issue", "read_pr":
				evals.Add(1)
				if (req.Tool == "create_issue" || req.Tool == "create_comment") && !req.ForceAsk {
					notForced.Store(true)
				}
			}
			return permission.HookResult{}
		})
		t.Cleanup(func() {
			if notForced.Load() {
				t.Error("write was not ForceAsk")
			}
		})
		srv := serve(t, app)
		bot := createGrantedBot(t, srv.URL, "Ada", []string{"github"})
		if repos != nil {
			res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"github_allow": repos}, "")
			if res.StatusCode != 200 {
				t.Fatalf("allow %d %s", res.StatusCode, b)
			}
		}
		return env{app: app, bot: bot, evals: &evals, audit: auditPath}
	}
	mark := func(t *testing.T, out string) {
		t.Helper()
		if !strings.Contains(out, "data, not instructions") || strings.Contains(out, leak) {
			t.Fatalf("untrusted mark or leak: %s", out)
		}
	}
	auditOK := func(t *testing.T, path, action, decision string) {
		t.Helper()
		raw := readAudit(t, path)
		if strings.Contains(raw, leak) || !auditLine(raw, action, decision) {
			t.Fatalf("audit %s %s missing\n%s", action, decision, raw)
		}
	}

	t.Run("list allowed", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, []string{"acme/widgets"})
		before := hits.Load()
		out, err := e.app.dispatchTool(t.Context(), e.bot, "list_issues", map[string]any{"repo": "acme/widgets"})
		if err != nil {
			t.Fatal(err)
		}
		if e.evals.Load() != 0 || hits.Load() == before {
			t.Fatalf("evals %d hits %d", e.evals.Load(), hits.Load()-before)
		}
		mark(t, out)
		var got struct {
			Truncated bool `json:"truncated"`
			Issues    []struct {
				Number int    `json:"number"`
				Title  string `json:"title"`
			} `json:"issues"`
		}
		if json.Unmarshal([]byte(out), &got) != nil || got.Truncated || len(got.Issues) != 2 || got.Issues[0].Number != 1 || got.Issues[1].Number != 2 {
			t.Fatalf("list %s", out)
		}
		if strings.Contains(out, `"number":99`) {
			t.Fatalf("pull request listed: %s", out)
		}
		auditOK(t, e.audit, "github_list_issues", "allow")
	})

	t.Run("read issue allowed", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, []string{"acme/widgets"})
		out, err := e.app.dispatchTool(t.Context(), e.bot, "read_issue", map[string]any{"repo": "acme/widgets", "number": float64(7)})
		if err != nil {
			t.Fatal(err)
		}
		if e.evals.Load() != 0 {
			t.Fatal("read_issue opened a card")
		}
		mark(t, out)
		if !strings.Contains(out, "the list is blank") || !strings.Contains(out, "please fix") || !strings.Contains(out, "issuecomment-11") {
			t.Fatalf("issue %s", out)
		}
		auditOK(t, e.audit, "github_read_issue", "allow")
	})

	t.Run("read pr allowed", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, []string{"acme/widgets"})
		out, err := e.app.dispatchTool(t.Context(), e.bot, "read_pr", map[string]any{"repo": "acme/widgets", "number": float64(7)})
		if err != nil {
			t.Fatal(err)
		}
		if e.evals.Load() != 0 {
			t.Fatal("read_pr opened a card")
		}
		mark(t, out)
		for _, want := range []string{"Fixes the empty state.", "a.go", "+new", "CHANGES_REQUESTED", "rename the helper", "nit", `"conclusion":"success"`} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %q in %s", want, out)
			}
		}
		auditOK(t, e.audit, "github_read_pr", "allow")
	})

	refused := func(t *testing.T, tool string, args map[string]any) {
		t.Helper()
		mode.Store("ok")
		e := newEnv(t, []string{"acme/widgets"})
		beforeHits := hits.Load()
		beforeTok := tokenReads.Load()
		out, err := e.app.dispatchTool(t.Context(), e.bot, tool, args)
		if err == nil || !strings.Contains(err.Error(), "not allowlisted") || out != "" || strings.Contains(err.Error(), leak) {
			t.Fatalf("%s refused: %v %s", tool, err, out)
		}
		if hits.Load() != beforeHits || tokenReads.Load() != beforeTok || e.evals.Load() != 0 {
			t.Fatalf("%s refused made a call hits %d tokens %d evals %d", tool, hits.Load()-beforeHits, tokenReads.Load()-beforeTok, e.evals.Load())
		}
		raw := readAudit(t, e.audit)
		if !strings.Contains(raw, "allowlist") || strings.Contains(raw, leak) {
			t.Fatalf("audit %s", raw)
		}
	}
	t.Run("list refused", func(t *testing.T) {
		refused(t, "list_issues", map[string]any{"repo": "other/nope"})
	})
	t.Run("read issue refused", func(t *testing.T) {
		refused(t, "read_issue", map[string]any{"repo": "other/nope", "number": float64(7)})
	})
	t.Run("read pr refused", func(t *testing.T) {
		refused(t, "read_pr", map[string]any{"repo": "other/nope", "number": float64(7)})
	})

	t.Run("item cap and pages", func(t *testing.T) {
		mode.Store("many")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, []string{"acme/widgets"})
		mu.Lock()
		from := len(seen)
		mu.Unlock()
		out, err := e.app.dispatchTool(t.Context(), e.bot, "list_issues", map[string]any{"repo": "acme/widgets"})
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Truncated bool `json:"truncated"`
			Issues    []struct {
				Number int `json:"number"`
			} `json:"issues"`
		}
		if json.Unmarshal([]byte(out), &got) != nil || !got.Truncated || len(got.Issues) != 20 {
			t.Fatalf("capped list %d truncated %v %s", len(got.Issues), got.Truncated, out)
		}
		mu.Lock()
		pages := 0
		for _, h := range seen[from:] {
			if h.method == http.MethodGet && h.path == "/repos/acme/widgets/issues" {
				pages++
			}
		}
		mu.Unlock()
		if pages != 2 {
			t.Fatalf("pages %d", pages)
		}
		mark(t, out)
	})

	t.Run("comment cap", func(t *testing.T) {
		mode.Store("many")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, []string{"acme/widgets"})
		mu.Lock()
		from := len(seen)
		mu.Unlock()
		out, err := e.app.dispatchTool(t.Context(), e.bot, "read_issue", map[string]any{"repo": "acme/widgets", "number": float64(7)})
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Truncated bool  `json:"truncated"`
			Comments  []any `json:"comments"`
		}
		if json.Unmarshal([]byte(out), &got) != nil || !got.Truncated || len(got.Comments) != 20 {
			t.Fatalf("comments %d %v %s", len(got.Comments), got.Truncated, out)
		}
		mu.Lock()
		pages := 0
		for _, h := range seen[from:] {
			if h.method == http.MethodGet && h.path == "/repos/acme/widgets/issues/7/comments" {
				pages++
			}
		}
		mu.Unlock()
		if pages != 2 {
			t.Fatalf("comment pages %d", pages)
		}
	})

	t.Run("field cap", func(t *testing.T) {
		mode.Store("huge")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, []string{"acme/widgets"})
		out, err := e.app.dispatchTool(t.Context(), e.bot, "list_issues", map[string]any{"repo": "acme/widgets"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "Huge body") || strings.Contains(out, strings.Repeat("B", 1025)) || len(out) > 8192 || !strings.Contains(out, `"truncated":true`) {
			t.Fatalf("len %d truncated missing or oversized", len(out))
		}
		mark(t, out)
	})

	t.Run("byte cap", func(t *testing.T) {
		mode.Store("wide")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, []string{"acme/widgets"})
		out, err := e.app.dispatchTool(t.Context(), e.bot, "list_issues", map[string]any{"repo": "acme/widgets"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "Issue 1") || len(out) > 8192 || !strings.Contains(out, `"truncated":true`) {
			t.Fatalf("byte cap len %d", len(out))
		}
		mark(t, out)
	})

	t.Run("create issue approved", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, []string{"acme/widgets"})
		before := hits.Load()
		done := approveCard(e.app, e.bot.ID, "create_issue")
		out, err := e.app.dispatchTool(t.Context(), e.bot, "create_issue", map[string]any{
			"repo": "acme/widgets", "title": "Empty state", "body": "the list is blank",
		})
		if aerr := <-done; aerr != nil {
			t.Fatal(aerr)
		}
		if err != nil || e.evals.Load() == 0 || hits.Load() <= before {
			t.Fatalf("create %v evals %d %s", err, e.evals.Load(), out)
		}
		mark(t, out)
		if !strings.Contains(out, "https://github.com/acme/widgets/issues/4") || !strings.Contains(out, `"number":4`) {
			t.Fatalf("created %s", out)
		}
		mu.Lock()
		var posted string
		for i := len(seen) - 1; i >= 0; i-- {
			if seen[i].method == http.MethodPost && seen[i].path == "/repos/acme/widgets/issues" {
				posted = seen[i].body
				break
			}
		}
		mu.Unlock()
		if !strings.Contains(posted, `"title":"Empty state"`) || !strings.Contains(posted, `"body":"the list is blank"`) {
			t.Fatalf("posted %s", posted)
		}
		auditOK(t, e.audit, "github_issue_allowed", "allow")
	})

	t.Run("create comment approved", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, []string{"acme/widgets"})
		before := hits.Load()
		done := approveCard(e.app, e.bot.ID, "create_comment")
		out, err := e.app.dispatchTool(t.Context(), e.bot, "create_comment", map[string]any{
			"repo": "acme/widgets", "number": float64(7), "body": "Fixed in the latest commit.",
		})
		if aerr := <-done; aerr != nil {
			t.Fatal(aerr)
		}
		if err != nil || e.evals.Load() == 0 || hits.Load() <= before || !strings.Contains(out, "issuecomment-15") {
			t.Fatalf("comment %v evals %d %s", err, e.evals.Load(), out)
		}
		mark(t, out)
		auditOK(t, e.audit, "github_comment_allowed", "allow")
	})

	t.Run("create issue denied", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, []string{"acme/widgets"})
		before := hits.Load()
		done := denyCard(e.app, e.bot.ID, "create_issue")
		out, err := e.app.dispatchTool(t.Context(), e.bot, "create_issue", map[string]any{
			"repo": "acme/widgets", "title": "Nope",
		})
		if aerr := <-done; aerr != nil {
			t.Fatal(aerr)
		}
		if err == nil || !strings.Contains(err.Error(), "not approved") || hits.Load() != before || strings.Contains(out, "issues/4") {
			t.Fatalf("deny %v hits %d %s", err, hits.Load()-before, out)
		}
		auditOK(t, e.audit, "github_issue_denied", "deny")
	})

	t.Run("create comment denied", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, []string{"acme/widgets"})
		before := hits.Load()
		done := denyCard(e.app, e.bot.ID, "create_comment")
		_, err := e.app.dispatchTool(t.Context(), e.bot, "create_comment", map[string]any{
			"repo": "acme/widgets", "number": float64(7), "body": "no",
		})
		if aerr := <-done; aerr != nil {
			t.Fatal(aerr)
		}
		if err == nil || !strings.Contains(err.Error(), "not approved") || hits.Load() != before {
			t.Fatalf("deny comment %v hits %d", err, hits.Load()-before)
		}
		auditOK(t, e.audit, "github_comment_denied", "deny")
	})

	t.Run("create issue out of scope", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, []string{"acme/widgets"})
		before := hits.Load()
		beforeTok := tokenReads.Load()
		out, err := e.app.dispatchTool(t.Context(), e.bot, "create_issue", map[string]any{
			"repo": "other/nope", "title": "Nope",
		})
		if err == nil || !strings.Contains(err.Error(), "not allowlisted") || hits.Load() != before || tokenReads.Load() != beforeTok || e.evals.Load() != 0 {
			t.Fatalf("scope %v hits %d evals %d %s", err, hits.Load()-before, e.evals.Load(), out)
		}
	})

	t.Run("create comment out of scope", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, []string{"acme/widgets"})
		before := hits.Load()
		_, err := e.app.dispatchTool(t.Context(), e.bot, "create_comment", map[string]any{
			"repo": "other/nope", "number": float64(7), "body": "no",
		})
		if err == nil || !strings.Contains(err.Error(), "not allowlisted") || hits.Load() != before || e.evals.Load() != 0 {
			t.Fatalf("scope comment %v hits %d evals %d", err, hits.Load()-before, e.evals.Load())
		}
	})

	t.Run("broker unavailable", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, []string{"acme/widgets"})
		e.app.perm = nil
		before := hits.Load()
		out, err := e.app.dispatchTool(t.Context(), e.bot, "create_issue", map[string]any{
			"repo": "acme/widgets", "title": "Nope",
		})
		if err == nil || !strings.Contains(err.Error(), "approval unavailable") || hits.Load() != before || strings.Contains(out, "issues/") {
			t.Fatalf("broker %v hits %d %s", err, hits.Load()-before, out)
		}
		auditOK(t, e.audit, "github_issue_denied", "deny")
	})

	t.Run("broker timeout", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, []string{"acme/widgets"})
		e.app.editPol(func(p *policy.Policy) { p.PromptTimeout = 200 * time.Millisecond })
		before := hits.Load()
		out, err := e.app.dispatchTool(t.Context(), e.bot, "create_comment", map[string]any{
			"repo": "acme/widgets", "number": float64(7), "body": "too slow",
		})
		if err == nil || !strings.Contains(err.Error(), "approval unavailable") || hits.Load() != before {
			t.Fatalf("timeout %v hits %d %s", err, hits.Load()-before, out)
		}
	})

	t.Run("managed allow still asks", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, []string{"acme/widgets"})
		e.app.editPol(func(p *policy.Policy) { p.ToolAllow = []string{"create_issue"} })
		done := approveCard(e.app, e.bot.ID, "create_issue")
		_, err := e.app.dispatchTool(t.Context(), e.bot, "create_issue", map[string]any{
			"repo": "acme/widgets", "title": "Managed",
		})
		if aerr := <-done; aerr != nil {
			t.Fatal(aerr)
		}
		if err != nil || e.evals.Load() == 0 {
			t.Fatalf("managed allow skipped the card: %v evals %d", err, e.evals.Load())
		}
	})
}

func writeIssuePage(w http.ResponseWriter, page, per int, body string) {
	start := (page-1)*per + 1
	fmt.Fprint(w, "[")
	n := 0
	for num := start; num <= 25 && n < per; num++ {
		if n > 0 {
			fmt.Fprint(w, ",")
		}
		fmt.Fprintf(w, `{"number":%d,"title":"Issue %d","state":"open","body":%q,"html_url":"https://github.com/acme/widgets/issues/%d","user":{"login":"ada"}}`, num, num, body, num)
		n++
	}
	fmt.Fprint(w, "]")
}

func writeCommentPage(w http.ResponseWriter, page, per int) {
	start := (page-1)*per + 1
	fmt.Fprint(w, "[")
	n := 0
	for id := start; id <= 25 && n < per; id++ {
		if n > 0 {
			fmt.Fprint(w, ",")
		}
		fmt.Fprintf(w, `{"id":%d,"body":"c%d","html_url":"https://github.com/acme/widgets/issues/7#issuecomment-%d","user":{"login":"bea"}}`, id, id, id)
		n++
	}
	fmt.Fprint(w, "]")
}

func writeFilePage(w http.ResponseWriter, page, per int) {
	start := (page-1)*per + 1
	fmt.Fprint(w, "[")
	n := 0
	for i := start; i <= 25 && n < per; i++ {
		if n > 0 {
			fmt.Fprint(w, ",")
		}
		fmt.Fprintf(w, `{"filename":"f%d.go","status":"modified","additions":1,"deletions":0,"patch":"p"}`, i)
		n++
	}
	fmt.Fprint(w, "]")
}

func auditLine(raw, action, decision string) bool {
	for _, line := range strings.Split(raw, "\n") {
		if strings.Contains(line, `"`+action+`"`) && strings.Contains(line, `"`+decision+`"`) {
			return true
		}
	}
	return false
}

func denyCard(app *App, botID, tool string) <-chan error {
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
					errc <- fmt.Errorf("write proxy reachable before denial")
					return
				}
				if err := app.perm.DecideFor(botID, runID, id, permission.Deny); err != nil {
					errc <- err
				}
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
		errc <- fmt.Errorf("approval card did not appear")
	}()
	return errc
}
