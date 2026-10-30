package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/permbroker"
)

func splitRoute(pattern string) (string, string) {
	method, path, ok := strings.Cut(pattern, " ")
	if !ok {
		return http.MethodGet, pattern
	}
	path = strings.ReplaceAll(path, "{id}", "x")
	path = strings.ReplaceAll(path, "{run_id}", "run")
	path = strings.ReplaceAll(path, "{req_id}", "req")
	path = strings.ReplaceAll(path, "{rule_id}", "rule")
	path = strings.ReplaceAll(path, "{sug_id}", "sug")
	return method, path
}

func callApp(h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, "http://127.0.0.1"+path, strings.NewReader(`{}`))
	req.Host = "127.0.0.1"
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	h.ServeHTTP(rec, req)
	return rec
}

func TestGolden_BrokerAuthIsTheRoute(t *testing.T) {
	app := newApp(t, "", nil)
	h := app.Handler()
	if len(app.adminPatterns) == 0 {
		t.Fatal("no admin routes")
	}
	for _, pattern := range app.adminPatterns {
		method, path := splitRoute(pattern)
		rec := callApp(h, method, path, "")
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin token required") {
			t.Fatalf("open %s %d %s", pattern, rec.Code, rec.Body.String())
		}
	}
	for _, pattern := range app.permPatterns {
		method, path := splitRoute(pattern)
		rec := callApp(h, method, path, "")
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin token required") {
			t.Fatalf("perm %s %d %s", pattern, rec.Code, rec.Body.String())
		}
	}
	odd := []string{"/api/permbroker%2Fpending", "//api/permbroker/pending", "/api/permbroker/./pending"}
	for _, p := range odd {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/permbroker/pending", nil)
		req.URL.Path = p
		req.URL.RawPath = p
		req.Host = "127.0.0.1"
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK && !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("%s reached a broker handler %s", p, rec.Body.String())
		}
		switch rec.Code {
		case http.StatusOK, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusTemporaryRedirect, http.StatusMovedPermanently, http.StatusFound, http.StatusPermanentRedirect:
		default:
			t.Fatalf("%s %d", p, rec.Code)
		}
	}
	const token = "lgbr_admintesttokenvalue"
	app.cfg.AuthToken = token
	for _, pattern := range app.adminPatterns {
		method, path := splitRoute(pattern)
		rec := callApp(h, method, path, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("no cred %s %d %s", pattern, rec.Code, rec.Body.String())
		}
		app.noteRunToken("lgbr_testtokenvalue", "bot", "run")
		rec = callApp(h, method, path, "lgbr_testtokenvalue")
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "unauthorized") || !strings.Contains(rec.Body.String(), "run token cannot decide permissions") {
			t.Fatalf("run %s %d %s", pattern, rec.Code, rec.Body.String())
		}
	}
	for _, p := range odd {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/permbroker/pending", nil)
		req.URL.Path = p
		req.URL.RawPath = p
		req.Host = "127.0.0.1"
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Fatalf("authed odd %s %s", p, rec.Body.String())
		}
		if strings.Contains(rec.Header().Get("Content-Type"), "json") && strings.Contains(rec.Body.String(), `"pending"`) {
			t.Fatalf("authed odd %s returned broker json", p)
		}
	}
	_ = token
}

func TestGolden_BrokerUIRoutes(t *testing.T) {
	app := newApp(t, "", nil)
	srv := serve(t, app)
	const token = "lgbr_admintesttokenvalue"
	app.cfg.AuthToken = token
	bot, err := app.st.CreateBot("Ada", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ws := t.TempDir()
	app.broker.NoteUserText(bot.ID, "task", "check status please")
	pending := app.broker.Evaluate(ctx, shellEval(bot.ID, ws, "git status"))
	if pending.PendingID == "" {
		t.Fatal(pending)
	}

	noAuth := func(method, path string) {
		t.Helper()
		res, body := do(t, method, srv.URL+path, map[string]any{}, "")
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("no token %s %s %d %s", method, path, res.StatusCode, body)
		}
		app.noteRunToken("lgbr_testtokenvalue", bot.ID, "run")
		res, body = do(t, method, srv.URL+path, map[string]any{}, "lgbr_testtokenvalue")
		if res.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "run token cannot decide permissions") {
			t.Fatalf("run token %s %s %d %s", method, path, res.StatusCode, body)
		}
	}

	noAuth("GET", "/api/permbroker/pending")
	res, body := do(t, "GET", srv.URL+"/api/permbroker/pending", nil, token)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"bot_name":"Ada"`) || !strings.Contains(string(body), `"task_text":"check status please"`) || !strings.Contains(string(body), `"allowed_scopes"`) || !strings.Contains(string(body), `"critical_reason"`) || !strings.Contains(string(body), `"suggest_always"`) {
		t.Fatalf("pending %d %s", res.StatusCode, body)
	}

	noAuth("POST", "/api/permbroker/pending/"+pending.PendingID)
	res, body = do(t, "POST", srv.URL+"/api/permbroker/pending/"+pending.PendingID, map[string]any{"decision": "approve", "scope": "task"}, token)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("task scope %d %s", res.StatusCode, body)
	}
	if d := app.broker.Evaluate(ctx, shellEval(bot.ID, ws, "git status")); d.Verdict != permbroker.VerdictAllow {
		t.Fatalf("task grant %+v", d)
	}

	noAuth("GET", "/api/permbroker/rules")
	res, body = do(t, "GET", srv.URL+"/api/permbroker/rules", nil, token)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"task_grants"`) {
		t.Fatalf("rules %d %s", res.StatusCode, body)
	}

	noAuth("POST", "/api/permbroker/rules")
	res, body = do(t, "POST", srv.URL+"/api/permbroker/rules", map[string]any{
		"kind": "exact", "argv": []string{"git", "status;"}, "scope": "bot", "bot_id": bot.ID, "effect": "allow",
	}, token)
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), `"code":"operators"`) {
		t.Fatalf("operators %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", srv.URL+"/api/permbroker/rules", map[string]any{
		"kind": "pattern", "pattern": "git diff *", "scope": "bot", "bot_id": bot.ID, "effect": "allow",
	}, token)
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), `"code":"trailing_wildcard"`) {
		t.Fatalf("pattern %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", srv.URL+"/api/permbroker/rules", map[string]any{
		"kind": "exact", "argv": []string{"git", "diff"}, "scope": "bot", "bot_id": bot.ID, "effect": "ask",
	}, token)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create %d %s", res.StatusCode, body)
	}

	noAuth("POST", "/api/permbroker/patterns/validate")
	res, body = do(t, "POST", srv.URL+"/api/permbroker/patterns/validate", map[string]any{"pattern": "bash -c echo"}, token)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"ok":false`) || !strings.Contains(string(body), `"code":"wrapper"`) {
		t.Fatalf("validate %d %s", res.StatusCode, body)
	}
	noAuth("GET", "/api/permbroker/patterns/wrappers")
	res, body = do(t, "GET", srv.URL+"/api/permbroker/patterns/wrappers", nil, token)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"bash"`) {
		t.Fatalf("wrappers %d %s", res.StatusCode, body)
	}

	_ = app.broker.Evaluate(ctx, shellEval(bot.ID, ws, "git diff"))
	noAuth("POST", "/api/permbroker/patterns/preview")
	res, body = do(t, "POST", srv.URL+"/api/permbroker/patterns/preview", map[string]any{
		"kind": "exact", "argv": []string{"git", "status"}, "scope": "bot", "bot_id": bot.ID, "effect": "allow",
	}, token)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"summary"`) || !strings.Contains(string(body), "would_allow") && !strings.Contains(string(body), "no_match") {
		t.Fatalf("preview %d %s", res.StatusCode, body)
	}
	var prev struct {
		Summary map[string]int `json:"summary"`
	}
	if err := json.Unmarshal(body, &prev); err != nil || prev.Summary["would_allow"] < 1 {
		t.Fatalf("preview summary %s %v", body, err)
	}

	noAuth("GET", "/api/permbroker/risk-tables")
	res, body = do(t, "GET", srv.URL+"/api/permbroker/risk-tables", nil, token)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"version"`) || !strings.Contains(string(body), `"builtin"`) || !strings.Contains(string(body), `"stricter"`) {
		t.Fatalf("tables %d %s", res.StatusCode, body)
	}

	noAuth("GET", "/api/permbroker/recent")
	res, body = do(t, "GET", srv.URL+"/api/permbroker/recent", nil, token)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), "allowed_by_task_grant") {
		t.Fatalf("recent %d %s", res.StatusCode, body)
	}
}
