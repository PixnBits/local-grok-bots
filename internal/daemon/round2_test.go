package daemon

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/permbroker"
)

func TestGolden_PermRoutesCrossPortOrigin(t *testing.T) {
	app := newApp(t, "", nil)
	srv := serve(t, app)
	tok := armAdmin(app)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	other := "1"
	if port == "1" {
		other = "2"
	}
	origin := "http://127.0.0.1:" + other
	routes := []struct{ method, path string }{
		{"POST", "/api/bots/b1/runs/r1/permissions/q1"},
		{"POST", "/api/bots/b1/permission-rules"},
		{"DELETE", "/api/bots/b1/permission-rules/r1"},
		{"POST", "/api/bots/b1/permission-suggestions/analyze"},
		{"POST", "/api/bots/b1/permission-suggestions/s1/accept"},
		{"POST", "/api/bots/b1/permission-suggestions/s1/dismiss"},
	}
	for _, rt := range routes {
		req, err := http.NewRequest(rt.method, srv.URL+rt.path, strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = req.URL.Host
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Origin", origin)
		req.Header.Set("Sec-Fetch-Site", "same-site")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("%s %s %d", rt.method, rt.path, res.StatusCode)
		}
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/bots/b1/permission-rules", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = req.URL.Host
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty body %d", res.StatusCode)
	}
	req, err = http.NewRequest(http.MethodPost, srv.URL+"/api/bots/b1/permission-rules", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = req.URL.Host
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("content type %d", res.StatusCode)
	}
}

func TestGolden_PageCSP(t *testing.T) {
	app := newApp(t, "", nil)
	srv := serve(t, app)
	for _, path := range []string{"/", "/rules", "/login", "/index.html", "/app.js", "/app.css", "/theme.js"} {
		res, body := do(t, "GET", srv.URL+path, nil, "")
		if res.Header.Get("Content-Security-Policy") != cspValue || res.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s csp %q nosniff %q", path, res.Header.Get("Content-Security-Policy"), res.Header.Get("X-Content-Type-Options"))
		}
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s %d %s", path, res.StatusCode, body)
		}
	}
	if ct := func() string {
		res, _ := do(t, "GET", srv.URL+"/app.js", nil, "")
		return res.Header.Get("Content-Type")
	}(); !strings.Contains(ct, "javascript") {
		t.Fatalf("app.js %s", ct)
	}
	armAdmin(app)
	res, body := do(t, "GET", srv.URL+"/", nil, "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("signed out %d %s", res.StatusCode, body)
	}
	if res.Header.Get("Content-Security-Policy") != cspValue || res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("401 csp %q", res.Header.Get("Content-Security-Policy"))
	}
	res, _ = do(t, "GET", srv.URL+"/api/health", nil, "")
	if res.Header.Get("Content-Security-Policy") != cspValue || res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("health headers")
	}
}

func TestGolden_ReplaceRuleHTTPKeepsBoth(t *testing.T) {
	app := newApp(t, "", nil)
	srv := serve(t, app)
	tok := armAdmin(app)
	old, err := app.broker.SaveRule(permbroker.Rule{
		Effect: permbroker.EffectAllow, Argv: []string{"git", "status"},
		Tool: permbroker.ToolShell, Scope: permbroker.ScopeBot, BotID: "bot",
	})
	if err != nil {
		t.Fatal(err)
	}
	app.broker.SetRevokeFailure(errors.New("revoke failed"))
	res, body := do(t, "POST", srv.URL+"/api/permbroker/rules/"+old.ID+"/replace", map[string]any{
		"kind": "exact", "argv": []string{"git", "diff"}, "scope": "bot", "bot_id": "bot", "effect": "allow",
	}, tok)
	if res.StatusCode != http.StatusMultiStatus || !strings.Contains(string(body), `"revoked":false`) || !strings.Contains(string(body), "revoke failed") {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	if app.broker.RuleCount() != 2 {
		t.Fatalf("rules %d", app.broker.RuleCount())
	}
}
