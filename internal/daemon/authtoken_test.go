package daemon

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOllamaOnlyNeedsNoToken(t *testing.T) {
	app := newApp(t, "", nil)
	if app.cfg.AuthToken != "" {
		t.Fatalf("ollama-only got a token")
	}
	if _, err := os.Stat(filepath.Join(app.cfg.DataDir, adminTokenFile)); err == nil {
		t.Fatalf("ollama-only wrote a token file")
	}
	srv := serve(t, app)
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, ""); res.StatusCode != 200 {
		t.Fatalf("ollama-only list %d", res.StatusCode)
	}
}

func TestCLIBackendRequiresGeneratedToken(t *testing.T) {
	t.Setenv("AUTH_TOKEN", "")
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	tok := app.cfg.AuthToken
	path := filepath.Join(dir, adminTokenFile)
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 || len(tok) != 64 {
		t.Fatalf("token file %v %v len %d", err, st, len(tok))
	}
	srv := serve(t, app)
	if res, _ := do(t, "GET", srv.URL+"/api/health", nil, ""); res.StatusCode != 200 {
		t.Fatalf("health %d", res.StatusCode)
	}
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, ""); res.StatusCode != 401 {
		t.Fatalf("no token %d", res.StatusCode)
	}
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, tok); res.StatusCode != 200 {
		t.Fatalf("bearer %d", res.StatusCode)
	}
	// A CLI on this host has no token, so it can't decide its own requests.
	if res, _ := do(t, "POST", srv.URL+"/api/bots/b/runs/r/permissions/q", map[string]string{"decision": "allow_once"}, ""); res.StatusCode != 401 {
		t.Fatalf("decision without token %d", res.StatusCode)
	}
	if res, _ := do(t, "GET", srv.URL+"/login?token=wrong", nil, ""); res.StatusCode != 401 {
		t.Fatalf("bad login %d", res.StatusCode)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(srv.URL + "/login?token=" + tok)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == authCookie {
			cookie = c
		}
	}
	if res.StatusCode != http.StatusSeeOther || cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("login %d cookie %+v", res.StatusCode, cookie)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/api/bots", nil)
	req.AddCookie(cookie)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("cookie %d", res.StatusCode)
	}

	// The same token is reused on restart.
	app.Shutdown()
	app2 := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	if app2.cfg.AuthToken != tok {
		t.Fatalf("token changed on restart")
	}
}

func TestExplicitAuthTokenWins(t *testing.T) {
	dir := t.TempDir()
	cfgTok := "explicit-token-explicit-token-explicit"
	tok, path, err := ensureAdminToken(dir, cfgTok, true)
	if err != nil || tok != cfgTok || path != "" {
		t.Fatalf("%q %q %v", tok, path, err)
	}
	if _, err := os.Stat(filepath.Join(dir, adminTokenFile)); err == nil {
		t.Fatalf("wrote a file despite AUTH_TOKEN")
	}
}

func TestCLIEnvNeverCarriesAdminToken(t *testing.T) {
	t.Setenv("AUTH_TOKEN", "")
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	tok := app.cfg.AuthToken
	t.Setenv("AUTH_TOKEN", tok)
	t.Setenv("LGB_TOKEN_COPY", "x"+tok)
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"claude", "grok"} {
		iso, err := app.cliIsolation("bot1", backend, ws)
		if err != nil {
			t.Fatal(err)
		}
		for _, kv := range iso.Env {
			if strings.HasPrefix(kv, "AUTH_TOKEN=") || strings.Contains(kv, tok) {
				t.Fatalf("%s env leaks token: %s", backend, kv)
			}
		}
	}
}
