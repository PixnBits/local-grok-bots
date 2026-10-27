package daemon

import (
	"net/http"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/config"
)

func TestNonLoopbackHostGate(t *testing.T) {
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	app, err := New(config.Config{
		DataDir: dir, BindAddr: "192.0.2.10:9",
		OllamaURL: "http://127.0.0.1:9", Model: "test-model", Version: "0.1.0",
		AuthToken: "host-gate-token-host-gate-token", TLSSelfSigned: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	srv := serve(t, app)
	tok := app.cfg.AuthToken

	res, b := do(t, "GET", srv.URL+"/api/bots", nil, tok)
	if res.StatusCode != http.StatusForbidden || string(b) == "" {
		t.Fatalf("request host %d %s", res.StatusCode, b)
	}
	if res, b := do(t, "GET", srv.URL+"/api/health", nil, ""); res.StatusCode != http.StatusForbidden {
		t.Fatalf("health %d %s", res.StatusCode, b)
	}
	if res, b := do(t, "GET", srv.URL+"/login?token="+tok, nil, ""); res.StatusCode != http.StatusForbidden {
		t.Fatalf("login %d %s", res.StatusCode, b)
	}

	ok := func(path, host string, want int) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		if path != "/api/health" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("%s host %q got %d want %d", path, host, res.StatusCode, want)
		}
	}
	ok("/api/bots", "192.0.2.10:9", http.StatusOK)
	ok("/api/policy", "192.0.2.10:9", http.StatusOK)
	ok("/api/health", "192.0.2.10:9", http.StatusOK)
	ok("/api/bots", "192.0.2.10", http.StatusForbidden)
	ok("/api/bots", "other.example:9", http.StatusForbidden)
	ok("/api/stt/status", "192.0.2.10", http.StatusForbidden)

	loop := newApp(t, "", nil)
	loopSrv := serve(t, loop)
	req, err := http.NewRequest(http.MethodGet, loopSrv.URL+"/api/bots", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "other.example"
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("loopback host gate %d", res.StatusCode)
	}
}
