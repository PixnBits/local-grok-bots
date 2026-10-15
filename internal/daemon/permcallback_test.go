package daemon

import (
	"net/http"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/config"
)

func tlsCfg(t *testing.T, addr string) config.Config {
	return config.Config{DataDir: t.TempDir(), BindAddr: "127.0.0.1:0", OllamaURL: "http://127.0.0.1:9",
		Model: "test-model", Version: "0.1.0", TLSSelfSigned: true, PermCallbackAddr: addr}
}

func TestPermCallbackRejectsNonLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "192.168.5.48:0", "localhost:0", ":0", "[::]:0", "nonsense"} {
		if _, err := New(tlsCfg(t, addr), nil); err == nil {
			t.Errorf("%s: startup should fail", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0"} {
		if err := checkLoopbackAddr(addr); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func TestPermCallbackServesOnlyPermissionRoute(t *testing.T) {
	app := newAppCfg(t, tlsCfg(t, ""))
	base := app.permBase
	if !strings.HasPrefix(base, "http://127.0.0.1:") {
		t.Fatalf("permBase %q", base)
	}
	n, err := app.st.LogCount("perm_callback_listen")
	if err != nil || n != 1 {
		t.Fatalf("listen log %d %v", n, err)
	}
	for _, c := range []struct{ method, path string }{
		{"GET", "/"}, {"GET", "/index.html"}, {"GET", "/bots/x"}, {"GET", "/login"},
		{"GET", "/api/health"}, {"GET", "/api/bots"}, {"POST", "/api/bots"},
		{"GET", "/api/stt/status"}, {"POST", "/api/stt"}, {"GET", "/api/log"},
		{"GET", "/api/mcp/permission"}, {"POST", "/api/mcp/permission/a/b"},
		{"POST", "/api/bots/b/runs/r/permissions/q"},
	} {
		req, _ := http.NewRequest(c.method, base+c.path, strings.NewReader("{}"))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", c.method, c.path, res.StatusCode)
		}
	}
	// The permission route is there and still demands the per-run token.
	for _, p := range []string{"/api/mcp/permission", "/api/mcp/permission/" + strings.Repeat("a", 64)} {
		res, err := http.Post(base+p, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s without a valid token = %d", p, res.StatusCode)
		}
	}
}

func TestNoTLSHasNoCallbackListener(t *testing.T) {
	cfg := tlsCfg(t, "")
	cfg.TLSSelfSigned = false
	cfg.BindAddr = "127.0.0.1:8787"
	app := newAppCfg(t, cfg)
	if app.permSrv != nil || app.permBase != "http://127.0.0.1:8787" {
		t.Fatalf("no-TLS: srv=%v base=%q", app.permSrv != nil, app.permBase)
	}
}
