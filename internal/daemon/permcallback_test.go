package daemon

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func setClaudeMCP(app *App, transport string) {
	app.rtMu.Lock()
	app.policy.Backend = "claude"
	app.policy.CLIPermitted = true
	app.policy.ClaudeTransport = transport
	app.rtMu.Unlock()
}

func TestPermCallbackAbsentWithoutMCPBot(t *testing.T) {
	app := newApp(t, "", nil)
	setClaudeMCP(app, policy.TransportMCP)
	if err := app.syncPermCallback(); err != nil {
		t.Fatal(err)
	}
	if addr, on := app.permCallbackOn(); on {
		t.Fatalf("listened at %s with no bots", addr)
	}
	if _, err := app.st.CreateBot("Ada", "", nil, "user"); err != nil {
		t.Fatal(err)
	}
	app.rtMu.Lock()
	app.policy.Backend = "ollama"
	app.rtMu.Unlock()
	if err := app.syncPermCallback(); err != nil {
		t.Fatal(err)
	}
	if addr, on := app.permCallbackOn(); on {
		t.Fatalf("ollama bot listened at %s", addr)
	}
	setClaudeMCP(app, policy.TransportStreamControl)
	if err := app.syncPermCallback(); err != nil {
		t.Fatal(err)
	}
	if addr, on := app.permCallbackOn(); on {
		t.Fatalf("stream_control listened at %s", addr)
	}
}

func TestPermCallbackLoopbackWhenMCPBotExists(t *testing.T) {
	app := newApp(t, "", nil)
	setClaudeMCP(app, policy.TransportMCP)
	app.cfg.PermCallbackAddr = "127.0.0.1:0"
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Ada", "description": "d"}, "")
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	addr, on := app.permCallbackOn()
	if !on {
		t.Fatal("callback did not listen")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || ip.String() != "127.0.0.1" {
		t.Fatalf("bound %s", addr)
	}
	res, err = http.Get("http://" + addr + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("health on callback %d", res.StatusCode)
	}
	res, err = http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("index on callback %d", res.StatusCode)
	}
	if n, err := app.st.LogCount("perm_callback_listen"); err != nil || n != 1 {
		t.Fatalf("listen log %d %v", n, err)
	}

	var bot struct {
		ID string `json:"id"`
	}
	decodeJSON(t, b, &bot)
	res, _ = do(t, "DELETE", srv.URL+"/api/bots/"+bot.ID, nil, "")
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete %d", res.StatusCode)
	}
	if addr, on := app.permCallbackOn(); on {
		t.Fatalf("still listening at %s after delete", addr)
	}
}

func TestPermCallbackIPv6Loopback(t *testing.T) {
	app := newApp(t, "", nil)
	setClaudeMCP(app, policy.TransportMCP)
	app.cfg.PermCallbackAddr = "[::1]:0"
	if _, err := app.st.CreateBot("Ada", "", nil, "user"); err != nil {
		t.Fatal(err)
	}
	if err := app.syncPermCallback(); err != nil {
		t.Fatal(err)
	}
	addr, on := app.permCallbackOn()
	if !on || !strings.HasPrefix(addr, "[::1]:") {
		t.Fatalf("bound %s on %v", addr, on)
	}
}

func TestPermCallbackFollowsPolicyReload(t *testing.T) {
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.toml")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("[backend]\nbackend = \"ollama\"\n")
	app, err := New(config.Config{
		DataDir: dir, BindAddr: "127.0.0.1:0", OllamaURL: "http://127.0.0.1:9",
		Model: "test-model", Version: "0.1.0", PolicyPath: path, AuthToken: "perm-test-token",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	app.noGrokProxy = true
	t.Cleanup(app.Shutdown)
	if _, err := app.st.CreateBot("Ada", "", nil, "user"); err != nil {
		t.Fatal(err)
	}
	if addr, on := app.permCallbackOn(); on {
		t.Fatalf("listened at %s before reload", addr)
	}
	write("[backend]\nbackend = \"claude\"\n")
	if _, err := app.policyNow(); err != nil {
		t.Fatal(err)
	}
	if _, on := app.permCallbackOn(); !on {
		t.Fatal("callback did not listen")
	}
	write("[backend]\nbackend = \"ollama\"\n")
	if _, err := app.policyNow(); err != nil {
		t.Fatal(err)
	}
	if addr, on := app.permCallbackOn(); on {
		t.Fatalf("still listening at %s", addr)
	}
}

func TestPermCallbackRejectsWildcard(t *testing.T) {
	app := newApp(t, "", nil)
	setClaudeMCP(app, policy.TransportMCP)
	app.cfg.PermCallbackAddr = "0.0.0.0:0"
	if _, err := app.st.CreateBot("Ada", "", nil, "user"); err != nil {
		t.Fatal(err)
	}
	if err := app.syncPermCallback(); err == nil {
		t.Fatal("wildcard bind was accepted")
	}
	if addr, on := app.permCallbackOn(); on {
		t.Fatalf("listened at %s", addr)
	}
}
