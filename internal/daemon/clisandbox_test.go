package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestClaudeSandboxUnavailableFailsClosed(t *testing.T) {
	old := claudeSandboxMissing
	claudeSandboxMissing = func() []string { return []string{"socat"} }
	t.Cleanup(func() { claudeSandboxMissing = old })
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	ws := filepath.Join(dir, "ws")
	_ = os.MkdirAll(ws, 0o755)
	_, err := app.cliIsolation(store.Bot{ID: "b1"}, "claude", ws)
	if err == nil || !strings.Contains(err.Error(), "missing socat") || !strings.Contains(err.Error(), "claude_sandbox") {
		t.Fatalf("want fail-closed sandbox error, got %v", err)
	}
	srv := serve(t, app)
	_, b := do(t, "GET", srv.URL+"/api/log?kind=cli_sandbox_unavailable&limit=10", nil, app.cfg.AuthToken)
	var events []store.LogEvent
	decodeJSON(t, b, &events)
	if len(events) != 1 {
		t.Fatalf("log events %s", b)
	}
	// Grok is unaffected.
	if _, err := app.cliIsolation(store.Bot{ID: "b1"}, "grok", ws); err != nil {
		t.Fatal(err)
	}
}

func TestClaudeSandboxManagedOffSkipsCheckAndBlock(t *testing.T) {
	old := claudeSandboxMissing
	claudeSandboxMissing = func() []string { return []string{"bwrap", "socat"} }
	t.Cleanup(func() { claudeSandboxMissing = old })
	dir := t.TempDir()
	managed := filepath.Join(dir, "managed.json")
	_ = os.WriteFile(managed, []byte(`{"cli":{"isolation":{"claude_sandbox":"off"}}}`), 0o644)
	t.Setenv("MANAGED_POLICY", managed)
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	ws := filepath.Join(dir, "ws")
	_ = os.MkdirAll(ws, 0o755)
	iso, err := app.cliIsolation(store.Bot{ID: "b1", Grants: []string{"net"}, NetAllow: []string{"pypi.org"}}, "claude", ws)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(iso.SettingsPath)
	var doc map[string]any
	_ = json.Unmarshal(b, &doc)
	if _, ok := doc["sandbox"]; ok || iso.ClaudeSandbox {
		t.Fatalf("sandbox block with managed off: %s", b)
	}
	if strings.Contains(string(b), `"WebFetch"`) {
		t.Fatalf("net grant still denies WebFetch: %s", b)
	}
	if !strings.Contains(string(b), filepath.Join(dir, adminTokenFile)) {
		t.Fatalf("admin token not denied to Claude tools: %s", b)
	}
}
