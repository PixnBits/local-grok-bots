package daemon

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// TestLiveCLISmoke is the one-shot live check for a Framework Desktop or a Mac.
// Ordinary unit tests skip it. See experiment/cli-backend-policy/README.md.
func TestLiveCLISmoke(t *testing.T) {
	if os.Getenv("LGB_LIVE_CLI") != "1" {
		t.Skip("set LGB_LIVE_CLI=1 to send one live CLI prompt")
	}
	path := os.Getenv("POLICY_PATH")
	if path == "" {
		path = "policy.toml"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("policy file %s is not available", path)
	}
	pol, err := policy.Load(policy.Options{
		Path:        path,
		ManagedPath: os.Getenv("MANAGED_POLICY"),
	})
	if err != nil {
		t.Fatal(err)
	}
	backend := pol.EffectiveBackend()
	if backend != "claude" && backend != "grok" {
		t.Skipf("policy selects %s, not claude or grok", backend)
	}
	if _, err := exec.LookPath(backend); err != nil {
		t.Skipf("%s is not on PATH", backend)
	}

	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	app, err := New(config.Config{
		DataDir: dir, BindAddr: "127.0.0.1:0",
		OllamaURL: "http://127.0.0.1:9", Model: "live", Version: "live",
		PolicyPath: path,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	if app.policy.DaemonJail || !app.policy.UsesCLI() {
		t.Fatalf("CLI turn would use the daemon jail: backend %s jail %v", app.policy.EffectiveBackend(), app.policy.DaemonJail)
	}
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Smoke", "description": "live"}, "")
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{
		"content": "Reply with exactly the word pong. Do not use tools.",
	}, "")
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	waitIdleFor(t, srv.URL, bot.ID, 3*time.Minute)
	got, err := app.st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID == "" {
		t.Fatal("session id was not stored")
	}
	if got.LastRunStatus != "done" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	msgs, err := app.st.ListMessages(bot.ID, "user", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	var reply string
	for _, m := range msgs {
		if m.Role == "bot" && m.Content != "" {
			reply = m.Content
		}
	}
	if reply == "" {
		t.Fatal("stream did not store a reply")
	}
	t.Logf("session %s reply %q", got.SessionID, reply)
}

// TestLiveClaudeStreamControl is the live check for claude_transport
// stream_control. It skips when claude is not on PATH, and unless
// LGB_LIVE_CLI=1, so go test ./... does not call a live model.
func TestLiveClaudeStreamControl(t *testing.T) {
	if _, err := exec.LookPath("claude"); err != nil {
		t.Skip("claude is not on PATH")
	}
	if os.Getenv("LGB_LIVE_CLI") != "1" {
		t.Skip("set LGB_LIVE_CLI=1 to send one live stream-control prompt")
	}
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	app, err := New(config.Config{
		DataDir: dir, BindAddr: "127.0.0.1:0",
		OllamaURL: "http://127.0.0.1:9", Model: "live", Version: "live",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	app.rtMu.Lock()
	app.policy.Backend = "claude"
	app.policy.CLIPermitted = true
	app.policy.DaemonJail = false
	app.policy.ClaudeTransport = policy.TransportStreamControl
	app.policy.UIPrompts = false
	app.policy.Allow = nil
	app.rtMu.Unlock()
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Smoke", "description": "live"}, "")
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{
		"content": "Reply with exactly the word pong. Do not use tools.",
	}, "")
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	waitIdleFor(t, srv.URL, bot.ID, 3*time.Minute)
	got, err := app.st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID == "" {
		t.Fatal("session id was not stored")
	}
	if got.LastRunStatus != "done" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
}

func waitIdleFor(t *testing.T, base, id string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		res, b := do(t, "GET", base+"/api/bots/"+id, nil, "")
		if res.StatusCode != 200 {
			t.Fatalf("status %d %s", res.StatusCode, b)
		}
		var bot store.Bot
		decodeJSON(t, b, &bot)
		if bot.Status != "running" {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("bot stayed running")
}
