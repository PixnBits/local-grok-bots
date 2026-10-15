package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/policy"
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

func TestGrokUserHomeUsesFailClosedProfile(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	_ = os.MkdirAll(filepath.Join(home, ".grok"), 0o700)
	_ = os.WriteFile(filepath.Join(home, ".grok", "auth.json"), []byte("{}"), 0o600)
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	app.rtMu.Lock()
	app.policy.CLIHome = policy.HomeUser
	app.rtMu.Unlock()
	ws := filepath.Join(dir, "ws")
	_ = os.MkdirAll(ws, 0o755)
	iso, err := app.cliIsolation(store.Bot{ID: "b1"}, "grok", ws)
	if err != nil {
		t.Fatal(err)
	}
	if iso.GrokSandbox != clisession.GrokProfile {
		t.Fatalf("profile %q", iso.GrokSandbox)
	}
	grokHome := filepath.Join(filepath.Dir(app.ws), "cli", "b1", "grok-home")
	env := strings.Join(iso.Env, "\n")
	if !strings.Contains(env, "HOME="+home+"\n") || !strings.Contains(env, "GROK_HOME="+grokHome+"\n") {
		t.Fatalf("env:\n%s", env)
	}
	if _, err := os.Stat(filepath.Join(home, ".grok", "sandbox.toml")); err == nil {
		t.Fatal("wrote the user's sandbox.toml")
	}
	b, err := os.ReadFile(filepath.Join(grokHome, "sandbox.toml"))
	if err != nil || !strings.Contains(string(b), "[profiles.lgb]") {
		t.Fatalf("profile file: %s %v", b, err)
	}
	argv, err := clisession.Args(clisession.Spec{Backend: "grok", Prompt: "hi", Workspace: ws, Isolate: iso})
	if err != nil || !strings.Contains(strings.Join(argv, " "), "--sandbox lgb") {
		t.Fatalf("argv %v %v", argv, err)
	}
}

type sandboxFailRunner struct{}

func (sandboxFailRunner) Run(context.Context, clisession.Spec, func(clisession.Event)) (clisession.Result, error) {
	return clisession.Result{}, fmt.Errorf("sandbox profile lgb could not be applied")
}

func TestGrokSandboxFailureIsAudited(t *testing.T) {
	dir := t.TempDir()
	app := newApp(t, dir, nil)
	logPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	app.runner = sandboxFailRunner{}
	app.rtMu.Lock()
	app.policy = policy.Policy{Backend: "grok", CLIPermitted: true, TimersEnabled: true, Idle: time.Hour, Imminent: time.Minute}
	app.rtMu.Unlock()
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Geo", "description": "g"}, "")
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{"content": "go"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, "")
	got, err := app.st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastRunStatus != "error" || !strings.Contains(got.LastRunError, "Grok's sandbox is required") {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	evs, err := app.st.ListLog(bot.ID, "cli_sandbox_unavailable", "", 10)
	if err != nil || len(evs) != 1 || !strings.Contains(string(evs[0].Detail), `"backend":"grok"`) {
		t.Fatalf("log %v %v", evs, err)
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(raw), `"event":"cli_sandbox_unavailable"`) || !strings.Contains(string(raw), `"backend":"grok"`) {
		t.Fatalf("audit %s %v", raw, err)
	}
}

func TestCLIPreambleStatesTheRealBoundary(t *testing.T) {
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	got := app.cliBoundary()
	for _, want := range []string{"Claude Code's sandbox", "not inside the daemon's jail", "run_shell"} {
		if !strings.Contains(got, want) {
			t.Fatalf("claude boundary lacks %q: %s", want, got)
		}
	}
	if strings.Contains(got, "your own sandbox is the boundary") {
		t.Fatalf("old wording: %s", got)
	}
	app.policy.Backend = "grok"
	if g := app.cliBoundary(); !strings.Contains(g, "Grok's sandbox") {
		t.Fatalf("grok boundary: %s", g)
	}
}
