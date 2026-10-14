package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func isolationApp(t *testing.T, backend, overrides string) (*App, string, store.Bot, string) {
	t.Helper()
	dir := t.TempDir()
	installCLIStub(t, dir, backend)
	argvLog := filepath.Join(dir, "argv.log")
	envLog := filepath.Join(dir, "env.log")
	t.Setenv("LGB_ARGV_LOG", argvLog)
	t.Setenv("LGB_ENV_LOG", envLog)
	t.Setenv("LGB_CLI_MODE", "ok")
	t.Setenv("ANTHROPIC_BASE_URL", "http://evil.example")
	t.Setenv("CLAUDE_CONFIG_DIR", "/elsewhere")
	t.Setenv("GROK_CONFIG", `{"x":1}`)
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	app := newApp(t, dir, nil)
	app.rtMu.Lock()
	app.policy = policy.Policy{
		Backend: backend, CLIPermitted: true, TimersEnabled: true, Idle: time.Hour,
		Imminent: 2 * time.Minute, ConflictPolicy: "refuse", CLIOverrides: overrides,
		CLIHome: policy.HomeIsolated, PermissionMode: "default",
	}
	app.rtMu.Unlock()
	bot, err := app.st.CreateBot("Iso", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	return app, dir, bot, envLog
}

func postAndWait(t *testing.T, app *App, botID string) store.Bot {
	t.Helper()
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots/"+botID+"/thread/messages", map[string]any{"content": "hi"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, botID, "")
	got, err := app.st.GetBot(botID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestCLIClaudeIsolatedLaunch(t *testing.T) {
	app, dir, bot, envLog := isolationApp(t, "claude", "")
	ws := filepath.Join(app.ws, "bots", bot.ID)
	_ = os.MkdirAll(filepath.Join(ws, ".claude"), 0o700)
	_ = os.WriteFile(filepath.Join(ws, ".claude", "settings.json"), []byte(`{"permissions":{"allow":["Bash"]}}`), 0o644)
	got := postAndWait(t, app, bot.ID)
	if got.LastRunStatus != "done" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	argv := readArgv(t, filepath.Join(dir, "argv.log"))
	for _, f := range []string{"--setting-sources=\n", "--strict-mcp-config\n", "--settings\n"} {
		if !strings.Contains(argv, f) {
			t.Fatalf("missing %q:\n%s", f, argv)
		}
	}
	env := readArgv(t, envLog)
	home := filepath.Join(filepath.Dir(app.ws), "cli", bot.ID, "home")
	for _, want := range []string{"HOME=" + home + "\n", "CLAUDE_CONFIG_DIR=" + filepath.Join(home, ".claude") + "\n", "ANTHROPIC_API_KEY=sk-test\n"} {
		if !strings.Contains(env, want) {
			t.Fatalf("missing %q in env:\n%s", want, env)
		}
	}
	for _, bad := range []string{"ANTHROPIC_BASE_URL", "/elsewhere", "GROK_CONFIG"} {
		if strings.Contains(env, bad) {
			t.Fatalf("%s leaked:\n%s", bad, env)
		}
	}
	events, err := app.st.ListLog(bot.ID, "cli_override", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, e := range events {
		if d := string(e.Detail); strings.Contains(d, ".claude/settings.json") && strings.Contains(d, `"ignore"`) {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("override not logged: %+v", events)
	}
}

func TestCLIOverrideRefuseFailsClosed(t *testing.T) {
	app, dir, bot, _ := isolationApp(t, "claude", policy.OverridesRefuse)
	ws := filepath.Join(app.ws, "bots", bot.ID)
	_ = os.MkdirAll(ws, 0o700)
	_ = os.WriteFile(filepath.Join(ws, ".mcp.json"), []byte(`{}`), 0o644)
	got := postAndWait(t, app, bot.ID)
	if got.LastRunStatus != "error" || !strings.Contains(got.LastRunError, "override refused: .mcp.json") {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	if _, err := os.Stat(filepath.Join(dir, "argv.log")); err == nil {
		t.Fatal("CLI ran despite refuse")
	}
}

func TestCLIGrokMCPJSONRefusedEvenWhenIgnoring(t *testing.T) {
	app, _, bot, envLog := isolationApp(t, "grok", "")
	ws := filepath.Join(app.ws, "bots", bot.ID)
	_ = os.MkdirAll(ws, 0o700)
	_ = os.WriteFile(filepath.Join(ws, "AGENTS.md"), []byte("x"), 0o644)
	got := postAndWait(t, app, bot.ID)
	env := readArgv(t, envLog)
	if !strings.Contains(env, "GROK_HOME=") || !strings.Contains(env, "GROK_CLAUDE_MCPS_ENABLED=false") || strings.Contains(env, "GROK_CONFIG=") {
		t.Fatalf("grok env:\n%s", env)
	}
	_ = got
	_ = os.WriteFile(filepath.Join(ws, ".mcp.json"), []byte(`{}`), 0o644)
	got = postAndWait(t, app, bot.ID)
	if got.LastRunStatus != "error" || !strings.Contains(got.LastRunError, ".mcp.json") || strings.Contains(got.LastRunError, "AGENTS.md") {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
}
