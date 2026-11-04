package daemon

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func apiError(t *testing.T, b []byte) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	decodeJSON(t, b, &body)
	return body.Error
}

func TestBotLimitsAPIAcceptRejectAndJSON(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	srv := serve(t, app)

	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada", "description": "stay",
		"run_timeout": "5m", "shell_timeout": "10s", "tool_rounds": 3,
	}, "")
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	if bot.RunTimeout.Duration() != 5*time.Minute || bot.ShellTimeout.Duration() != 10*time.Second || bot.ToolRounds != 3 {
		t.Fatalf("stored %#v", bot)
	}
	if bot.Limits == nil || bot.Limits.RunTimeout.Value != "5m" || bot.Limits.RunTimeout.Source != "bot" || bot.Limits.RunTimeout.Ceiling != "10m" || bot.Limits.RunTimeout.CeilingSource != "the built-in default" || bot.Limits.RunTimeout.CeilingKey != "" {
		t.Fatalf("limits %#v", bot.Limits)
	}
	if bot.Limits.ToolRounds.Value != 3 || bot.Limits.ToolRounds.Source != "bot" || bot.Limits.ToolRounds.Ceiling != 8 {
		t.Fatalf("rounds limits %#v", bot.Limits.ToolRounds)
	}
	if bot.Limits.ShellTimeout.Value != "10s" || bot.Limits.ShellTimeout.Source != "bot" || bot.Limits.ShellTimeout.Ceiling != "30s" {
		t.Fatalf("shell limits %#v", bot.Limits.ShellTimeout)
	}

	res, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("get %d %s", res.StatusCode, b)
	}
	decodeJSON(t, b, &bot)
	if bot.Limits == nil || bot.Limits.RunTimeout.Source != "bot" {
		t.Fatalf("get limits %#v", bot.Limits)
	}

	res, b = do(t, "GET", srv.URL+"/api/bots", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("list %d %s", res.StatusCode, b)
	}
	var listed []store.Bot
	decodeJSON(t, b, &listed)
	var found bool
	for _, item := range listed {
		if item.ID == bot.ID && item.Limits != nil && item.Limits.ToolRounds.Value == 3 {
			found = true
		}
	}
	if !found {
		t.Fatalf("list missing limits %#v", listed)
	}

	res, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/state", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("state %d %s", res.StatusCode, b)
	}
	var st botState
	decodeJSON(t, b, &st)
	if st.Limits == nil || st.Limits.ShellTimeout.Value != "10s" || st.Limits.ShellTimeout.Source != "bot" {
		t.Fatalf("state limits %#v", st.Limits)
	}

	name := bot.Name
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{
		"name": "Ada Lovelace", "shell_timeout": "20m",
	}, "")
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("above ceiling %d %s", res.StatusCode, b)
	}
	errText := apiError(t, b)
	if errText != "Shell timeout can be at most 30s. Enter 30s or less, or leave it blank." {
		t.Fatalf("reject message %q", errText)
	}
	got := fetchBot(t, srv.URL, bot.ID)
	if got.Name != name || got.ShellTimeout.Duration() != 10*time.Second {
		t.Fatalf("rejected patch saved %#v", got)
	}

	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"run_timeout": "nope"}, "")
	if res.StatusCode != 400 || apiError(t, b) != "Enter a time like 90s, 5m or 1h." {
		t.Fatalf("malformed %d %s", res.StatusCode, b)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"run_timeout": "0s"}, "")
	if res.StatusCode != 400 || apiError(t, b) != "Enter a time like 90s, 5m or 1h." {
		t.Fatalf("zero %d %s", res.StatusCode, b)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"tool_rounds": -1}, "")
	if res.StatusCode != 400 || apiError(t, b) != "Enter a whole number from 1 to 8." {
		t.Fatalf("neg rounds %d %s", res.StatusCode, b)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"tool_rounds": 20}, "")
	if res.StatusCode != 400 || apiError(t, b) != "Tool rounds can be at most 8. Enter 8 or less, or leave it blank." {
		t.Fatalf("rounds ceiling %d %s", res.StatusCode, b)
	}

	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{
		"run_timeout": "", "shell_timeout": nil, "tool_rounds": 0,
	}, "")
	if res.StatusCode != 200 {
		t.Fatalf("clear %d %s", res.StatusCode, b)
	}
	decodeJSON(t, b, &bot)
	if bot.RunTimeout != 0 || bot.ShellTimeout != 0 || bot.ToolRounds != 0 {
		t.Fatalf("cleared stored %#v", bot)
	}
	if bot.Limits == nil || bot.Limits.RunTimeout.Source != "policy" || bot.Limits.RunTimeout.Value != "10m" {
		t.Fatalf("cleared limits %#v", bot.Limits)
	}
}

func TestBotLimitsLoweredPolicyClamps(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Bea", "description": "stay", "run_timeout": "5m", "tool_rounds": 6,
	}, "")
	if res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	setPolicy(app, func(p *policy.Policy) {
		p.OllamaRunTimeout = time.Minute
		p.OllamaToolRounds = 2
	})
	got := fetchBot(t, srv.URL, bot.ID)
	if got.RunTimeout.Duration() != 5*time.Minute || got.ToolRounds != 6 {
		t.Fatalf("stored still %#v", got)
	}
	if got.Limits == nil || got.Limits.RunTimeout.Value != "1m" || got.Limits.RunTimeout.Source != "policy" || got.Limits.RunTimeout.Ceiling != "1m" {
		t.Fatalf("clamped run %#v", got.Limits)
	}
	if got.Limits.ToolRounds.Value != 2 || got.Limits.ToolRounds.Source != "policy" || got.Limits.ToolRounds.Ceiling != 2 {
		t.Fatalf("clamped rounds %#v", got.Limits.ToolRounds)
	}
}

func TestBotLimitsCLIRunTimeoutCeiling(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	setPolicy(app, func(p *policy.Policy) {
		p.Backend = "claude"
		p.CLIPermitted = true
		p.TurnTimeout = 30 * time.Minute
	})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Ceil")
	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"run_timeout": "45m"}, "")
	if res.StatusCode != 400 {
		t.Fatalf("status %d %s", res.StatusCode, b)
	}
	errText := apiError(t, b)
	if errText != "Run timeout can be at most 30m. Enter 30m or less, or leave it blank." {
		t.Fatalf("message %q", errText)
	}
	if strings.Contains(errText, "ollama.run_timeout") {
		t.Fatalf("used ollama ceiling: %q", errText)
	}
	got := fetchBot(t, srv.URL, bot.ID)
	if got.RunTimeout != 0 {
		t.Fatalf("saved %#v", got)
	}
}

func TestBotLimitsAuditSetAndClear(t *testing.T) {
	dir := t.TempDir()
	app := newApp(t, dir, fakeModel{})
	auditPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lg.Close() })
	app.audit = lg
	srv := serve(t, app)

	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada", "description": "stay", "run_timeout": "5m",
	}, "")
	if res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)

	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"run_timeout": "5m", "label": "same"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("same %d %s", res.StatusCode, b)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"run_timeout": ""}, "")
	if res.StatusCode != 200 {
		t.Fatalf("clear %d %s", res.StatusCode, b)
	}

	events, err := app.st.ListLog(bot.ID, "bot_limits_changed", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("log rows %d %#v", len(events), events)
	}
	var setRow, clearRow map[string]any
	decodeJSON(t, events[1].Detail, &setRow)
	decodeJSON(t, events[0].Detail, &clearRow)
	if setRow["field"] != "run_timeout" || setRow["old"] != "" || setRow["new"] != "5m" || setRow["by"] != "user" || setRow["bot_id"] != bot.ID {
		t.Fatalf("set row %#v", setRow)
	}
	if clearRow["field"] != "run_timeout" || clearRow["old"] != "5m" || clearRow["new"] != "" || clearRow["by"] != "user" {
		t.Fatalf("clear row %#v", clearRow)
	}

	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Count(text, `"action":"bot_limits_changed"`) != 2 {
		t.Fatalf("audit lines %s", text)
	}
	if !strings.Contains(text, `"field":"run_timeout"`) || !strings.Contains(text, `"new":"5m"`) || !strings.Contains(text, `"by":"user"`) {
		t.Fatalf("audit body %s", text)
	}
}

func TestBotToolRoundsStopAtThree(t *testing.T) {
	mdl := &scriptModel{toolRounds: 20}
	app := newApp(t, "", mdl)
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada", "description": "stay", "tool_rounds": 3,
	}, "")
	if res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	postUser(t, srv.URL, bot.ID, "look around")
	got := waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool { return b.Status != "running" })
	want := toolRoundLimitBody(3, 3, 8, "the built-in default")
	if got.LastRunStatus != "error" || got.LastRunError != want {
		t.Fatalf("status %s %q want %q", got.LastRunStatus, got.LastRunError, want)
	}
	if !strings.Contains(got.LastRunError, "set on this bot") {
		t.Fatalf("missing bot source %q", got.LastRunError)
	}
	if calls := mdl.snapshot(); len(calls) != 3 {
		t.Fatalf("calls %d", len(calls))
	}
	page := readThread(t, srv.URL, bot.ID)
	if threadNotice(page) != "Notice: Stopped: used all 3 tool rounds. Press Continue, or raise the limit under Permissions & access." {
		t.Fatalf("notice %q", threadNotice(page))
	}
}

func TestPolicyToolRoundsRespected(t *testing.T) {
	mdl := &scriptModel{toolRounds: 20}
	app := newApp(t, "", mdl)
	setPolicy(app, func(p *policy.Policy) { p.OllamaToolRounds = 2 })
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Pol")
	postUser(t, srv.URL, bot.ID, "go")
	got := waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool { return b.Status != "running" })
	want := toolRoundLimitBody(2, 0, 2, "the built-in default")
	if got.LastRunStatus != "error" || got.LastRunError != want {
		t.Fatalf("status %s %q want %q", got.LastRunStatus, got.LastRunError, want)
	}
	if strings.Contains(got.LastRunError, "set on this bot") {
		t.Fatalf("policy error named the bot: %q", got.LastRunError)
	}
	if calls := mdl.snapshot(); len(calls) != 2 {
		t.Fatalf("calls %d", len(calls))
	}
}

func TestRunShellUsesBotShellTimeout(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Sh")
	root := app.botWorkspace(bot.ID)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	warm, err := app.dispatchTool(context.Background(), bot, "run_shell", map[string]any{"command": "true"})
	if err != nil {
		t.Fatalf("warm %v %s", err, warm)
	}
	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"shell_timeout": "1s"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("patch %d %s", res.StatusCode, b)
	}
	decodeJSON(t, b, &bot)
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, runErr := app.dispatchTool(ctx, bot, "run_shell", map[string]any{"command": "sleep 5"})
	elapsed := time.Since(start)
	if runErr == nil || !strings.Contains(runErr.Error(), "stopped after 1s (shell timeout set on this bot)") {
		t.Fatalf("err=%v out=%s", runErr, out)
	}
	if elapsed >= 4*time.Second {
		t.Fatalf("slept %s", elapsed)
	}
}

func TestRunTimeoutBodyNamesBotSource(t *testing.T) {
	if timeoutBody("run_timeout", 5*time.Minute, 0, "", "set on this bot") != "The run hit its 5m limit (set on this bot)." {
		t.Fatal("bot origin")
	}
	if timeoutBody("run_timeout", 10*time.Minute, 0, "", "") != "The run hit its 10m limit (the built-in default)." {
		t.Fatal("policy origin")
	}
}

func TestPolicyNamedCeilingInRejectMessage(t *testing.T) {
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(path, []byte("[ollama]\nshell_timeout = \"10m\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		DataDir: dir, BindAddr: "127.0.0.1:0",
		OllamaURL: "http://127.0.0.1:9", Model: "test-model", Version: "0.1.0",
		PolicyPath: path,
	}
	app, err := New(cfg, fakeModel{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	app.noGrokProxy = true
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Named")
	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"shell_timeout": "20m"}, "")
	if res.StatusCode != 400 {
		t.Fatalf("status %d %s", res.StatusCode, b)
	}
	errText := apiError(t, b)
	want := "Shell timeout can be at most 10m (set in policy.toml). Enter 10m or less, or leave it blank to use 10m."
	if errText != want {
		t.Fatalf("got %q want %q", errText, want)
	}
	got := fetchBot(t, srv.URL, bot.ID)
	if got.Limits == nil || got.Limits.ShellTimeout.Ceiling != "10m" || got.Limits.ShellTimeout.CeilingSource != "policy.toml" || got.Limits.ShellTimeout.CeilingKey != "ollama.shell_timeout" {
		t.Fatalf("limits %#v", got.Limits)
	}
}

func TestRunTimeoutOriginNamesSource(t *testing.T) {
	var a *App
	pol := policy.Policy{}
	if got := a.runTimeoutOrigin(store.Bot{RunTimeout: store.DurationMS(5 * time.Minute)}, pol); got != "set on this bot" {
		t.Fatalf("bot value: %q", got)
	}
	if got := a.runTimeoutOrigin(store.Bot{}, pol); got != "the built-in default" {
		t.Fatalf("inherited: %q", got)
	}
	if got := a.runTimeoutOrigin(store.Bot{RunTimeout: store.DurationMS(time.Hour)}, pol); got != "the built-in default" {
		t.Fatalf("above the policy value: %q", got)
	}
}
