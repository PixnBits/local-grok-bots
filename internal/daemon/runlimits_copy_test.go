package daemon

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func rawJSON(t *testing.T, method, url, raw string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := readAll(res)
	if err != nil {
		t.Fatal(err)
	}
	return res, b
}

func newPolicyApp(t *testing.T, body string) (*App, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
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
	return app, serve(t, app)
}

func writeManaged(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "managed.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLimitMessageCatalog pins every shared 400 sentence on the default ceiling,
// including the identical text for "0" and "-1m". tool_rounds 0 still inherits.
func TestLimitMessageCatalog(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Copy")

	same := "Enter a time like 90s, 5m or 1h."
	for _, raw := range []string{
		`{"run_timeout":"0"}`,
		`{"run_timeout":"-1m"}`,
		`{"run_timeout":"0s"}`,
		`{"run_timeout":"soon"}`,
		`{"shell_timeout":"0"}`,
		`{"shell_timeout":"-1m"}`,
	} {
		res, b := rawJSON(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, raw)
		if res.StatusCode != 400 || apiError(t, b) != same {
			t.Fatalf("patch %s %d %s", raw, res.StatusCode, b)
		}
	}
	for _, raw := range []string{
		`{"name":"Zero","description":"stay","run_timeout":"0"}`,
		`{"name":"Neg","description":"stay","run_timeout":"-1m"}`,
		`{"name":"Soon","description":"stay","shell_timeout":"soon"}`,
	} {
		res, b := rawJSON(t, "POST", srv.URL+"/api/bots", raw)
		if res.StatusCode != 400 || apiError(t, b) != same {
			t.Fatalf("post %s %d %s", raw, res.StatusCode, b)
		}
	}
	whole := "Use whole seconds, like 2s."
	for _, raw := range []string{`{"run_timeout":"1.5s"}`, `{"shell_timeout":"500ms"}`} {
		res, b := rawJSON(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, raw)
		if res.StatusCode != 400 || apiError(t, b) != whole {
			t.Fatalf("patch %s %d %s", raw, res.StatusCode, b)
		}
	}
	res, b := rawJSON(t, "POST", srv.URL+"/api/bots", `{"name":"Frac","description":"stay","run_timeout":"1500ms"}`)
	if res.StatusCode != 400 || apiError(t, b) != whole {
		t.Fatalf("post fraction %d %s", res.StatusCode, b)
	}

	rangeMsg := "Enter a whole number from 1 to 8."
	for _, raw := range []string{
		`{"tool_rounds":2.5}`,
		`{"tool_rounds":"3"}`,
		`{"tool_rounds":true}`,
		`{"tool_rounds":-1}`,
		`{"tool_rounds":0.5}`,
		`{"tool_rounds":101}`,
	} {
		res, b = rawJSON(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, raw)
		if res.StatusCode != 400 || apiError(t, b) != rangeMsg {
			t.Fatalf("rounds %s %d %s", raw, res.StatusCode, b)
		}
	}
	res, b = rawJSON(t, "POST", srv.URL+"/api/bots", `{"name":"Half","description":"stay","tool_rounds":2.5}`)
	if res.StatusCode != 400 || apiError(t, b) != rangeMsg {
		t.Fatalf("post rounds %d %s", res.StatusCode, b)
	}
	above := "Tool rounds can be at most 8. Enter 8 or less, or leave it blank."
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"tool_rounds": 9}, "")
	if res.StatusCode != 400 || apiError(t, b) != above {
		t.Fatalf("above rounds %d %s", res.StatusCode, b)
	}
	res, b = do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Inherit", "description": "stay", "tool_rounds": 0}, "")
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("zero rounds post %d %s", res.StatusCode, b)
	}
	var created store.Bot
	decodeJSON(t, b, &created)
	if created.ToolRounds != 0 {
		t.Fatalf("zero rounds stored %d", created.ToolRounds)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"tool_rounds": 3}, "")
	if res.StatusCode != 200 {
		t.Fatalf("set rounds %d %s", res.StatusCode, b)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"tool_rounds": 0}, "")
	if res.StatusCode != 200 || fetchBot(t, srv.URL, bot.ID).ToolRounds != 0 {
		t.Fatalf("clear rounds %d %s", res.StatusCode, b)
	}

	res, b = rawJSON(t, "POST", srv.URL+"/api/bots", `{`)
	if res.StatusCode != 400 || apiError(t, b) != "invalid JSON" {
		t.Fatalf("broken json %d %s", res.StatusCode, b)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"status": "running"}, "")
	if res.StatusCode != 400 || apiError(t, b) != "status must be idle or paused" {
		t.Fatalf("status %d %s", res.StatusCode, b)
	}
}

func TestLimitPolicyTomlMessages(t *testing.T) {
	app, srv := newPolicyApp(t, "[ollama]\nshell_timeout = \"10m\"\ntool_rounds = 3\n")
	bot := createBot(t, srv.URL, "Pol")
	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"tool_rounds": 4}, "")
	want := "Tool rounds can be at most 3 (set in policy.toml). Enter 3 or less, or leave it blank to use 3."
	if res.StatusCode != 400 || apiError(t, b) != want {
		t.Fatalf("policy rounds %d %s", res.StatusCode, b)
	}
	got := fetchBot(t, srv.URL, bot.ID)
	if got.Limits == nil || got.Limits.ToolRounds.CeilingSource != "policy.toml" || got.Limits.ToolRounds.CeilingKey != "ollama.tool_rounds" {
		t.Fatalf("rounds limits %#v", got.Limits)
	}
	if got.Limits.ShellTimeout.CeilingSource != "policy.toml" || got.Limits.ShellTimeout.CeilingKey != "ollama.shell_timeout" {
		t.Fatalf("shell limits %#v", got.Limits.ShellTimeout)
	}
	if msg := app.shellCapMessage(store.Bot{}, 10*time.Minute); msg != "stopped after 10m (shell timeout, set in policy.toml)" {
		t.Fatalf("shell %q", msg)
	}
}

func TestLimitManagedMessages(t *testing.T) {
	t.Setenv("MANAGED_POLICY", writeManaged(t, "[ollama]\nmax_shell_timeout = \"20s\"\nmax_tool_rounds = 4\nmax_run_timeout = \"5m\"\n"))
	app := newApp(t, "", fakeModel{})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Cap")
	checks := []struct {
		body map[string]any
		want string
	}{
		{map[string]any{"shell_timeout": "25s"}, "Shell timeout can be at most 20s, the most your administrator allows. Enter 20s or less."},
		{map[string]any{"run_timeout": "6m"}, "Run timeout can be at most 5m, the most your administrator allows. Enter 5m or less."},
		{map[string]any{"tool_rounds": 5}, "Tool rounds can be at most 4, the most your administrator allows. Enter 4 or less."},
		{map[string]any{"tool_rounds": 101}, "Enter a whole number from 1 to 4."},
	}
	for _, c := range checks {
		res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, c.body, "")
		if res.StatusCode != 400 || apiError(t, b) != c.want {
			t.Fatalf("managed %v %d %s", c.body, res.StatusCode, b)
		}
	}
	got := fetchBot(t, srv.URL, bot.ID)
	if got.Limits == nil || got.Limits.ShellTimeout.CeilingSource != "your administrator" || got.Limits.ShellTimeout.CeilingKey != "ollama.max_shell_timeout" || got.Limits.ToolRounds.CeilingKey != "ollama.max_tool_rounds" || got.Limits.RunTimeout.CeilingKey != "ollama.max_run_timeout" {
		t.Fatalf("managed limits %#v", got.Limits)
	}
	if msg := app.shellCapMessage(store.Bot{}, 20*time.Second); msg != "stopped after 20s (shell timeout, the most your administrator allows)" {
		t.Fatalf("managed shell %q", msg)
	}
}

func TestLimitCLICeilingKey(t *testing.T) {
	app, srv := newPolicyApp(t, "[backend]\nbackend = \"claude\"\n\n[cli]\nturn_timeout = \"30m\"\n")
	token := app.cfg.AuthToken
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "CLI", "description": "stay"}, token)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"run_timeout": "45m"}, token)
	want := "Run timeout can be at most 30m (set in policy.toml). Enter 30m or less, or leave it blank to use 30m."
	if res.StatusCode != 400 || apiError(t, b) != want {
		t.Fatalf("cli %d %s", res.StatusCode, b)
	}
	res, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, token)
	if res.StatusCode != 200 {
		t.Fatalf("get %d %s", res.StatusCode, b)
	}
	var got store.Bot
	decodeJSON(t, b, &got)
	if got.Limits == nil || got.Limits.RunTimeout.Ceiling != "30m" || got.Limits.RunTimeout.CeilingSource != "policy.toml" || got.Limits.RunTimeout.CeilingKey != "cli.turn_timeout" {
		t.Fatalf("cli limits %#v", got.Limits)
	}
}

func TestLimitSystemCeilingMessage(t *testing.T) {
	restore := sandbox.SetSafeSignalSupportedForTest(false)
	t.Cleanup(restore)
	app := newApp(t, "", fakeModel{})
	setPolicy(app, func(p *policy.Policy) { p.OllamaShellTimeout = 2 * time.Minute })
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Sys")
	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"shell_timeout": "31s"}, "")
	want := "Shell timeout can be at most 30s on this system. Enter 30s or less."
	if res.StatusCode != 400 || apiError(t, b) != want {
		t.Fatalf("system %d %s", res.StatusCode, b)
	}
	got := fetchBot(t, srv.URL, bot.ID)
	if got.Limits == nil || got.Limits.ShellTimeout.CeilingSource != "this system" || got.Limits.ShellTimeout.CeilingKey != "" || got.Limits.ShellTimeout.Ceiling != "30s" {
		t.Fatalf("system limits %#v", got.Limits)
	}
}

func TestLimitRunBodies(t *testing.T) {
	botBelow := "The run used all 3 tool rounds (set on this bot). Press Continue, or raise the limit under Permissions & access, up to 8."
	if toolRoundLimitBody(3, 3, 8, "the built-in default") != botBelow {
		t.Fatalf("bot rounds %q", toolRoundLimitBody(3, 3, 8, "the built-in default"))
	}
	one := "The run used all 1 tool round (set on this bot). Press Continue, or raise the limit under Permissions & access, up to 8."
	if toolRoundLimitBody(1, 1, 8, "policy.toml") != one {
		t.Fatalf("singular %q", toolRoundLimitBody(1, 1, 8, "policy.toml"))
	}
	fromPolicy := "The run used all 8 tool rounds (set in policy.toml). Press Continue, or ask whoever manages policy.toml to raise it."
	if toolRoundLimitBody(8, 0, 8, "policy.toml") != fromPolicy {
		t.Fatalf("policy %q", toolRoundLimitBody(8, 0, 8, "policy.toml"))
	}
	managed := "The run used all 4 tool rounds (the most your administrator allows). Press Continue."
	if toolRoundLimitBody(4, 4, 4, "your administrator") != managed {
		t.Fatalf("managed %q", toolRoundLimitBody(4, 4, 4, "your administrator"))
	}
	def := "The run used all 8 tool rounds (the built-in default). Press Continue, or raise the limit in policy.toml."
	if toolRoundLimitBody(8, 0, 8, "the built-in default") != def {
		t.Fatalf("default %q", toolRoundLimitBody(8, 0, 8, "the built-in default"))
	}
	if runNoticeText("error", botBelow) != "Notice: Stopped: used all 3 tool rounds. Press Continue, or raise the limit under Permissions & access." {
		t.Fatal(runNoticeText("error", botBelow))
	}
	if runNoticeText("error", one) != "Notice: Stopped: used all 1 tool round. Press Continue, or raise the limit under Permissions & access." {
		t.Fatal(runNoticeText("error", one))
	}

	cases := []struct{ origin, want string }{
		{"set on this bot", "The run hit its 5m limit (set on this bot)."},
		{"set in policy.toml", "The run hit its 5m limit (set in policy.toml)."},
		{"the most your administrator allows", "The run hit its 5m limit (the most your administrator allows)."},
		{"the built-in default", "The run hit its 5m limit (the built-in default)."},
		{"the limit on this system", "The run hit its 5m limit (the limit on this system)."},
	}
	for _, c := range cases {
		if got := timeoutBody("run_timeout", 5*time.Minute, 0, "", c.origin); got != c.want {
			t.Fatalf("timeout %q want %q", got, c.want)
		}
	}
	if ceilingParen("policy.toml") != "set in policy.toml" || ceilingParen("your administrator") != "the most your administrator allows" || ceilingParen("this system") != "the limit on this system" || ceilingParen("the built-in default") != "the built-in default" {
		t.Fatal("ceiling parentheticals drifted")
	}
	if shellParen(true, "policy.toml") != "shell timeout set on this bot" ||
		shellParen(false, "policy.toml") != "shell timeout, set in policy.toml" ||
		shellParen(false, "your administrator") != "shell timeout, the most your administrator allows" ||
		shellParen(false, "the built-in default") != "shell timeout, the built-in default" ||
		shellParen(false, "this system") != "shell timeout on this system" {
		t.Fatal("shell parentheticals drifted")
	}
}

func TestLimitClampKeepsConfigKey(t *testing.T) {
	app, _ := newPolicyApp(t, "[ollama]\nshell_timeout = \"10s\"\n")
	auditPath := filepath.Join(app.cfg.DataDir, "audit.log")
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lg.Close() })
	app.audit = lg
	bot, err := app.st.InsertBot(store.BotDraft{Name: "Ada", Description: "stay", ShellTimeout: 20 * time.Second}, "user")
	if err != nil {
		t.Fatal(err)
	}
	app.editPol(func(*policy.Policy) {})
	events, err := app.st.ListLog(bot.ID, "bot_limit_clamped", "", 20)
	if err != nil || len(events) != 1 {
		t.Fatalf("rows %d %v", len(events), err)
	}
	var detail map[string]any
	decodeJSON(t, events[0].Detail, &detail)
	if detail["source"] != "policy.toml" || detail["key"] != "ollama.shell_timeout" || detail["stored"] != "20s" || detail["effective"] != "10s" {
		t.Fatalf("detail %#v", detail)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"key":"ollama.shell_timeout"`) || !strings.Contains(text, `"source":"policy.toml"`) {
		t.Fatalf("audit %s", text)
	}
}
