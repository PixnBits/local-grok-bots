package daemon

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestLimitCopyNamesSource(t *testing.T) {
	cases := []struct{ got, want string }{
		{toolRoundLimitBody(3, 3, 8, "the built-in default"), "The run used all 3 tool rounds (tool_rounds, set on this bot). Raise it under Permissions & access, up to 8."},
		{toolRoundLimitBody(8, 8, 8, "the built-in default"), "The run used all 8 tool rounds (tool_rounds, set on this bot). To allow more, set ollama.tool_rounds in policy.toml."},
		{toolRoundLimitBody(2, 0, 2, "ollama.tool_rounds in policy.toml"), "The run used all 2 tool rounds (ollama.tool_rounds in policy.toml). To allow more, raise ollama.tool_rounds in policy.toml."},
		{toolRoundLimitBody(2, 0, 2, "the managed ollama.max_tool_rounds"), "The run used all 2 tool rounds (the managed ollama.max_tool_rounds). To allow more, raise the managed ollama.max_tool_rounds."},
		{toolRoundLimitBody(8, 0, 8, "the built-in default"), "The run used all 8 tool rounds (the built-in default). To allow more, set ollama.tool_rounds in policy.toml."},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Fatalf("got %q want %q", c.got, c.want)
		}
	}
	var a *App
	bot := store.Bot{ShellTimeout: store.DurationMS(time.Second)}
	if got := a.shellCapMessage(bot, time.Second); got != "stopped after 1s (shell_timeout, set on this bot)" {
		t.Fatalf("shell bot %q", got)
	}
	if got := a.shellCapMessage(store.Bot{}, 30*time.Second); got != "stopped after 30s (the built-in default)" {
		t.Fatalf("shell default %q", got)
	}
}

func TestCeilingBoundaries(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Bound")
	ok := []map[string]any{
		{"run_timeout": "10m"},
		{"shell_timeout": "30s"},
		{"tool_rounds": 8},
	}
	for _, body := range ok {
		res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, body, "")
		if res.StatusCode != 200 {
			t.Fatalf("at ceiling %v %d %s", body, res.StatusCode, b)
		}
	}
	bad := []struct {
		body map[string]any
		want string
	}{
		{map[string]any{"run_timeout": "10m1s"}, "run_timeout 10m1s is above the limit of 10m set by the built-in default"},
		{map[string]any{"shell_timeout": "31s"}, "shell_timeout 31s is above the limit of 30s set by the built-in default"},
		{map[string]any{"tool_rounds": 9}, "tool_rounds 9 is above the limit of 8 set by the built-in default"},
	}
	for _, c := range bad {
		res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, c.body, "")
		msg := apiError(t, b)
		if res.StatusCode != 400 || msg != c.want {
			t.Fatalf("above %v %d %q", c.body, res.StatusCode, msg)
		}
		if strings.Contains(msg, "10m is above the limit of 10m") || strings.Contains(msg, "30s is above the limit of 30s") || strings.Contains(msg, "8 is above the limit of 8") {
			t.Fatalf("equal values %q", msg)
		}
	}
	got := fetchBot(t, srv.URL, bot.ID)
	if got.RunTimeout.Duration() != 10*time.Minute || got.ShellTimeout.Duration() != 30*time.Second || got.ToolRounds != 8 {
		t.Fatalf("stored after rejects %#v", got)
	}
}

func TestCreateAtAndAboveCeiling(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	srv := serve(t, app)
	above := []map[string]any{
		{"name": "HighRun", "description": "stay", "run_timeout": "10m1s"},
		{"name": "HighShell", "description": "stay", "shell_timeout": "31s"},
		{"name": "HighRounds", "description": "stay", "tool_rounds": 9},
	}
	for _, body := range above {
		res, b := do(t, "POST", srv.URL+"/api/bots", body, "")
		if res.StatusCode != 400 {
			t.Fatalf("create above %v %d %s", body, res.StatusCode, b)
		}
	}
	listed := fetchBot(t, srv.URL, createBot(t, srv.URL, "Empty").ID)
	if listed.Name == "" {
		t.Fatal("missing empty bot")
	}
	res, b := do(t, "GET", srv.URL+"/api/bots", nil, "")
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	var bots []store.Bot
	decodeJSON(t, b, &bots)
	if len(bots) != 1 {
		t.Fatalf("created rejected bots %#v", bots)
	}
	at := []map[string]any{
		{"name": "AtRun", "description": "stay", "run_timeout": "10m"},
		{"name": "AtShell", "description": "stay", "shell_timeout": "30s"},
		{"name": "AtRounds", "description": "stay", "tool_rounds": 8},
	}
	for _, body := range at {
		res, b := do(t, "POST", srv.URL+"/api/bots", body, "")
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("create at ceiling %v %d %s", body, res.StatusCode, b)
		}
	}
}

func TestWholeSecondsRejected(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Secs")
	bad := []struct {
		body map[string]any
		want string
	}{
		{map[string]any{"run_timeout": "1.5s"}, "run_timeout must be a whole number of seconds, at least 1s"},
		{map[string]any{"run_timeout": "1500ms"}, "run_timeout must be a whole number of seconds, at least 1s"},
		{map[string]any{"run_timeout": "1ns"}, "run_timeout must be a whole number of seconds, at least 1s"},
		{map[string]any{"run_timeout": "300us"}, "run_timeout must be a whole number of seconds, at least 1s"},
		{map[string]any{"run_timeout": "90.001s"}, "run_timeout must be a whole number of seconds, at least 1s"},
		{map[string]any{"shell_timeout": "500ms"}, "shell_timeout must be a whole number of seconds, at least 1s"},
		{map[string]any{"shell_timeout": "1.5s"}, "shell_timeout must be a whole number of seconds, at least 1s"},
	}
	for _, c := range bad {
		res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, c.body, "")
		msg := apiError(t, b)
		if res.StatusCode != 400 || msg != c.want {
			t.Fatalf("%v %d %q", c.body, res.StatusCode, msg)
		}
	}
	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"run_timeout": "1m30s", "shell_timeout": "20s"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("whole %d %s", res.StatusCode, b)
	}
	setPolicy(app, func(p *policy.Policy) { p.OllamaShellTimeout = 3 * time.Hour })
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"shell_timeout": "2h"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("2h %d %s", res.StatusCode, b)
	}
	got := fetchBot(t, srv.URL, bot.ID)
	if got.RunTimeout.Duration() != 90*time.Second || got.ShellTimeout.Duration() != 2*time.Hour {
		t.Fatalf("stored %#v", got)
	}
}

func TestToolRoundsRejectsFraction(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Frac")
	for _, raw := range []string{`{"tool_rounds":2.5}`, `{"tool_rounds":3.7}`, `{"tool_rounds":"3"}`, `{"tool_rounds":true}`} {
		req, err := http.NewRequest(http.MethodPatch, srv.URL+"/api/bots/"+bot.ID, strings.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := readAll(res)
		if res.StatusCode != 400 || !strings.Contains(string(body), "invalid tool_rounds") && !strings.Contains(string(body), "tool_rounds must be") {
			t.Fatalf("%s %d %s", raw, res.StatusCode, body)
		}
	}
	got := fetchBot(t, srv.URL, bot.ID)
	if got.ToolRounds != 0 {
		t.Fatalf("stored %d", got.ToolRounds)
	}
}

func readAll(res *http.Response) ([]byte, error) {
	defer res.Body.Close()
	return io.ReadAll(res.Body)
}

func TestUnchangedAboveCeilingCanBeSaved(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Clamp", "description": "stay", "shell_timeout": "20s", "run_timeout": "5m", "tool_rounds": 6,
	}, "")
	if res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	if bot.Limits == nil || bot.Limits.ShellTimeout.CeilingSource != "the built-in default" {
		t.Fatalf("ceiling source %#v", bot.Limits)
	}
	setPolicy(app, func(p *policy.Policy) {
		p.OllamaShellTimeout = 10 * time.Second
		p.OllamaRunTimeout = time.Minute
		p.OllamaToolRounds = 2
	})
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"label": "notes"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("label %d %s", res.StatusCode, b)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"shell_timeout": "20s"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("unchanged shell %d %s", res.StatusCode, b)
	}
	got := fetchBot(t, srv.URL, bot.ID)
	if got.Label != "notes" || got.ShellTimeout.Duration() != 20*time.Second {
		t.Fatalf("stored %#v", got)
	}
	if got.Limits == nil || got.Limits.ShellTimeout.Value != "10s" || got.Limits.ShellTimeout.Source != "policy" || got.Limits.ShellTimeout.Ceiling != "10s" {
		t.Fatalf("limits %#v", got.Limits)
	}
	if app.shellCap(got) != 10*time.Second {
		t.Fatalf("shellCap %s", app.shellCap(got))
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"shell_timeout": "15s"}, "")
	if res.StatusCode != 400 || !strings.Contains(apiError(t, b), "shell_timeout 15s is above the limit of 10s") {
		t.Fatalf("changed above %d %s", res.StatusCode, b)
	}
	got = fetchBot(t, srv.URL, bot.ID)
	if got.ShellTimeout.Duration() != 20*time.Second {
		t.Fatalf("changed anyway %#v", got)
	}
}

func TestAuditByAndOldAcrossPatches(t *testing.T) {
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
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"run_timeout": "4m"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("first %d %s", res.StatusCode, b)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"run_timeout": "3m"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("second %d %s", res.StatusCode, b)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var sawFirst, sawSecond bool
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil || row["action"] != "bot_limits_changed" || row["field"] != "run_timeout" {
			continue
		}
		if row["by"] != "user" {
			t.Fatalf("by %#v", row)
		}
		if row["old"] == "5m" && row["new"] == "4m" {
			sawFirst = true
		}
		if row["old"] == "4m" && row["new"] == "3m" {
			sawSecond = true
		}
	}
	if !sawFirst || !sawSecond {
		t.Fatalf("audit %s", raw)
	}
}

func TestSaveRollsBackWhenLimitLogAborts(t *testing.T) {
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
	db, err := sql.Open("sqlite", "file:"+app.cfg.DBPath()+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(abortLimitLogSQL); err != nil {
		t.Fatal(err)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"run_timeout": "4m", "label": "nope"}, "")
	if res.StatusCode != 500 || apiError(t, b) != "could not save the bot" {
		t.Fatalf("patch %d %s", res.StatusCode, b)
	}
	got := fetchBot(t, srv.URL, bot.ID)
	if got.RunTimeout.Duration() != 5*time.Minute || got.Label != "" {
		t.Fatalf("row %#v", got)
	}
	res, b = do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Bea", "description": "stay", "shell_timeout": "10s",
	}, "")
	if res.StatusCode != 500 || apiError(t, b) != "could not save the bot" {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	res, b = do(t, "GET", srv.URL+"/api/bots", nil, "")
	var bots []store.Bot
	decodeJSON(t, b, &bots)
	if len(bots) != 1 || bots[0].ID != bot.ID {
		t.Fatalf("bots %#v", bots)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"new":"4m"`) || strings.Contains(text, `"new":"10s"`) || strings.Count(text, `"action":"bot_limits_changed"`) != 1 {
		t.Fatalf("audit %s", text)
	}
}

const abortLimitLogSQL = `CREATE TRIGGER abort_limit_log BEFORE INSERT ON log_events
WHEN NEW.kind = 'bot_limits_changed'
BEGIN
  SELECT RAISE(ABORT, 'disk full');
END`

func TestShellClampLoggedOnce(t *testing.T) {
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
		"name": "Ada", "description": "stay", "shell_timeout": "20s",
	}, "")
	if res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	lower := func() {
		setPolicy(app, func(p *policy.Policy) { p.OllamaShellTimeout = 10 * time.Second })
	}
	lower()
	lower()
	events, err := app.st.ListLog(bot.ID, "bot_limit_clamped", "", 20)
	if err != nil || len(events) != 1 {
		t.Fatalf("rows %d %v", len(events), err)
	}
	var detail map[string]any
	decodeJSON(t, events[0].Detail, &detail)
	_, src := app.pol().ShellTimeoutCeiling()
	if detail["field"] != "shell_timeout" || detail["stored"] != "20s" || detail["effective"] != "10s" || detail["source"] != src || detail["bot_id"] != bot.ID {
		t.Fatalf("detail %#v src %q", detail, src)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), `"action":"bot_limit_clamped"`) != 1 {
		t.Fatalf("audit %s", raw)
	}
}

func TestShellSignalRefusedIsAudited(t *testing.T) {
	dir := t.TempDir()
	app := newApp(t, dir, fakeModel{})
	auditPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lg.Close() })
	app.audit = lg
	bot, err := app.st.InsertBot(store.BotDraft{Name: "Ada", Description: "stay"}, "user")
	if err != nil {
		t.Fatal(err)
	}
	run := "run-1"
	bot.ActiveRunID = &run
	app.noteShellSignalRefused(bot, 4242, "not a descendant of the jail root")
	events, err := app.st.ListLog(bot.ID, "shell_signal_refused", "", 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("rows %d %v", len(events), err)
	}
	var detail map[string]any
	decodeJSON(t, events[0].Detail, &detail)
	if detail["action"] != "shell_signal_refused" || detail["pid"] != float64(4242) || detail["reason"] != "not a descendant of the jail root" || detail["run_id"] != run {
		t.Fatalf("detail %#v", detail)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"action":"shell_signal_refused"`) || !strings.Contains(string(raw), `"run_id":"run-1"`) {
		t.Fatalf("audit %s", raw)
	}
}

func TestShellCeilingDropsWithoutSafeSignal(t *testing.T) {
	restore := sandbox.SetSafeSignalSupportedForTest(false)
	t.Cleanup(restore)
	app := newApp(t, "", fakeModel{})
	setPolicy(app, func(p *policy.Policy) { p.OllamaShellTimeout = 2 * time.Minute })
	d, src := app.pol().ShellTimeoutCeiling()
	if d != 30*time.Second || src != "the 30s limit on this system" {
		t.Fatalf("ceiling %s %q warnings %v", d, src, app.pol().Warnings)
	}
	if !strings.Contains(strings.Join(app.pol().Warnings, "\n"), "shell timeouts above 30s are unavailable on this system; the ceiling is 30s") {
		t.Fatalf("warnings %v", app.pol().Warnings)
	}
	if got := app.shellCapMessage(store.Bot{}, d); got != "stopped after 30s (the 30s limit on this system)" {
		t.Fatalf("message %q", got)
	}
}

func TestAboveCeilingMessageValuesDiffer(t *testing.T) {
	msg := aboveCeilingMessage("shell_timeout", "31s", "30s", "the built-in default")
	if msg != "shell_timeout 31s is above the limit of 30s set by the built-in default" {
		t.Fatal(msg)
	}
	value := "31s"
	ceiling := "30s"
	if value == ceiling || !strings.Contains(msg, value) || !strings.Contains(msg, ceiling) {
		t.Fatalf("values not distinct %q", msg)
	}
}
