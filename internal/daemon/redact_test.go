package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func redactShapes() (ant, xai, lgbr, admin string) {
	ant = "sk-ant-api03-abc123xyz-456def789ghij_klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopAA"
	xai = "xai-" + strings.Repeat("ab12cd34", 5)
	lgbr = "lgbr_" + strings.Repeat("ab", 32)
	admin = strings.Repeat("cd", 32)
	return
}

func streamDelta(text string) string {
	return `{"type":"stream_event","session_id":"s-redact","event":{"delta":{"type":"text_delta","text":` + jsonString(text) + `}}}`
}

func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		if r == '\\' || r == '"' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

func TestCLITokenStreamRedactsSplitSecrets(t *testing.T) {
	ant, xai, lgbr, admin := redactShapes()
	antCut := strings.Index(ant, "-api03-") + len("-api03-")
	parts := []string{
		"note " + ant[:antCut],
		ant[antCut:] + " ",
		xai[:4],
		xai[4:] + " ",
		lgbr[:10],
		lgbr[10:] + " ",
		admin[:8],
		admin[8:] + " end",
	}
	var lines []string
	for _, p := range parts {
		lines = append(lines, streamDelta(p))
	}
	lines = append(lines,
		`{"type":"assistant","session_id":"s-redact","message":{"content":[{"type":"tool_use","id":"tu1","name":"Bash","input":{"command":"true"}}]}}`,
		`{"type":"user","session_id":"s-redact","message":{"content":[{"type":"tool_result","tool_use_id":"tu1","content":"ok"}]}}`,
		`{"type":"result","result":"done","session_id":"s-redact"}`,
	)
	app, bot, msgs, recs := runFixture(t, "claude", strings.Join(lines, "\n")+"\n")
	var runID string
	for _, m := range msgs {
		if m.Role == "bot" && m.RunID != nil {
			runID = *m.RunID
		}
		if strings.Contains(m.Content, ant) || strings.Contains(m.Content, xai) || strings.Contains(m.Content, lgbr) || strings.Contains(m.Content, admin) {
			t.Fatalf("thread leaked %q", m.Content)
		}
	}
	if runID == "" {
		t.Fatal("no run")
	}
	var text string
	for _, r := range recs {
		blob := r.Kind + r.Name + r.Result + string(r.Arguments)
		if leaked(blob, ant, xai, lgbr, admin) {
			t.Fatalf("record leaked %+v %s", r, r.Arguments)
		}
		if r.Kind == "text" {
			text = r.Result
		}
	}
	if !strings.Contains(text, "[redacted]") || !strings.Contains(text, "note ") || !strings.Contains(text, "end") {
		t.Fatalf("stored text %q", text)
	}
	hist, _ := app.bus.Subscribe(runID)
	var streamed string
	for _, f := range hist {
		if leaked(string(f.data), ant, xai, lgbr, admin) {
			t.Fatalf("event %s leaked %s", f.event, f.data)
		}
		if f.event == "token" {
			streamed += string(f.data)
		}
	}
	if !strings.Contains(streamed, "[redacted]") || strings.Contains(streamed, "sk-ant-api03-") {
		t.Fatalf("tokens %s", streamed)
	}
	assertLogsClean(t, app, bot.ID, ant, xai, lgbr, admin)
}

func TestCLIStderrIsRedactedInLogsAndEvents(t *testing.T) {
	ant, xai, lgbr, admin := redactShapes()
	app, dir, bot, _ := isolationApp(t, "claude", "")
	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = "auth" ] && [ "$2" = "status" ]; then
  printf '%%s\n' '{"loggedIn":true,"authMethod":"claude.ai"}'
  exit 0
fi
printf '%%s\n' '{"type":"result","result":"","session_id":"s"}'
printf '%%s\n' 'startup failed: %s %s %s %s' >&2
exit 1
`, ant, xai, lgbr, admin)
	if err := os.WriteFile(filepath.Join(dir, "bin", "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	got := postAndWait(t, app, bot.ID)
	if got.LastRunStatus != "error" || !strings.Contains(got.LastRunError, "startup failed") || !strings.Contains(got.LastRunError, "[redacted]") {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	if leaked(got.LastRunError, ant, xai, lgbr, admin) {
		t.Fatalf("run error leaked %s", got.LastRunError)
	}
	assertLogsClean(t, app, bot.ID, ant, xai, lgbr, admin)
	evs, err := app.st.ListLog(bot.ID, "run_finished", "", 10)
	if err != nil || len(evs) == 0 {
		t.Fatalf("run_finished %v %v", evs, err)
	}
	var detail map[string]any
	if err := json.Unmarshal(evs[len(evs)-1].Detail, &detail); err != nil {
		t.Fatal(err)
	}
	runID, _ := detail["run_id"].(string)
	hist, _ := app.bus.Subscribe(runID)
	saw := false
	for _, f := range hist {
		if leaked(string(f.data), ant, xai, lgbr, admin) {
			t.Fatalf("event %s leaked %s", f.event, f.data)
		}
		if f.event == "error" && strings.Contains(string(f.data), "[redacted]") && strings.Contains(string(f.data), "startup failed") {
			saw = true
		}
	}
	if !saw {
		t.Fatal("error event was not redacted")
	}
}

func TestFailCLIRedactsErrorString(t *testing.T) {
	ant, xai, lgbr, admin := redactShapes()
	app := newApp(t, t.TempDir(), nil)
	bot, err := app.st.CreateBot("Ada", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	run, err := app.st.CreateRun(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	app.failCLI(bot.ID, run.ID, "claude", fmt.Errorf("boom %s %s %s %s", ant, xai, lgbr, admin))
	got, err := app.st.GetRun(run.ID)
	if err != nil || got.Error == nil {
		t.Fatalf("run %v %v", got, err)
	}
	if !strings.Contains(*got.Error, "boom ") || !strings.Contains(*got.Error, "[redacted]") || leaked(*got.Error, ant, xai, lgbr, admin) {
		t.Fatalf("stored %q", *got.Error)
	}
	assertLogsClean(t, app, bot.ID, ant, xai, lgbr, admin)
	hist, _ := app.bus.Subscribe(run.ID)
	saw := false
	for _, f := range hist {
		if leaked(string(f.data), ant, xai, lgbr, admin) {
			t.Fatalf("event %s leaked %s", f.event, f.data)
		}
		if f.event == "error" && strings.Contains(string(f.data), "[redacted]") {
			saw = true
		}
	}
	if !saw {
		t.Fatal("failCLI published the raw error")
	}
}

func leaked(body string, secrets ...string) bool {
	for _, s := range secrets {
		if s != "" && strings.Contains(body, s) {
			return true
		}
	}
	return false
}

func assertLogsClean(t *testing.T, app *App, botID string, secrets ...string) {
	t.Helper()
	evs, err := app.st.ListLog(botID, "", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if leaked(string(e.Detail), secrets...) {
			t.Fatalf("log %s leaked %s", e.Kind, e.Detail)
		}
	}
}
