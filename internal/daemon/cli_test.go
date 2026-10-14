package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestCLIResumeAndScheduledPrompt(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "argv.log")
	installCLIStub(t, dir, "claude")
	t.Setenv("LGB_ARGV_LOG", logPath)
	t.Setenv("LGB_CLI_MODE", "ok")
	app := newApp(t, dir, fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		t.Errorf("ollama path used for a CLI backend")
		return model.ChatResponse{}, nil
	}})
	app.rtMu.Lock()
	app.policy = policy.Policy{
		Backend: "claude", CLIPermitted: true, DaemonJail: false,
		TimersEnabled: true, Idle: time.Hour, Imminent: 2 * time.Minute,
		ConflictPolicy: "refuse",
	}
	app.rtMu.Unlock()
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Ada", "description": "local"}, "")
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{"content": "hello"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, "")
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
	argv := readArgv(t, logPath)
	if strings.Contains(argv, "--resume") || strings.Contains(argv, "bypassPermissions") || strings.Contains(argv, "--always-approve") {
		t.Fatalf("first turn should be a fresh session without an allow mode:\n%s", argv)
	}
	if !strings.Contains(argv, "--session-id") || !strings.Contains(argv, got.SessionID) {
		t.Fatalf("missing --session-id:\n%s", argv)
	}
	if !strings.Contains(argv, "--output-format") || !strings.Contains(argv, "stream-json") {
		t.Fatalf("stream format missing:\n%s", argv)
	}
	_ = os.WriteFile(logPath, nil, 0o644)
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{"content": "again"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("second post %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, "")
	argv = readArgv(t, logPath)
	if !strings.Contains(argv, "--resume") || !strings.Contains(argv, got.SessionID) || strings.Contains(argv, "--session-id") {
		t.Fatalf("second turn did not resume %s:\n%s", got.SessionID, argv)
	}
	msgs := thread(t, srv.URL, bot.ID)
	var replies int
	for _, m := range msgs {
		if m.Role == "bot" && m.Content == "hello" {
			replies++
		}
	}
	if replies != 2 {
		t.Fatalf("daemon thread replies=%d %#v", replies, msgs)
	}

	_ = os.WriteFile(logPath, nil, 0o644)
	tm, err := app.st.CreateTimer(bot.ID, "tick", "1h", "check the gate", true, "user")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.st.BackdateTimer(tm.ID, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	app.fireDue()
	waitIdle(t, srv.URL, bot.ID, "")
	argv = readArgv(t, logPath)
	if !strings.Contains(argv, "--resume") || !strings.Contains(argv, "[scheduled] check the gate") {
		t.Fatalf("timer was not injected by resume:\n%s", argv)
	}
}

func TestCLIIdleKillKeepsSession(t *testing.T) {
	dir := t.TempDir()
	installCLIStub(t, dir, "claude")
	t.Setenv("LGB_ARGV_LOG", filepath.Join(dir, "argv.log"))
	t.Setenv("LGB_CLI_MODE", "sleep")
	t.Setenv("LGB_READY", filepath.Join(dir, "ready"))
	t.Setenv("LGB_CHILD", filepath.Join(dir, "child"))
	app := newApp(t, dir, nil)
	app.rtMu.Lock()
	app.policy = policy.Policy{
		Backend: "claude", CLIPermitted: true, TimersEnabled: true,
		Idle: 20 * time.Millisecond, Imminent: 2 * time.Minute,
	}
	app.rtMu.Unlock()
	bot, err := app.st.CreateBot("Ada", "local", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	tm, err := app.st.CreateTimer(bot.ID, "soon", "1h", "stay", true, "user")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.st.BackdateTimer(tm.ID, time.Now().Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := app.st.AddMessage(store.Message{BotID: bot.ID, Thread: "user", Role: "user", Content: "run"}); err != nil {
		t.Fatal(err)
	}
	app.kick(bot.ID)
	ready := waitFile(t, os.Getenv("LGB_READY"))
	child := pidFile(t, os.Getenv("LGB_CHILD"))
	t.Cleanup(func() { _ = syscall.Kill(child, syscall.SIGKILL) })
	time.Sleep(40 * time.Millisecond)
	app.killIdle()
	time.Sleep(30 * time.Millisecond)
	if !processAlive(child) {
		t.Fatal("user timer inside the imminent window did not keep the CLI")
	}
	if err := app.st.DeleteTimer(tm.ID); err != nil {
		t.Fatal(err)
	}
	botTimer, err := app.st.CreateTimer(bot.ID, "bot", "1h", "nope", true, "bot")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.st.BackdateTimer(botTimer.ID, time.Now().Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	app.killIdle()
	waitIdleDirect(t, app, bot.ID)
	if processAlive(child) {
		t.Fatal("idle kill left the CLI child running")
	}
	got, err := app.st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID == "" {
		t.Fatal("idle kill dropped the session id")
	}
	if got.LastRunStatus != "error" || got.LastRunError != "interrupted" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	if strings.TrimSpace(ready) == "" {
		t.Fatal("ready pid missing")
	}
	msgs, err := app.st.ListMessages(bot.ID, "user", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	var saw bool
	for _, m := range msgs {
		if m.Role == "bot" && strings.Contains(m.Content, "partial") {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("interrupted text was not stored %#v", msgs)
	}
}

func TestCLITruncatedStreamIsInterrupted(t *testing.T) {
	dir := t.TempDir()
	installCLIStub(t, dir, "grok")
	t.Setenv("LGB_ARGV_LOG", filepath.Join(dir, "argv.log"))
	t.Setenv("LGB_CLI_MODE", "trunc")
	app := newApp(t, dir, nil)
	app.rtMu.Lock()
	app.policy = policy.Policy{Backend: "grok", CLIPermitted: true, TimersEnabled: true, Idle: time.Hour, Imminent: time.Minute}
	app.rtMu.Unlock()
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Bea", "description": "g"}, "")
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
	if got.LastRunError != "interrupted" || got.SessionID == "" {
		t.Fatalf("status %s err %s session %q", got.LastRunStatus, got.LastRunError, got.SessionID)
	}
	argv := readArgv(t, os.Getenv("LGB_ARGV_LOG"))
	if strings.Contains(argv, "--always-approve") || !strings.Contains(argv, "streaming-json") {
		t.Fatalf("grok args:\n%s", argv)
	}
}

func TestOllamaModelAllowList(t *testing.T) {
	dir := t.TempDir()
	var calls int
	app := newApp(t, dir, fakeModel{fn: func(req model.ChatRequest) (model.ChatResponse, error) {
		calls++
		return model.ChatResponse{Content: "nope"}, nil
	}})
	app.rtMu.Lock()
	app.policy = policy.Policy{
		Backend: "ollama", CLIPermitted: true, DaemonJail: true, TimersEnabled: true,
		OllamaModels: []string{"llama3.1"},
	}
	app.rtMu.Unlock()
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Cam", "description": "o"}, "")
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{"content": "hi"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, "")
	if calls != 0 {
		t.Fatalf("disallowed model was called %d times", calls)
	}
	got, err := app.st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastRunStatus != "error" || !strings.Contains(got.LastRunError, "not allowed") {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
}

func installCLIStub(t *testing.T, dir, name string) {
	t.Helper()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
if [ -n "$LGB_ARGV_LOG" ]; then
  printf '%s\n' "$@" >> "$LGB_ARGV_LOG"
  printf '\n---\n' >> "$LGB_ARGV_LOG"
fi
mode=${LGB_CLI_MODE:-ok}
if [ "$mode" = "sleep" ]; then
  sleep 60 &
  echo $! > "$LGB_CHILD"
  echo $$ > "$LGB_READY"
  printf '%s\n' '{"type":"stream_event","session_id":"live","event":{"delta":{"type":"text_delta","text":"partial"}}}'
  sleep 60
  exit 0
fi
if [ "$mode" = "trunc" ]; then
  printf '%s\n' '{"type":"stream_event","session_id":"live","event":{"delta":{"type":"text_delta","text":"partial"}}}'
  exit 0
fi
sid=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--session-id" ] || [ "$prev" = "--resume" ]; then
    sid=$a
  fi
  prev=$a
done
printf '%s\n' "{\"type\":\"stream_event\",\"session_id\":\"$sid\",\"event\":{\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}}"
printf '%s\n' "{\"type\":\"result\",\"result\":\"hello\",\"session_id\":\"$sid\"}"
`
	path := filepath.Join(bin, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func readArgv(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func thread(t *testing.T, base, id string) []store.Message {
	t.Helper()
	res, b := do(t, "GET", base+"/api/bots/"+id+"/thread", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("thread %d %s", res.StatusCode, b)
	}
	var body struct {
		Messages []store.Message `json:"messages"`
	}
	decodeJSON(t, b, &body)
	return body.Messages
}

func waitFile(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err == nil && len(strings.TrimSpace(string(b))) > 0 {
			return string(b)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("file %s was not written", path)
	return ""
}

func pidFile(t *testing.T, path string) int {
	t.Helper()
	text := strings.TrimSpace(waitFile(t, path))
	pid, err := strconv.Atoi(text)
	if err != nil || pid <= 0 {
		t.Fatalf("pid %q: %v", text, err)
	}
	return pid
}

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil
}

func waitIdleDirect(t *testing.T, app *App, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		bot, err := app.st.GetBot(id)
		if err != nil {
			t.Fatal(err)
		}
		if bot.Status != "running" {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("bot stayed running")
}
