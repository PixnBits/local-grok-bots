package daemon

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/config"
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
	argvLog := filepath.Join(app.ws, "bots", bot.ID, "argv.log")
	if err := os.MkdirAll(filepath.Dir(argvLog), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LGB_ARGV_LOG", argvLog)
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{"content": "go"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, "")
	got, err := app.st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastRunStatus != "error" || !strings.Contains(got.LastRunError, "acp host") || got.SessionID == "" {
		t.Fatalf("status %s err %s session %q", got.LastRunStatus, got.LastRunError, got.SessionID)
	}
	argv := readArgv(t, argvLog)
	if strings.Contains(argv, "--always-approve") || strings.Contains(argv, "streaming-json") || strings.Contains(argv, "--permission-mode") {
		t.Fatalf("grok args:\n%s", argv)
	}
	if !strings.Contains(argv, "agent") || !strings.Contains(argv, "--no-leader") || !strings.Contains(argv, "stdio") {
		t.Fatalf("grok args:\n%s", argv)
	}
}

func TestCLIPermissionPromptNeedsTTY(t *testing.T) {
	dir := t.TempDir()
	installCLIStub(t, dir, "claude")
	t.Setenv("LGB_CLI_MODE", "prompt")
	app := newApp(t, dir, nil)
	app.cliTTY = func() bool { return false }
	app.rtMu.Lock()
	app.policy = policy.Policy{Backend: "claude", CLIPermitted: true, TimersEnabled: true, Idle: time.Hour, Imminent: time.Minute}
	app.rtMu.Unlock()
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Dee", "description": "p"}, "")
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
	if got.LastRunStatus != "error" || got.LastRunError != "permission prompt requires a TTY or an explicit permission_mode" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	if got.SessionID != "sess-prompt" {
		t.Fatalf("session %q", got.SessionID)
	}
}

func TestCLICrashRestartKillsGroupAndResumes(t *testing.T) {
	dir := t.TempDir()
	installCLIStub(t, dir, "claude")
	policyPath := writeCLIPolicy(t, dir)
	childPath := filepath.Join(dir, "child")
	logPath := filepath.Join(dir, "argv.log")
	t.Setenv("LGB_CLI_MODE", "sleep")
	t.Setenv("LGB_CHILD", childPath)
	t.Setenv("LGB_READY", filepath.Join(dir, "ready"))
	t.Setenv("LGB_ARGV_LOG", logPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const marker = "run-crash"
	started := make(chan int, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (clisession.ExecRunner{HasTTY: func() bool { return false }}).Run(ctx, clisession.Spec{
			Backend: "claude", Bin: filepath.Join(dir, "bin", "claude"),
			Prompt: "orphan", Workspace: dir, Fresh: true, Marker: marker,
			OnStart: func(pid int) { started <- pid },
		}, nil)
	}()
	var leader int
	select {
	case leader = <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("orphan cli did not start")
	}
	child := pidFile(t, childPath)
	id, err := clisession.Identify(leader, marker, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = syscall.Kill(-leader, syscall.SIGKILL)
		_ = syscall.Kill(child, syscall.SIGKILL)
	})

	const session = "11111111-1111-4111-8111-111111111111"
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	bot, err := st.CreateBot("Ada", "local", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetBotSession(bot.ID, session); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddMessage(store.Message{BotID: bot.ID, Thread: "user", Role: "user", Content: "old"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetStatus(bot.ID, "running"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertRunningRun(bot.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.SetCLIProc(bot.ID, store.CLIProc{
		PID: id.PID, PGID: id.PGID, Start: id.Start, Exe: id.Exe, Marker: id.Marker,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	app := newCLIApp(t, dir, policyPath)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("orphan cli was not killed on restart")
	}
	waitDead(t, leader)
	waitDead(t, child)
	got, err := app.st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID != session || got.LastRunStatus != "error" || got.LastRunError != "interrupted" || got.Status == "running" {
		t.Fatalf("after crash %#v", got)
	}

	t.Setenv("LGB_CLI_MODE", "ok")
	_ = os.WriteFile(logPath, nil, 0o644)
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{"content": "next"}, app.cfg.AuthToken)
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, app.cfg.AuthToken)
	argv := readArgv(t, logPath)
	if !strings.Contains(argv, "--resume") || !strings.Contains(argv, session) || strings.Contains(argv, "--session-id") {
		t.Fatalf("next message did not resume %s:\n%s", session, argv)
	}
	if strings.Contains(argv, "bwrap") || strings.Contains(argv, "sandbox-exec") {
		t.Fatalf("daemon jail wrapped the resume:\n%s", argv)
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
	waitIdle(t, srv.URL, bot.ID, app.cfg.AuthToken)
	argv = readArgv(t, logPath)
	if !strings.Contains(argv, "--resume") || !strings.Contains(argv, session) || !strings.Contains(argv, "[scheduled] check the gate") {
		t.Fatalf("timer did not resume:\n%s", argv)
	}
}

func TestCLIShutdownMidTurnResumes(t *testing.T) {
	dir := t.TempDir()
	installCLIStub(t, dir, "claude")
	policyPath := writeCLIPolicy(t, dir)
	childPath := filepath.Join(dir, "child")
	logPath := filepath.Join(dir, "argv.log")
	t.Setenv("LGB_CLI_MODE", "sleep")
	t.Setenv("LGB_CHILD", childPath)
	t.Setenv("LGB_READY", filepath.Join(dir, "ready"))
	t.Setenv("LGB_ARGV_LOG", logPath)
	app := newCLIApp(t, dir, policyPath)
	bot, err := app.st.CreateBot("Ada", "local", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.st.AddMessage(store.Message{BotID: bot.ID, Thread: "user", Role: "user", Content: "run"}); err != nil {
		t.Fatal(err)
	}
	app.kick(bot.ID)
	child := pidFile(t, childPath)
	t.Cleanup(func() { _ = syscall.Kill(child, syscall.SIGKILL) })
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := app.st.GetBot(bot.ID)
		if err != nil {
			t.Fatal(err)
		}
		// The session id is stored before the CLI starts; the identity row is
		// written from OnStart. Wait for both before shutting down.
		proc, perr := app.st.GetCLIProc(bot.ID)
		if perr != nil {
			t.Fatal(perr)
		}
		if got.SessionID != "" && proc.PID > 1 {
			if proc.PID <= 1 || proc.PGID != proc.PID || proc.Start == "" || proc.Exe == "" || proc.Marker == "" {
				t.Fatalf("cli identity %+v", proc)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session and cli identity were not stored before shutdown")
		}
		time.Sleep(10 * time.Millisecond)
	}
	app.Shutdown()
	waitDead(t, child)
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID == "" || got.LastRunStatus != "error" || got.LastRunError != "interrupted" {
		t.Fatalf("after shutdown %#v", got)
	}
	proc, err := st.GetCLIProc(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if proc.PID != 0 || proc.PGID != 0 || proc.Start != "" || proc.Exe != "" || proc.Marker != "" {
		t.Fatalf("cli identity left after shutdown %+v", proc)
	}
	session := got.SessionID
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	t.Setenv("LGB_CLI_MODE", "ok")
	_ = os.WriteFile(logPath, nil, 0o644)
	app2 := newCLIApp(t, dir, policyPath)
	srv := serve(t, app2)
	res, b := do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{"content": "next"}, app2.cfg.AuthToken)
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, app2.cfg.AuthToken)
	argv := readArgv(t, logPath)
	if !strings.Contains(argv, "--resume") || !strings.Contains(argv, session) || strings.Contains(argv, "--session-id") {
		t.Fatalf("shutdown resume %s:\n%s", session, argv)
	}
	_ = os.WriteFile(logPath, nil, 0o644)
	tm, err := app2.st.CreateTimer(bot.ID, "tick", "1h", "check the gate", true, "user")
	if err != nil {
		t.Fatal(err)
	}
	if err := app2.st.BackdateTimer(tm.ID, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	app2.fireDue()
	waitIdle(t, srv.URL, bot.ID, app2.cfg.AuthToken)
	argv = readArgv(t, logPath)
	if !strings.Contains(argv, "--resume") || !strings.Contains(argv, session) || !strings.Contains(argv, "[scheduled] check the gate") {
		t.Fatalf("timer after shutdown:\n%s", argv)
	}
}

func newCLIApp(t *testing.T, dir, policyPath string) *App {
	t.Helper()
	// t.TempDir is 0775 when umask is 0002. Token generation refuses a group-writable DATA_DIR.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		DataDir: dir, BindAddr: "127.0.0.1:0",
		OllamaURL: "http://127.0.0.1:9", Model: "test-model", Version: "0.1.0",
		PolicyPath: policyPath,
	}
	app, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	app.noGrokProxy = true
	t.Cleanup(app.Shutdown)
	return app
}

func writeCLIPolicy(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "policy.toml")
	body := "[backend]\nbackend = \"claude\"\n[timers]\nenabled = true\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
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
if [ "$1" = "--version" ]; then
  printf '%s\n' 'grok 1.0.52'
  exit 0
fi
if [ "$1" = "auth" ] && [ "$2" = "status" ]; then
  [ -n "$LGB_AUTH_LOG" ] && env > "$LGB_AUTH_LOG"
  printf '{"loggedIn":true,"authMethod":"%s","configDirectory":"%s"}\n' "${LGB_AUTH_METHOD:-claude.ai}" "${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
  exit 0
fi
if [ -n "$LGB_ARGV_LOG" ]; then
  printf '%s\n' "$@" >> "$LGB_ARGV_LOG"
  printf '\n---\n' >> "$LGB_ARGV_LOG"
fi
if [ -n "$LGB_ENV_LOG" ]; then
  env > "$LGB_ENV_LOG"
fi
is_agent=
for a in "$@"; do [ "$a" = "agent" ] && is_agent=1; done
if [ -z "$is_agent" ] && [ -n "$LGB_FIXTURE" ]; then
  cat "$LGB_FIXTURE"
  exit 0
fi
if [ -n "$is_agent" ]; then
  acp_id() { printf '%s\n' "$1" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p'; }
  acp_send() { awk -v line="$1" 'BEGIN{print line; fflush()}'; }
  IFS= read -r line || exit 1
  id=$(acp_id "$line")
  acp_send "{\"jsonrpc\":\"2.0\",\"id\":${id:-0},\"result\":{\"protocolVersion\":1,\"agentCapabilities\":{\"loadSession\":true}}}"
  IFS= read -r line || exit 1
  id=$(acp_id "$line")
  sid=stub-session
  acp_send "{\"jsonrpc\":\"2.0\",\"id\":${id:-0},\"result\":{\"sessionId\":\"$sid\",\"modes\":{\"currentModeId\":\"default\"}}}"
  IFS= read -r line || exit 1
  id=$(acp_id "$line")
  mode=${LGB_CLI_MODE:-ok}
  if [ -n "$LGB_FIXTURE" ]; then
    cat "$LGB_FIXTURE"
    exit 0
  fi
  if [ "$mode" = "trunc" ]; then
    acp_send "{\"jsonrpc\":\"2.0\",\"method\":\"session/update\",\"params\":{\"sessionId\":\"$sid\",\"update\":{\"sessionUpdate\":\"agent_message_chunk\",\"content\":{\"type\":\"text\",\"text\":\"partial\"}}}}"
    exit 0
  fi
  acp_send "{\"jsonrpc\":\"2.0\",\"method\":\"session/update\",\"params\":{\"sessionId\":\"$sid\",\"update\":{\"sessionUpdate\":\"agent_message_chunk\",\"content\":{\"type\":\"text\",\"text\":\"hello\"}}}}"
  acp_send "{\"jsonrpc\":\"2.0\",\"id\":${id:-0},\"result\":{\"stopReason\":\"end_turn\"}}"
  exit 0
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
if [ "$mode" = "prompt" ]; then
  printf '%s\n' '{"type":"control_request","request":{"subtype":"can_use_tool","tool_name":"Bash"},"session_id":"sess-prompt"}'
  sleep 120
  exit 0
fi
if [ "$mode" = "lgb" ]; then
  {
    lgb memory set color blue; echo "rc=$?"
    lgb timer in 5m check in with the user --name ping; echo "rc=$?"
    lgb memory list; echo "rc=$?"
    lgb run_shell ls; echo "rc=$?"
    lgb bot create Eve spy; echo "rc=$?"
    LGB_TOKEN=wrong lgb memory list; echo "rc=$?"
    echo "token=$LGB_TOKEN"
  } > "$LGB_OUT" 2>&1
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

func waitDead(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !stillRunningProc(pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("pid %d still running", pid)
}

func stillRunningProc(pid int) bool {
	if !processAlive(pid) {
		return false
	}
	out, err := exec.Command("ps", "-o", "state=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return false
	}
	state := strings.TrimSpace(string(out))
	return state != "" && !strings.HasPrefix(state, "Z")
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
