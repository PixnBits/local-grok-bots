package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

var initLineRe = regexp.MustCompile(`^\{"type":"control_request","request_id":"req_1_[0-9a-f]{8}","request":\{"subtype":"initialize","hooks":null\}\}$`)

func TestStreamControlAllowAndInterleave(t *testing.T) {
	f := newStreamTurn(t, "allow", policy.Policy{
		UIPrompts: true, PromptTimeout: 20 * time.Second,
		ToolAllow: []string{"Read"}, ToolDeny: []string{"Bash(rm *)"},
	}, true, true)
	f.openGate()
	var saw []string
	var reqID string
	deadline := time.Now().Add(8 * time.Second)
	for reqID == "" && time.Now().Before(deadline) {
		select {
		case ev := <-f.events:
			saw = append(saw, ev)
			if !strings.HasPrefix(ev, "permission_request\n") {
				continue
			}
			data := strings.TrimPrefix(ev, "permission_request\n")
			if strings.Contains(data, "sk-supersecretvalue12") {
				t.Fatalf("sse leaked secret: %s", data)
			}
			if !strings.Contains(data, `"transport":"stream_control"`) || !strings.Contains(data, `"tool":"Bash"`) {
				t.Fatalf("request %s", data)
			}
			var payload struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal([]byte(data), &payload); err != nil {
				t.Fatal(err)
			}
			reqID = payload.ID
		case <-time.After(20 * time.Millisecond):
		}
	}
	if reqID == "" {
		t.Fatal("UI did not see a permission_request")
	}
	decide := f.url + "/api/bots/" + f.bot.ID + "/runs/" + f.runID + "/permissions/" + reqID
	res, b := do(t, "POST", decide, map[string]any{"decision": "allow_once"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("allow %d %s", res.StatusCode, b)
	}
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	saw = append(saw, drainEvents(f.events, 300*time.Millisecond)...)
	if !eventHas(saw, "token\n", `"text":"mid"`) {
		t.Fatalf("stream events did not interleave: %#v", saw)
	}
	if !eventHas(saw, "permission_decision\n", `"decision":"allow_once"`) || !eventHas(saw, "permission_decision\n", `"transport":"stream_control"`) {
		t.Fatalf("decision %#v", saw)
	}
	var reply string
	for _, m := range thread(t, f.url, f.bot.ID) {
		if m.Role == "bot" {
			reply = m.Content
		}
	}
	if reply != "approved" {
		t.Fatalf("reply %q", reply)
	}
	assertStreamArgv(t, readArgv(t, f.argvPath))
	if !strings.Contains(readArgv(t, f.argvPath), "--allowedTools") || !strings.Contains(readArgv(t, f.argvPath), "--disallowedTools") {
		t.Fatalf("argv rules:\n%s", readArgv(t, f.argvPath))
	}
	lines := stdinLines(t, f.stdinPath)
	if len(lines) != 3 {
		t.Fatalf("stdin %#v", lines)
	}
	assertControlPreamble(t, lines)
	const allowLine = `{"type":"control_response","response":{"subtype":"success","request_id":"req_tool_1","response":{"behavior":"allow","updatedInput":{"command":"echo sk-supersecretvalue12","api_key":"sk-supersecretvalue12"}}}}`
	if lines[2] != allowLine {
		t.Fatalf("allow response %s", lines[2])
	}
	raw := f.auditText()
	if !strings.Contains(raw, `"source":"ui"`) || !strings.Contains(raw, `"decision":"allow_once"`) || !strings.Contains(raw, `"transport":"stream_control"`) || strings.Contains(raw, "sk-supersecretvalue12") {
		t.Fatalf("audit %s", raw)
	}
}

func TestStreamControlDenyByRule(t *testing.T) {
	f := newStreamTurn(t, "deny", policy.Policy{
		UIPrompts: true, PromptTimeout: 20 * time.Second,
		ToolDeny: []string{"Bash(rm *)"},
	}, false, false)
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	lines := stdinLines(t, f.stdinPath)
	if len(lines) != 3 {
		t.Fatalf("stdin %#v", lines)
	}
	assertControlPreamble(t, lines)
	const denyLine = `{"type":"control_response","response":{"subtype":"success","request_id":"req_deny_1","response":{"behavior":"deny","message":"denied by policy rule Bash(rm *)"}}}`
	if lines[2] != denyLine {
		t.Fatalf("deny response %s", lines[2])
	}
	raw := f.auditText()
	for _, want := range []string{`"source":"policy"`, `"decision":"deny"`, `"rule":"Bash(rm *)"`, `"tool":"Bash"`, `"transport":"stream_control"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("audit missing %s in %s", want, raw)
		}
	}
	assertStreamArgv(t, readArgv(t, f.argvPath))
}

func TestStreamControlTimeoutDeny(t *testing.T) {
	f := newStreamTurn(t, "timeout", policy.Policy{
		UIPrompts: true, PromptTimeout: 200 * time.Millisecond,
	}, true, true)
	f.openGate()
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	saw := drainEvents(f.events, 200*time.Millisecond)
	if !eventHas(saw, "permission_request\n", `"transport":"stream_control"`) {
		t.Fatalf("timeout did not ask the UI: %#v", saw)
	}
	lines := stdinLines(t, f.stdinPath)
	if len(lines) != 3 {
		t.Fatalf("stdin %#v", lines)
	}
	assertControlPreamble(t, lines)
	const timeoutLine = `{"type":"control_response","response":{"subtype":"success","request_id":"req_to_1","response":{"behavior":"deny","message":"permission prompt timed out"}}}`
	if lines[2] != timeoutLine {
		t.Fatalf("timeout response %s", lines[2])
	}
	raw := f.auditText()
	if !strings.Contains(raw, `"source":"timeout"`) || !strings.Contains(raw, `"transport":"stream_control"`) || !strings.Contains(raw, `"decision":"deny"`) {
		t.Fatalf("audit %s", raw)
	}
}

func TestStreamControlNoUIStillSpeaksProtocol(t *testing.T) {
	f := newStreamTurn(t, "noui", policy.Policy{UIPrompts: false}, false, false)
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	lines := stdinLines(t, f.stdinPath)
	if len(lines) != 3 {
		t.Fatalf("stdin %#v", lines)
	}
	assertControlPreamble(t, lines)
	const line = `{"type":"control_response","response":{"subtype":"success","request_id":"req_noui_1","response":{"behavior":"deny","message":"no UI is connected to approve this tool"}}}`
	if lines[2] != line {
		t.Fatalf("no_ui response %s", lines[2])
	}
	raw := f.auditText()
	if !strings.Contains(raw, `"source":"no_ui"`) || !strings.Contains(raw, `"transport":"stream_control"`) {
		t.Fatalf("audit %s", raw)
	}
	argv := readArgv(t, f.argvPath)
	assertStreamArgv(t, argv)
	if strings.Contains(argv, "--permission-prompts") {
		t.Fatalf("stream_control passed --permission-prompts:\n%s", argv)
	}
}

func TestStreamControlMalformedDoesNotCrash(t *testing.T) {
	f := newStreamTurn(t, "malformed", policy.Policy{UIPrompts: true}, false, false)
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	var reply string
	for _, m := range thread(t, f.url, f.bot.ID) {
		if m.Role == "bot" {
			reply = m.Content
		}
	}
	if reply != "continued" {
		t.Fatalf("reply %q", reply)
	}
	lines := stdinLines(t, f.stdinPath)
	if len(lines) != 6 {
		t.Fatalf("stdin %#v", lines)
	}
	assertControlPreamble(t, lines)
	want := []string{
		`{"type":"control_response","response":{"subtype":"error","request_id":"hk_1","error":"Unsupported control request subtype: hook_callback"}}`,
		`{"type":"control_response","response":{"subtype":"error","request_id":"mcp_1","error":"Unsupported control request subtype: mcp_message"}}`,
		`{"type":"control_response","response":{"subtype":"error","request_id":"unk_1","error":"Unsupported control request subtype: nope_subtype"}}`,
		`{"type":"control_response","response":{"subtype":"error","request_id":"bad_1","error":"malformed control request"}}`,
	}
	for i, line := range want {
		if lines[i+2] != line {
			t.Fatalf("line %d %s", i+2, lines[i+2])
		}
	}
	raw := f.auditText()
	for _, rule := range []string{
		"Unsupported control request subtype: hook_callback",
		"Unsupported control request subtype: mcp_message",
		"Unsupported control request subtype: nope_subtype",
		"malformed control request",
		"malformed control message",
	} {
		if !strings.Contains(raw, rule) {
			t.Fatalf("audit missing %s in %s", rule, raw)
		}
	}
	if strings.Count(raw, "malformed control message") < 2 {
		t.Fatalf("audit %s", raw)
	}
	if !strings.Contains(raw, `"source":"cli"`) || !strings.Contains(raw, `"decision":"deny"`) || !strings.Contains(raw, `"transport":"stream_control"`) || !strings.Contains(raw, `"tool":"hook_callback"`) {
		t.Fatalf("audit %s", raw)
	}
}

func TestStreamControlCancelWritesNoResponse(t *testing.T) {
	f := newStreamTurn(t, "cancel", policy.Policy{
		UIPrompts: true, PromptTimeout: 20 * time.Second,
	}, true, true)
	f.openGate()
	var saw []string
	var sawReq bool
	deadline := time.Now().Add(8 * time.Second)
	for !sawReq && time.Now().Before(deadline) {
		select {
		case ev := <-f.events:
			saw = append(saw, ev)
			if strings.HasPrefix(ev, "permission_request\n") && strings.Contains(ev, `"transport":"stream_control"`) {
				sawReq = true
			}
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !sawReq {
		t.Fatal("cancel target was not asked")
	}
	if err := os.WriteFile(f.cancelGate, []byte("go\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(8 * time.Second)
	for tokenCompletes(saw, "after-cancel") < 0 && time.Now().Before(deadline) {
		select {
		case ev := <-f.events:
			saw = append(saw, ev)
		case <-time.After(20 * time.Millisecond):
		}
	}
	tokAt := tokenCompletes(saw, "after-cancel")
	if tokAt < 0 {
		t.Fatalf("events %#v", saw)
	}
	decAt := -1
	for i, ev := range saw {
		if decAt < 0 && strings.HasPrefix(ev, "permission_decision\n") && strings.Contains(ev, `"source":"cancel"`) && strings.Contains(ev, `"transport":"stream_control"`) {
			decAt = i
		}
	}
	if decAt < 0 || decAt > tokAt {
		t.Fatalf("order decision %d token %d events %#v", decAt, tokAt, saw)
	}
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	lines := stdinLines(t, f.stdinPath)
	if len(lines) != 2 {
		t.Fatalf("stdin %#v", lines)
	}
	assertControlPreamble(t, lines)
	for _, line := range lines {
		if strings.Contains(line, "control_response") {
			t.Fatalf("cancel wrote a response: %s", line)
		}
	}
	raw := f.auditText()
	if !strings.Contains(raw, `"source":"cancel"`) || !strings.Contains(raw, `"decision":"deny"`) || !strings.Contains(raw, `"transport":"stream_control"`) {
		t.Fatalf("audit %s", raw)
	}
}

func TestStreamControlInitializeErrorFailsClosed(t *testing.T) {
	f := newStreamTurn(t, "init_error", policy.Policy{UIPrompts: true}, false, false)
	got := f.waitDone()
	if got.LastRunStatus != "error" || !strings.Contains(got.LastRunError, "initialize") || !strings.Contains(got.LastRunError, "init failed") {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	lines := stdinLines(t, f.stdinPath)
	if len(lines) != 1 || !initLineRe.MatchString(lines[0]) {
		t.Fatalf("stdin %#v", lines)
	}
	assertStreamArgv(t, readArgv(t, f.argvPath))
}

func TestClaudeTransportNoneSkipsHost(t *testing.T) {
	dir := t.TempDir()
	installFakeClaude(t, dir)
	logPath := filepath.Join(dir, "argv.log")
	auditPath := filepath.Join(dir, "audit.log")
	t.Setenv("LGB_ARGV_LOG", logPath)
	app := newApp(t, dir, nil)
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	app.cliTTY = func() bool { return false }
	app.rtMu.Lock()
	app.policy = policy.Policy{
		Backend: "claude", CLIPermitted: true, TimersEnabled: true,
		Idle: time.Hour, Imminent: time.Minute,
		UIPrompts: true, ClaudeTransport: policy.TransportNone,
	}
	app.rtMu.Unlock()
	srv := serve(t, app)
	app.permBase = srv.URL
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Ada", "description": "p"}, "")
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
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	argv := readArgv(t, logPath)
	if !strings.Contains(argv, "--permission-prompts\nnone") {
		t.Fatalf("argv missing --permission-prompts none:\n%s", argv)
	}
	if strings.Contains(argv, "--permission-prompt-tool") || strings.Contains(argv, "--mcp-config") || strings.Contains(argv, "--input-format") {
		t.Fatalf("none transport attached a host:\n%s", argv)
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"source":"policy"`) || !strings.Contains(string(raw), `"transport":"none"`) || !strings.Contains(string(raw), `"tool":"Bash"`) {
		t.Fatalf("audit %s", raw)
	}
}

func TestDaemonUnknownClaudeTransportDoesNotSpawn(t *testing.T) {
	dir := t.TempDir()
	installFakeClaude(t, dir)
	logPath := filepath.Join(dir, "argv.log")
	t.Setenv("LGB_ARGV_LOG", logPath)
	app := newApp(t, dir, nil)
	app.cliTTY = func() bool { return false }
	app.rtMu.Lock()
	app.policy = policy.Policy{
		Backend: "claude", CLIPermitted: true, TimersEnabled: true,
		Idle: time.Hour, Imminent: time.Minute,
		UIPrompts: true, ClaudeTransport: "stdio",
	}
	app.rtMu.Unlock()
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Ada", "description": "p"}, "")
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
	if got.LastRunStatus != "error" || !strings.Contains(got.LastRunError, "claude_transport") {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	if _, err := os.Stat(logPath); err == nil {
		t.Fatal("unknown transport spawned claude")
	}
}

type streamFix struct {
	t          *testing.T
	app        *App
	url        string
	bot        store.Bot
	runID      string
	events     <-chan string
	argvPath   string
	stdinPath  string
	gate       string
	cancelGate string
	lg         *audit.Logger
	auditPath  string
}

func newStreamTurn(t *testing.T, mode string, pol policy.Policy, withGate, prompts bool) *streamFix {
	t.Helper()
	dir := t.TempDir()
	installFakeClaude(t, dir)
	f := &streamFix{
		t:         t,
		argvPath:  filepath.Join(dir, "argv.log"),
		stdinPath: filepath.Join(dir, "stdin.log"),
		auditPath: filepath.Join(dir, "audit.log"),
	}
	t.Setenv("LGB_ARGV_LOG", f.argvPath)
	t.Setenv("LGB_STDIN_LOG", f.stdinPath)
	t.Setenv("LGB_FAKE_MODE", mode)
	if withGate {
		f.gate = filepath.Join(dir, "gate")
		t.Setenv("LGB_FAKE_GATE", f.gate)
	}
	if mode == "cancel" {
		f.cancelGate = filepath.Join(dir, "cancel")
		t.Setenv("LGB_FAKE_CANCEL_GATE", f.cancelGate)
	}
	app := newApp(t, dir, nil)
	lg, err := audit.Open(f.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	app.cliTTY = func() bool { return false }
	pol.Backend = "claude"
	pol.CLIPermitted = true
	pol.TimersEnabled = true
	if pol.Idle == 0 {
		pol.Idle = time.Hour
	}
	if pol.Imminent == 0 {
		pol.Imminent = time.Minute
	}
	if pol.ClaudeTransport == "" {
		pol.ClaudeTransport = policy.TransportStreamControl
	}
	app.rtMu.Lock()
	app.policy = pol
	app.rtMu.Unlock()
	srv := serve(t, app)
	app.permBase = srv.URL
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Ada", "description": "p"}, "")
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{"content": "go"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	var posted struct {
		RunID string `json:"run_id"`
	}
	decodeJSON(t, b, &posted)
	f.app = app
	f.url = srv.URL
	f.bot = bot
	f.runID = posted.RunID
	f.lg = lg
	if prompts {
		f.events = startSSE(t, srv.URL, bot.ID, posted.RunID)
		waitSubscribed(t, app, posted.RunID)
	}
	return f
}

func (f *streamFix) openGate() {
	f.t.Helper()
	if err := os.WriteFile(f.gate, []byte("go\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *streamFix) waitDone() store.Bot {
	f.t.Helper()
	waitIdle(f.t, f.url, f.bot.ID, "")
	got, err := f.app.st.GetBot(f.bot.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	return got
}

func (f *streamFix) auditText() string {
	f.t.Helper()
	if err := f.lg.Close(); err != nil {
		f.t.Fatal(err)
	}
	raw, err := os.ReadFile(f.auditPath)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(raw)
}

func stdinLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimRight(string(b), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func assertControlPreamble(t *testing.T, lines []string) {
	t.Helper()
	if len(lines) < 2 || !initLineRe.MatchString(lines[0]) {
		t.Fatalf("initialize %q", lines)
	}
	line := lines[1]
	if !strings.HasPrefix(line, `{"type":"user","session_id":"","message":{"role":"user","content":"`) || !strings.HasSuffix(line, `"},"parent_tool_use_id":null}`) {
		t.Fatalf("user line %s", line)
	}
	var msg struct {
		Type      string `json:"type"`
		SessionID string `json:"session_id"`
		Message   struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		Parent *string `json:"parent_tool_use_id"`
	}
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Type != "user" || msg.SessionID != "" || msg.Message.Role != "user" || msg.Parent != nil || !strings.Contains(msg.Message.Content, "go") {
		t.Fatalf("user %#v", msg)
	}
}

func assertStreamArgv(t *testing.T, argv string) {
	t.Helper()
	for _, flag := range []string{"--input-format", "--output-format", "--verbose", "--permission-prompt-tool"} {
		if !argvHas(argv, flag) {
			t.Fatalf("argv missing %s:\n%s", flag, argv)
		}
	}
	if !strings.Contains(argv, "--input-format\nstream-json") || !strings.Contains(argv, "--output-format\nstream-json") || !strings.Contains(argv, "--permission-prompt-tool\nstdio") {
		t.Fatalf("argv values:\n%s", argv)
	}
	for _, bad := range []string{"-p", "--mcp-config", "--include-partial-messages", "--permission-prompts"} {
		if argvHas(argv, bad) {
			t.Fatalf("argv has %s:\n%s", bad, argv)
		}
	}
}

func argvHas(argv, flag string) bool {
	for _, line := range strings.Split(argv, "\n") {
		if line == flag {
			return true
		}
	}
	return false
}

// tokenCompletes is the event index where concatenated token text first
// contains needle. The redactor holds a trailing letter that could start a
// key, so one word can arrive as two frames.
func tokenCompletes(events []string, needle string) int {
	var b strings.Builder
	for i, ev := range events {
		if !strings.HasPrefix(ev, "token\n") {
			continue
		}
		var payload struct {
			Text string `json:"text"`
		}
		if json.Unmarshal([]byte(strings.TrimPrefix(ev, "token\n")), &payload) != nil {
			continue
		}
		b.WriteString(payload.Text)
		if strings.Contains(b.String(), needle) {
			return i
		}
	}
	return -1
}

func eventHas(events []string, prefix, needle string) bool {
	for _, ev := range events {
		if strings.HasPrefix(ev, prefix) && strings.Contains(ev, needle) {
			return true
		}
	}
	return false
}

func drainEvents(ch <-chan string, quiet time.Duration) []string {
	if ch == nil {
		return nil
	}
	var out []string
	timer := time.NewTimer(quiet)
	defer timer.Stop()
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, ev)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(quiet)
		case <-timer.C:
			return out
		}
	}
}
