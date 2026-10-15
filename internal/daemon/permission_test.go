package daemon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestMCPRoundTrip(t *testing.T) {
	app := newApp(t, t.TempDir(), nil)
	app.cfg.AuthToken = "sekrit"
	app.rtMu.Lock()
	app.policy.UIPrompts = true
	app.policy.PromptTimeout = 5 * time.Second
	app.policy.AllowSessionGrants = false
	app.rtMu.Unlock()
	srv := serve(t, app)
	token := app.registerPerm("bot-1", "run-1", "sess-1")
	base := srv.URL + "/api/mcp/permission/" + token

	res, body := do(t, "POST", base, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "t", "version": "0"}},
	}, "")
	if res.StatusCode != 200 || !strings.Contains(string(body), `"lgbperm"`) {
		t.Fatalf("initialize %d %s", res.StatusCode, body)
	}
	note, _ := http.NewRequest(http.MethodPost, base, strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	note.Header.Set("Content-Type", "application/json")
	noteRes, err := http.DefaultClient.Do(note)
	if err != nil {
		t.Fatal(err)
	}
	noteRes.Body.Close()
	if noteRes.StatusCode != http.StatusAccepted {
		t.Fatalf("notification %d", noteRes.StatusCode)
	}
	res, body = do(t, "POST", base, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, "")
	if res.StatusCode != 200 || !strings.Contains(string(body), `"approve"`) {
		t.Fatalf("tools/list %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", srv.URL+"/api/mcp/permission/nope", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}, "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", srv.URL+"/api/mcp/permission", map[string]any{"jsonrpc": "2.0", "id": 4, "method": "ping"}, token)
	if res.StatusCode != 200 || !strings.Contains(string(body), `"result"`) {
		t.Fatalf("bearer ping %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", srv.URL+"/api/mcp/permission", map[string]any{"jsonrpc": "2.0", "id": 5, "method": "ping"}, "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing bearer %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", srv.URL+"/api/mcp/permission", map[string]any{"jsonrpc": "2.0", "id": 6, "method": "ping"}, "sekrit")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin token on permission route %d %s", res.StatusCode, body)
	}

	_, frames := app.bus.SubscribePrompts("run-1")
	secret := "sk-supersecretvalue12"
	type got struct {
		code int
		body string
	}
	out := make(chan got, 1)
	go func() {
		code, body, err := postJSON(base, map[string]any{
			"jsonrpc": "2.0", "id": 3, "method": "tools/call",
			"params": map[string]any{
				"name": "approve",
				"arguments": map[string]any{
					"tool_name":   "Bash",
					"tool_use_id": "tu_1",
					"input":       map[string]any{"command": "echo " + secret, "api_key": secret},
				},
			},
		}, "")
		if err != nil {
			out <- got{0, err.Error()}
			return
		}
		out <- got{code, string(body)}
	}()

	var reqId string
	deadline := time.Now().Add(3 * time.Second)
	for reqId == "" && time.Now().Before(deadline) {
		select {
		case f := <-frames:
			if f.event != "permission_request" {
				continue
			}
			if strings.Contains(string(f.data), secret) {
				t.Fatalf("request leaked the secret: %s", f.data)
			}
			var payload struct {
				ID             string `json:"id"`
				Tool           string `json:"tool"`
				SessionAllowed bool   `json:"session_allowed"`
			}
			if err := json.Unmarshal(f.data, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Tool != "Bash" || payload.SessionAllowed {
				t.Fatalf("payload %+v", payload)
			}
			if !strings.Contains(string(f.data), `"transport":"mcp"`) {
				t.Fatalf("request missing transport: %s", f.data)
			}
			reqId = payload.ID
		case <-time.After(50 * time.Millisecond):
		}
	}
	if reqId == "" {
		t.Fatal("no permission_request")
	}
	decide := srv.URL + "/api/bots/bot-1/runs/run-1/permissions/" + reqId
	res, body = do(t, "POST", decide, map[string]any{"decision": "allow_session"}, "sekrit")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("session grant %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", srv.URL+"/api/bots/other/runs/run-1/permissions/"+reqId, map[string]any{"decision": "allow_once"}, "sekrit")
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("mismatch %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", decide, map[string]any{"decision": "allow_once"}, "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("decide without auth %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", decide, map[string]any{"decision": "allow_once"}, "sekrit")
	if res.StatusCode != 200 {
		t.Fatalf("allow %d %s", res.StatusCode, body)
	}
	select {
	case g := <-out:
		if g.code != 200 {
			t.Fatalf("mcp response %d %s", g.code, g.body)
		}
		behavior, updated := mcpApproveText(t, g.body)
		if behavior != "allow" {
			t.Fatalf("behavior %q in %s", behavior, g.body)
		}
		if !strings.Contains(updated, secret) {
			t.Fatalf("updatedInput dropped the original args: %s", updated)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tools/call did not return")
	}
}

func mcpApproveText(t *testing.T, body string) (behavior, updated string) {
	t.Helper()
	var rpc struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &rpc); err != nil {
		t.Fatal(err)
	}
	if len(rpc.Result.Content) == 0 || rpc.Result.Content[0].Text == "" {
		t.Fatalf("no text content in %s", body)
	}
	text := rpc.Result.Content[0].Text
	var decision struct {
		Behavior     string         `json:"behavior"`
		UpdatedInput map[string]any `json:"updatedInput"`
	}
	if err := json.Unmarshal([]byte(text), &decision); err != nil {
		t.Fatalf("decision text: %v %s", err, text)
	}
	raw, err := json.Marshal(decision.UpdatedInput)
	if err != nil {
		t.Fatal(err)
	}
	return decision.Behavior, string(raw)
}

func TestCLIPermissionDenialIsAudited(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
printf '%s\n' '{"type":"system","subtype":"permission_denied","session_id":"s","tool":"Bash","tool_input":{"command":"echo sk-supersecretvalue12","api_key":"sk-supersecretvalue12"}}'
printf '%s\n' '{"type":"result","result":"continued","session_id":"s","permission_denials":[{"tool_name":"Bash","tool_input":{"command":"echo sk-supersecretvalue12"}}]}'
`
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	app := newApp(t, dir, nil)
	logPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	app.cliTTY = func() bool { return false }
	app.rtMu.Lock()
	app.policy = policy.Policy{Backend: "claude", CLIPermitted: true, TimersEnabled: true, Idle: time.Hour, Imminent: time.Minute, UIPrompts: true}
	app.rtMu.Unlock()
	srv := serve(t, app)
	// A host is attached, so a denial Claude reports itself stays source cli.
	app.permBase = srv.URL
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Ada", "description": "d"}, "")
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
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"source":"cli"`) || !strings.Contains(string(raw), `"tool":"Bash"`) || !strings.Contains(string(raw), `"transport":"mcp"`) || strings.Contains(string(raw), "sk-supersecretvalue12") {
		t.Fatalf("audit %s", raw)
	}
}

func TestFakeClaudePermissionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	installFakeClaude(t, dir)
	logPath := filepath.Join(dir, "argv.log")
	auditPath := filepath.Join(dir, "audit.log")
	gate := filepath.Join(dir, "gate")
	t.Setenv("LGB_ARGV_LOG", logPath)
	t.Setenv("LGB_FAKE_GATE", gate)
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
		UIPrompts: true, PromptTimeout: 20 * time.Second,
		ToolAllow: []string{"Read"}, ToolDeny: []string{"Bash(rm *)"},
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
	var posted struct {
		RunID string `json:"run_id"`
	}
	decodeJSON(t, b, &posted)
	if posted.RunID == "" {
		t.Fatalf("no run id %s", b)
	}
	events := startSSE(t, srv.URL, bot.ID, posted.RunID)
	waitSubscribed(t, app, posted.RunID)
	if err := os.WriteFile(gate, []byte("go\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var reqID string
	deadline := time.Now().Add(8 * time.Second)
	for reqID == "" && time.Now().Before(deadline) {
		select {
		case ev := <-events:
			if !strings.HasPrefix(ev, "permission_request\n") {
				continue
			}
			data := strings.TrimPrefix(ev, "permission_request\n")
			if strings.Contains(data, "sk-supersecretvalue12") {
				t.Fatalf("sse leaked secret: %s", data)
			}
			var payload struct {
				ID   string `json:"id"`
				Tool string `json:"tool"`
			}
			if err := json.Unmarshal([]byte(data), &payload); err != nil {
				t.Fatal(err)
			}
			reqID = payload.ID
		case <-time.After(30 * time.Millisecond):
		}
	}
	if reqID == "" {
		t.Fatal("UI did not see a permission_request")
	}
	permToken := permFilesDuringRun(t, dir, bot.ID)
	decide := srv.URL + "/api/bots/" + bot.ID + "/runs/" + posted.RunID + "/permissions/" + reqID
	res, b = do(t, "POST", decide, map[string]any{"decision": "allow_session"}, "")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("session %d %s", res.StatusCode, b)
	}
	res, b = do(t, "POST", decide, map[string]any{"decision": "allow_once"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("allow %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, "")
	got, err := app.st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	msgs := thread(t, srv.URL, bot.ID)
	var saw bool
	for _, m := range msgs {
		if m.Role == "bot" && m.Content == "approved" {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("thread %#v", msgs)
	}
	argv := readArgv(t, logPath)
	if !strings.Contains(argv, "--permission-prompt-tool") || !strings.Contains(argv, "mcp__lgbperm__approve") || !strings.Contains(argv, "mcp.json") {
		t.Fatalf("argv missing the permission host:\n%s", argv)
	}
	if strings.Contains(argv, permToken) || strings.Contains(argv, "/api/mcp/permission/") {
		t.Fatalf("argv contains the permission token:\n%s", argv)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "cli", bot.ID, "perm", "*")); len(left) != 0 {
		t.Fatalf("permission files left after the turn: %v", left)
	}
	if strings.Contains(argv, "--always-approve") || !strings.Contains(argv, "--allowedTools") || !strings.Contains(argv, "--disallowedTools") {
		t.Fatalf("argv flags:\n%s", argv)
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"source":"ui"`) || !strings.Contains(string(raw), `"decision":"allow_once"`) || !strings.Contains(string(raw), `"transport":"mcp"`) || strings.Contains(string(raw), "sk-supersecretvalue12") {
		t.Fatalf("audit %s", raw)
	}
}

func startSSE(t *testing.T, base, botID, runID string) <-chan string {
	t.Helper()
	_, events := openSSE(t, base, botID, runID, true)
	return events
}

func openSSE(t *testing.T, base, botID, runID string, prompts bool) (*http.Response, <-chan string) {
	t.Helper()
	u := base + "/api/bots/" + botID + "/thread/stream?run_id=" + runID
	if prompts {
		u += "&prompts=1"
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		t.Fatalf("sse %d %s", res.StatusCode, b)
	}
	t.Cleanup(func() { res.Body.Close() })
	events := make(chan string, 32)
	go func() {
		sc := bufio.NewScanner(res.Body)
		var event, data string
		for sc.Scan() {
			line := sc.Text()
			if line == "" {
				if event != "" {
					events <- event + "\n" + data
				}
				event, data = "", ""
				continue
			}
			if strings.HasPrefix(line, "event:") {
				event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			} else if strings.HasPrefix(line, "data:") {
				data = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			}
		}
	}()
	return res, events
}

func waitSubscribed(t *testing.T, app *App, runID string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if app.bus.PromptSubscribed(runID) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("prompt subscriber was not registered")
}

// startPendingRun starts a fake-Claude turn with no page attached and
// returns the run once the CLI is asking for a permission.
func startPendingRun(t *testing.T, timeout time.Duration) (*App, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	installFakeClaude(t, dir)
	gate := filepath.Join(dir, "gate")
	t.Setenv("LGB_FAKE_GATE", gate)
	app := newApp(t, dir, nil)
	app.cliTTY = func() bool { return false }
	app.rtMu.Lock()
	app.policy = policy.Policy{
		Backend: "claude", CLIPermitted: true, TimersEnabled: true,
		Idle: time.Hour, Imminent: time.Minute,
		UIPrompts: true, PromptTimeout: timeout,
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
	var posted struct {
		RunID string `json:"run_id"`
	}
	decodeJSON(t, b, &posted)
	if err := os.WriteFile(gate, []byte("go\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return app, srv.URL, bot.ID, posted.RunID
}

type pendingList struct {
	Pending []struct {
		ID       string `json:"id"`
		RunID    string `json:"run_id"`
		BotID    string `json:"bot_id"`
		Tool     string `json:"tool"`
		Deadline string `json:"deadline"`
	} `json:"pending"`
}

func getPending(t *testing.T, base, botID string) pendingList {
	t.Helper()
	res, b := do(t, "GET", base+"/api/bots/"+botID+"/permissions", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("pending %d %s", res.StatusCode, b)
	}
	var out pendingList
	decodeJSON(t, b, &out)
	return out
}

// Bug: with no ?prompts=1 stream on the run (the bot was not the open tab),
// the broker denied at once with source no_ui. A request must stay pending
// until it is answered or times out, and a page opened later must see it.
func TestPermissionWaitsWithNoPageOpen(t *testing.T) {
	app, base, botID, runID := startPendingRun(t, 20*time.Second)
	var list pendingList
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		list = getPending(t, base, botID)
		if len(list.Pending) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(list.Pending) != 1 {
		t.Fatalf("pending %+v", list)
	}
	p := list.Pending[0]
	if p.RunID != runID || p.BotID != botID || p.Tool != "Bash" || p.Deadline == "" {
		t.Fatalf("pending %+v", p)
	}
	// Still pending a little later: nothing auto-denied it.
	time.Sleep(300 * time.Millisecond)
	if again := getPending(t, base, botID); len(again.Pending) != 1 {
		t.Fatalf("request was resolved with no page: %+v", again)
	}
	res, b := do(t, "GET", base+"/api/bots", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("bots %d", res.StatusCode)
	}
	var bots []store.Bot
	decodeJSON(t, b, &bots)
	if len(bots) != 1 || bots[0].PendingPermissions != 1 {
		t.Fatalf("bot list badge %+v", bots)
	}
	res, b = do(t, "GET", base+"/api/permissions", nil, "")
	if res.StatusCode != 200 || !strings.Contains(string(b), p.ID) {
		t.Fatalf("all pending %d %s", res.StatusCode, b)
	}
	// A page that opens now gets the card from the stream history too.
	_, events := openSSE(t, base, botID, runID, true)
	sawCard := false
	wait := time.After(3 * time.Second)
	for !sawCard {
		select {
		case ev := <-events:
			sawCard = strings.HasPrefix(ev, "permission_request\n") && strings.Contains(ev, p.ID)
		case <-wait:
			t.Fatal("late page did not get the permission_request")
		}
	}
	decide := base + "/api/bots/" + botID + "/runs/" + runID + "/permissions/" + p.ID
	res, b = do(t, "POST", decide, map[string]any{"decision": "allow_once"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("allow %d %s", res.StatusCode, b)
	}
	res, _ = do(t, "POST", decide, map[string]any{"decision": "deny"}, "")
	if res.StatusCode == 200 {
		t.Fatal("second decision accepted")
	}
	waitIdle(t, base, botID, "")
	got, err := app.st.GetBot(botID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	saw := false
	for _, m := range thread(t, base, botID) {
		if m.Role == "bot" && m.Content == "approved" {
			saw = true
		}
	}
	if !saw {
		t.Fatal("approved reply missing")
	}
	if left := getPending(t, base, botID); len(left.Pending) != 0 {
		t.Fatalf("pending after decision %+v", left)
	}
}

// Fail closed: an unanswered request with no page is denied at the timeout.
func TestPermissionTimesOutWithNoPageOpen(t *testing.T) {
	app, base, botID, runID := startPendingRun(t, 400*time.Millisecond)
	waitIdle(t, base, botID, "")
	tools, err := app.st.RunTools([]string{runID})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range tools[runID] {
		if r.Kind == "permission" && !r.OK && strings.Contains(r.Result, `"source":"timeout"`) {
			found = true
		}
		if r.Kind == "permission" && strings.Contains(r.Result, "no_ui") {
			t.Fatalf("denied as no_ui: %+v", r)
		}
	}
	if !found {
		t.Fatalf("no timeout record: %+v", tools[runID])
	}
	if left := getPending(t, base, botID); len(left.Pending) != 0 {
		t.Fatalf("pending after timeout %+v", left)
	}
}

func TestClaudeResidualAsksAreDenied(t *testing.T) {
	t.Run("prompts off", func(t *testing.T) {
		assertResidualDenied(t, false, true, "no_ui")
	})
	t.Run("no host", func(t *testing.T) {
		assertResidualDenied(t, true, false, "policy")
	})
}

func assertResidualDenied(t *testing.T, uiPrompts, withHost bool, source string) {
	t.Helper()
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
		UIPrompts: uiPrompts,
	}
	app.rtMu.Unlock()
	srv := serve(t, app)
	if withHost {
		app.permBase = srv.URL
	}
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
	if strings.Contains(argv, "--permission-prompt-tool") || strings.Contains(argv, "--mcp-config") {
		t.Fatalf("prompts none still attached a host:\n%s", argv)
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"source":"`+source+`"`) || !strings.Contains(string(raw), `"tool":"Bash"`) || !strings.Contains(string(raw), `"decision":"deny"`) || !strings.Contains(string(raw), `"transport":"none"`) {
		t.Fatalf("audit %s", raw)
	}
}

func waitBus(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("stream subscriber state did not settle")
}

func installFakeClaude(t *testing.T, dir string) {
	t.Helper()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nexec " + shellQuote(exe) + " --lgb-fake-claude \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func fakeClaudeMain() {
	args := os.Args[2:]
	if p := os.Getenv("LGB_ARGV_LOG"); p != "" {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintln(f, strings.Join(args, "\n"))
			fmt.Fprintln(f, "---")
			f.Close()
		}
	}
	if os.Getenv("LGB_FAKE_ASKS") != "" {
		fakeMulti(args)
		return
	}
	if streamControlArgs(args) {
		fakeStreamClaude(args)
		return
	}
	waitFakeGate()
	sid := flagValue(args, "--session-id")
	if sid == "" {
		sid = flagValue(args, "--resume")
	}
	behavior, detail := "deny", "permission host was not configured"
	mode := os.Getenv("LGB_FAKE_MODE")
	if url := mcpURL(args); url != "" {
		var err error
		if mode == "question" || mode == "question-timeout" {
			behavior, err = callQuestionTool(url)
		} else {
			behavior, err = callPermissionTool(url)
		}
		if err != nil {
			fmt.Printf("{\"type\":\"result\",\"is_error\":true,\"result\":%q,\"session_id\":%q}\n", err.Error(), sid)
			os.Exit(1)
		}
	}
	if behavior == "allow" || mode == "question" || mode == "question-timeout" {
		word := "approved"
		if mode == "question" || mode == "question-timeout" {
			word = "asked"
		}
		fmt.Printf("{\"type\":\"stream_event\",\"session_id\":%q,\"event\":{\"delta\":{\"type\":\"text_delta\",\"text\":%q}}}\n", sid, word)
		fmt.Printf("{\"type\":\"result\",\"result\":%q,\"session_id\":%q}\n", word, sid)
		os.Exit(0)
	}
	fmt.Printf("{\"type\":\"system\",\"subtype\":\"permission_denied\",\"session_id\":%q,\"tool\":\"Bash\"}\n", sid)
	fmt.Printf("{\"type\":\"result\",\"result\":%q,\"session_id\":%q}\n", detail, sid)
	os.Exit(0)
}

func waitFakeGate() {
	waitFakeFile(os.Getenv("LGB_FAKE_GATE"), false)
}

func waitFakeFile(path string, required bool) {
	if path == "" {
		if required {
			fmt.Fprintf(os.Stderr, "fake claude gate is unset\n")
			os.Exit(1)
		}
		return
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	if required {
		fmt.Fprintf(os.Stderr, "fake claude gate timeout\n")
		os.Exit(1)
	}
}

func streamControlArgs(args []string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--input-format" && args[i+1] == "stream-json" {
			return true
		}
		if args[i] == "--permission-prompt-tool" && args[i+1] == "stdio" {
			return true
		}
	}
	return false
}

func fakeOut(line string) {
	if !strings.HasSuffix(line, "\n") {
		line += "\n"
	}
	_, _ = os.Stdout.WriteString(line)
}

func fakeStreamClaude(args []string) {
	// The gate is the same one MCP tests use: the daemon's initialize
	// request sits in the pipe until a subscriber is ready.
	waitFakeGate()
	switch os.Getenv("LGB_FAKE_MODE") {
	case "stall":
		fakeStall(args)
		return
	case "reuse":
		fakeReuse(args)
		return
	case "early":
		fakeEarly(args)
		return
	}
	log := stdinLogger()
	lines := make(chan string, 32)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			log(line)
			lines <- line
		}
		close(lines)
	}()
	first := mustStdin(lines)
	id := controlRequestID(first)
	if id == "" {
		fmt.Fprintf(os.Stderr, "missing initialize: %s\n", first)
		os.Exit(1)
	}
	if os.Getenv("LGB_FAKE_MODE") == "init_error" {
		fakeOut(fmt.Sprintf(`{"type":"control_response","response":{"subtype":"error","request_id":%q,"error":"init failed"}}`, id))
		os.Exit(0)
	}
	fakeOut(fmt.Sprintf(`{"type":"control_response","response":{"subtype":"success","request_id":%q,"response":{}}}`, id))
	if _, ok := readStdin(lines); !ok {
		os.Exit(1)
	}
	sid := flagValue(args, "--session-id")
	if sid == "" {
		sid = flagValue(args, "--resume")
	}
	switch os.Getenv("LGB_FAKE_MODE") {
	case "deny":
		fakeToolAsk("req_deny_1", `{"command":"rm -rf /tmp/x"}`)
		_ = mustStdin(lines)
		fakeResult(sid, "denied")
	case "timeout":
		fakeToolAsk("req_to_1", `{"command":"echo hi"}`)
		_ = mustStdin(lines)
		fakeResult(sid, "timed-out")
	case "noui":
		fakeToolAsk("req_noui_1", `{"command":"echo hi"}`)
		_ = mustStdin(lines)
		fakeResult(sid, "no-ui")
	case "malformed":
		fakeMalformed(lines, sid)
	case "cancel":
		fakeToolAsk("req_cancel_1", `{"command":"echo hello"}`)
		waitFakeFile(os.Getenv("LGB_FAKE_CANCEL_GATE"), true)
		fakeOut(`{"type":"control_cancel_request","request_id":"req_cancel_1"}`)
		// The broker publishes the cancel decision off this stdout reader.
		// The test opens the gate once that event is visible, so the next
		// line cannot overtake it.
		waitFakeFile(os.Getenv("LGB_FAKE_CANCEL_DONE"), true)
		fakeOut(fmt.Sprintf(`{"type":"stream_event","session_id":%q,"event":{"delta":{"type":"text_delta","text":"after-cancel"}}}`, sid))
		fakeResult(sid, "cancelled")
	case "question", "question-timeout":
		fakeQuestionAsk("req_q_1")
		_ = mustStdin(lines)
		fakeResult(sid, "asked")
	default:
		// The tool ask is in flight while ordinary stream events are written,
		// so the daemon has to parse both on the same stdout.
		fakeToolAsk("req_tool_1", `{"command":"echo sk-supersecretvalue12","api_key":"sk-supersecretvalue12"}`)
		fakeOut(fmt.Sprintf(`{"type":"stream_event","session_id":%q,"event":{"delta":{"type":"text_delta","text":"mid"}}}`, sid))
		fakeOut(fmt.Sprintf(`{"type":"assistant","session_id":%q,"message":{"role":"assistant","content":[{"type":"text","text":"thinking"}]}}`, sid))
		fakeOut(fmt.Sprintf(`{"type":"system","subtype":"init","session_id":%q}`, sid))
		_ = mustStdin(lines)
		fakeResult(sid, "approved")
	}
	waitStdinClosed(lines)
	os.Exit(0)
}

func fakeMalformed(lines <-chan string, sid string) {
	fakeOut(`{"type":"control_request","request_id":"hk_1","request":{"subtype":"hook_callback","callback_id":"c"}}`)
	_ = mustStdin(lines)
	fakeOut(`{"type":"control_request","request_id":"mcp_1","request":{"subtype":"mcp_message","server_name":"x","message":{}}}`)
	_ = mustStdin(lines)
	fakeOut(`{"type":"control_request","request_id":"unk_1","request":{"subtype":"nope_subtype"}}`)
	_ = mustStdin(lines)
	fakeOut(`{"type":"control_request","request_id":"bad_1","request":"nope"}`)
	_ = mustStdin(lines)
	fakeOut(`{"type":"control_request","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{}}}`)
	fakeOut(`this is not json`)
	fakeOut(fmt.Sprintf(`{"type":"stream_event","session_id":%q,"event":{"delta":{"type":"text_delta","text":"still-going"}}}`, sid))
	fakeResult(sid, "continued")
}

func fakeToolAsk(id, input string) {
	fakeOut(`{"type":"control_request","request_id":"` + id + `","request":{"subtype":"can_use_tool","tool_name":"Bash","input":` + input + `,"tool_use_id":"tu_1","permission_suggestions":[],"blocked_path":null,"decision_reason":null}}`)
}

func fakeQuestionAsk(id string) {
	input := os.Getenv("LGB_QUESTION_INPUT")
	if input == "" {
		input = `{}`
	}
	fakeOut(`{"type":"control_request","request_id":"` + id + `","request":{"subtype":"can_use_tool","tool_name":"AskUserQuestion","input":` + input + `,"tool_use_id":"tu_q"}}`)
}

func fakeResult(sid, text string) {
	fakeOut(fmt.Sprintf(`{"type":"result","result":%q,"session_id":%q}`, text, sid))
}

func fakeSession(args []string) string {
	sid := flagValue(args, "--session-id")
	if sid == "" {
		sid = flagValue(args, "--resume")
	}
	return sid
}

// scriptedIn reads the daemon's stdin a line at a time without pulling a
// whole pipe into a buffer. Stall mode needs that so one Write stays blocked.
func scriptedIn() (*bufio.Reader, func(string)) {
	return bufio.NewReaderSize(os.Stdin, 16), stdinLogger()
}

func mustReadLine(in *bufio.Reader, log func(string)) string {
	line, err := readLineWait(in, 15*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fake claude stdin: %v\n", err)
		os.Exit(1)
	}
	log(line)
	return line
}

// readLineWait reads one stdin line. The pipe does not support read deadlines,
// so the timer lives beside the read.
func readLineWait(in *bufio.Reader, d time.Duration) (string, error) {
	type got struct {
		line string
		err  error
	}
	ch := make(chan got, 1)
	go func() {
		line, err := in.ReadString('\n')
		ch <- got{strings.TrimRight(line, "\r\n"), err}
	}()
	select {
	case g := <-ch:
		if g.err != nil {
			return "", g.err
		}
		return g.line, nil
	case <-time.After(d):
		return "", fmt.Errorf("timeout")
	}
}

func fakeHandshake(in *bufio.Reader, log func(string)) {
	first := mustReadLine(in, log)
	id := controlRequestID(first)
	if id == "" {
		fmt.Fprintf(os.Stderr, "missing initialize: %s\n", first)
		os.Exit(1)
	}
	fakeOut(fmt.Sprintf(`{"type":"control_response","response":{"subtype":"success","request_id":%q,"response":{}}}`, id))
	if _, ok := readUserPrompt(in, log); !ok {
		os.Exit(1)
	}
}

func readUserPrompt(in *bufio.Reader, log func(string)) (string, bool) {
	line := mustReadLine(in, log)
	if !strings.Contains(line, `"type":"user"`) {
		fmt.Fprintf(os.Stderr, "missing user prompt: %s\n", line)
		return "", false
	}
	return line, true
}

// fakeStall fills the stdin pipe on purpose. A control_cancel_request and a
// token follow the first byte of the blocked response. The stdout reader has
// to handle both while that Write is still blocked.
func fakeStall(args []string) {
	in, log := scriptedIn()
	fakeHandshake(in, log)
	sz := shrinkStdinPipe()
	body := strings.Repeat("A", sz+8192)
	fakeToolAsk("req_stall_1", `{"command":"`+body+`"}`)
	if err := readByteWait(in, 15*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "fake claude stall read: %v\n", err)
		os.Exit(1)
	}
	fakeOut(`{"type":"control_cancel_request","request_id":"req_stall_1"}`)
	sid := fakeSession(args)
	fakeOut(fmt.Sprintf(`{"type":"stream_event","session_id":%q,"event":{"delta":{"type":"text_delta","text":"unstuck"}}}`, sid))
	waitFakeFile(os.Getenv("LGB_FAKE_STALL_RELEASE"), true)
	if _, err := readLineWait(in, 15*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "fake claude stall drain: %v\n", err)
		os.Exit(1)
	}
	fakeResult(sid, "stalled")
	os.Exit(0)
}

// fakeReuse cancels an id after its response has been written, then sends a
// new can_use_tool with that same id. The second ask must still be answered.
func fakeReuse(args []string) {
	in, log := scriptedIn()
	fakeHandshake(in, log)
	fakeToolAsk("req_reuse_1", `{"command":"echo-first"}`)
	first := mustReadLine(in, log)
	if !strings.Contains(first, "echo-first") || !strings.Contains(first, `"request_id":"req_reuse_1"`) {
		fmt.Fprintf(os.Stderr, "first response %s\n", first)
		os.Exit(1)
	}
	fakeOut(`{"type":"control_cancel_request","request_id":"req_reuse_1"}`)
	fakeToolAsk("req_reuse_1", `{"command":"echo-second"}`)
	second := mustReadLine(in, log)
	if !strings.Contains(second, "echo-second") || !strings.Contains(second, `"request_id":"req_reuse_1"`) {
		fmt.Fprintf(os.Stderr, "reused id got %s\n", second)
		os.Exit(1)
	}
	fakeResult(fakeSession(args), "reused")
	os.Exit(0)
}

// fakeEarly sends one more cancel than the early set keeps, then asks with
// the oldest id and with an id that is still in the set.
func fakeEarly(args []string) {
	in, log := scriptedIn()
	fakeHandshake(in, log)
	const capN = 64
	for i := 0; i <= capN; i++ {
		fakeOut(fmt.Sprintf(`{"type":"control_cancel_request","request_id":"early_%d"}`, i))
	}
	fakeToolAsk("early_0", `{"command":"evicted"}`)
	got := mustReadLine(in, log)
	if !strings.Contains(got, `"request_id":"early_0"`) || !strings.Contains(got, "evicted") {
		fmt.Fprintf(os.Stderr, "evicted id got %s\n", got)
		os.Exit(1)
	}
	fakeToolAsk("early_64", `{"command":"kept"}`)
	extra, err := readLineWait(in, 2*time.Second)
	if err == nil {
		log(extra)
		fmt.Fprintf(os.Stderr, "kept id was answered: %s\n", extra)
		os.Exit(1)
	}
	fakeResult(fakeSession(args), "early-done")
	os.Exit(0)
}

func readByteWait(in *bufio.Reader, d time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
		_, err := in.ReadByte()
		errCh <- err
	}()
	select {
	case err := <-errCh:
		return err
	case <-time.After(d):
		return fmt.Errorf("timeout")
	}
}

func controlRequestID(line string) string {
	var msg struct {
		Type      string `json:"type"`
		RequestID string `json:"request_id"`
		Request   struct {
			Subtype string `json:"subtype"`
		} `json:"request"`
	}
	if json.Unmarshal([]byte(line), &msg) != nil {
		return ""
	}
	if msg.Type != "control_request" || msg.Request.Subtype != "initialize" || msg.RequestID == "" {
		return ""
	}
	return msg.RequestID
}

func stdinLogger() func(string) {
	p := os.Getenv("LGB_STDIN_LOG")
	if p == "" {
		return func(string) {}
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return func(string) {}
	}
	return func(line string) {
		_, _ = f.WriteString(line + "\n")
		_ = f.Sync()
	}
}

func readStdin(lines <-chan string) (string, bool) {
	select {
	case line, ok := <-lines:
		return line, ok
	case <-time.After(15 * time.Second):
		fmt.Fprintf(os.Stderr, "fake claude stdin timeout\n")
		os.Exit(1)
		return "", false
	}
}

func mustStdin(lines <-chan string) string {
	line, ok := readStdin(lines)
	if !ok {
		fmt.Fprintf(os.Stderr, "fake claude stdin closed\n")
		os.Exit(1)
	}
	return line
}

func waitStdinClosed(lines <-chan string) {
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-lines:
			if !ok {
				return
			}
		case <-deadline:
			return
		}
	}
}

func callPermissionTool(url string) (string, error) {
	if err := rpc(url, 1, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "fake-claude", "version": "0"},
	}, nil); err != nil {
		return "", err
	}
	notify, err := http.NewRequest(http.MethodPost, url, strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil {
		return "", err
	}
	notify.Header.Set("Content-Type", "application/json")
	if fakeMCPBearer != "" {
		notify.Header.Set("Authorization", "Bearer "+fakeMCPBearer)
	}
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(notify)
	if err != nil {
		return "", err
	}
	res.Body.Close()
	var listed struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := rpc(url, 2, "tools/list", map[string]any{}, &listed); err != nil {
		return "", err
	}
	var saw bool
	for _, tool := range listed.Result.Tools {
		if tool.Name == "approve" {
			saw = true
		}
	}
	if !saw {
		return "", fmt.Errorf("approve tool missing")
	}
	var called struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := rpc(url, 3, "tools/call", map[string]any{
		"name": "approve",
		"arguments": map[string]any{
			"tool_name":   "Bash",
			"tool_use_id": "tu_fake",
			"input": map[string]any{
				"command": "echo sk-supersecretvalue12",
				"api_key": "sk-supersecretvalue12",
			},
		},
	}, &called); err != nil {
		return "", err
	}
	if called.Error != nil {
		return "", fmt.Errorf("%s", called.Error.Message)
	}
	if len(called.Result.Content) == 0 {
		return "", fmt.Errorf("empty tool result")
	}
	var decision struct {
		Behavior string `json:"behavior"`
		Message  string `json:"message"`
	}
	if err := json.Unmarshal([]byte(called.Result.Content[0].Text), &decision); err != nil {
		return "", err
	}
	if decision.Behavior == "" {
		decision.Behavior = "deny"
	}
	return decision.Behavior, nil
}

func callQuestionTool(url string) (string, error) {
	input := os.Getenv("LGB_QUESTION_INPUT")
	if input == "" {
		return "", fmt.Errorf("question input is unset")
	}
	var raw any
	if err := json.Unmarshal([]byte(input), &raw); err != nil {
		return "", err
	}
	var called struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := rpc(url, 1, "tools/call", map[string]any{
		"name": "approve",
		"arguments": map[string]any{
			"tool_name":   "AskUserQuestion",
			"tool_use_id": "tu_q",
			"input":       raw,
		},
	}, &called); err != nil {
		return "", err
	}
	if called.Error != nil {
		return "", fmt.Errorf("%s", called.Error.Message)
	}
	if len(called.Result.Content) == 0 || called.Result.Content[0].Text == "" {
		return "", fmt.Errorf("empty tool result")
	}
	text := called.Result.Content[0].Text
	if p := os.Getenv("LGB_QUESTION_OUT"); p != "" {
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			return "", err
		}
	}
	var decision struct {
		Behavior string `json:"behavior"`
	}
	if err := json.Unmarshal([]byte(text), &decision); err != nil {
		return "", err
	}
	if decision.Behavior == "" {
		decision.Behavior = "deny"
	}
	return decision.Behavior, nil
}

func rpc(url string, id int, method string, params any, dst any) error {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if fakeMCPBearer != "" {
		req.Header.Set("Authorization", "Bearer "+fakeMCPBearer)
	}
	client := &http.Client{Timeout: 25 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		return fmt.Errorf("mcp %s: %d %s", method, res.StatusCode, raw)
	}
	if dst == nil {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("mcp %s: %w", method, err)
	}
	return nil
}

// fakeMCPBearer is the permission token the fake CLI read from headersHelper.
// The fake is a child of the test, so this variable is not shared with the test.
var fakeMCPBearer string

func mcpURL(args []string) string {
	fakeMCPBearer = ""
	for i := 0; i < len(args)-1; i++ {
		if args[i] != "--mcp-config" {
			continue
		}
		raw := []byte(args[i+1])
		if len(raw) == 0 || raw[0] != '{' {
			b, err := os.ReadFile(args[i+1])
			if err != nil {
				return ""
			}
			raw = b
		}
		var cfg struct {
			MCPServers map[string]struct {
				URL           string `json:"url"`
				HeadersHelper string `json:"headersHelper"`
			} `json:"mcpServers"`
		}
		if json.Unmarshal(raw, &cfg) != nil {
			return ""
		}
		for _, srv := range cfg.MCPServers {
			if srv.HeadersHelper != "" {
				fakeMCPBearer = bearerFromHelper(srv.HeadersHelper)
			}
			if srv.URL != "" {
				return srv.URL
			}
		}
	}
	return ""
}

func bearerFromHelper(command string) string {
	out, err := exec.Command("/bin/sh", "-c", command).Output()
	if err != nil {
		return ""
	}
	var hdr struct {
		Authorization string `json:"Authorization"`
	}
	if json.Unmarshal(bytes.TrimSpace(out), &hdr) != nil {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(hdr.Authorization, prefix) {
		return ""
	}
	return strings.TrimPrefix(hdr.Authorization, prefix)
}

func permFilesDuringRun(t *testing.T, dir, botID string) string {
	t.Helper()
	runs, _ := filepath.Glob(filepath.Join(dir, "cli", botID, "perm", "*"))
	if len(runs) != 1 {
		t.Fatalf("want one per-run permission dir, got %v", runs)
	}
	base := runs[0]
	for _, name := range []string{"mcp.json", "mcp-perm.token", "mcp-perm-headers"} {
		st, err := os.Stat(filepath.Join(base, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o", name, st.Mode().Perm())
		}
	}
	tok, err := os.ReadFile(filepath.Join(base, "mcp-perm.token"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := os.ReadFile(filepath.Join(base, "mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(tok))
	if token == "" || strings.Contains(string(cfg), token) {
		t.Fatal("mcp.json contains the permission token")
	}
	if !strings.Contains(string(cfg), "headersHelper") || strings.Contains(string(cfg), "/api/mcp/permission/") {
		t.Fatalf("mcp.json %s", cfg)
	}
	return token
}

func flagValue(args []string, name string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func postJSON(url string, body any, token string) (int, []byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return res.StatusCode, b, err
	}
	return res.StatusCode, b, nil
}
