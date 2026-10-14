package daemon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
	if !strings.Contains(string(raw), `"source":"cli"`) || !strings.Contains(string(raw), `"tool":"Bash"`) || strings.Contains(string(raw), "sk-supersecretvalue12") {
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
	if !strings.Contains(argv, "--permission-prompt-tool") || !strings.Contains(argv, "mcp__lgbperm__approve") || !strings.Contains(argv, "/api/mcp/permission/") {
		t.Fatalf("argv missing the permission host:\n%s", argv)
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
	if !strings.Contains(string(raw), `"source":"ui"`) || !strings.Contains(string(raw), `"decision":"allow_once"`) || strings.Contains(string(raw), "sk-supersecretvalue12") {
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

func TestPlainStreamIsNotAPromptUI(t *testing.T) {
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
		UIPrompts: true, PromptTimeout: 20 * time.Second,
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
	plainRes, events := openSSE(t, srv.URL, bot.ID, posted.RunID, false)
	waitBus(t, func() bool { return app.bus.Subscribed(posted.RunID) && !app.bus.PromptSubscribed(posted.RunID) })
	promptRes, _ := openSSE(t, srv.URL, bot.ID, posted.RunID, true)
	waitBus(t, func() bool { return app.bus.PromptSubscribed(posted.RunID) })
	promptRes.Body.Close()
	waitBus(t, func() bool { return !app.bus.PromptSubscribed(posted.RunID) && app.bus.Subscribed(posted.RunID) })
	if err := os.WriteFile(gate, []byte("go\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sawRequest := false
	sawNoUI := false
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && !sawNoUI {
		select {
		case ev := <-events:
			if strings.HasPrefix(ev, "permission_request\n") {
				sawRequest = true
			}
			if strings.HasPrefix(ev, "permission_decision\n") && strings.Contains(ev, `"source":"no_ui"`) {
				sawNoUI = true
			}
		case <-time.After(20 * time.Millisecond):
		}
	}
	plainRes.Body.Close()
	if sawRequest {
		t.Fatal("plain stream received a permission_request")
	}
	if !sawNoUI {
		t.Fatal("plain stream did not fail closed with source no_ui")
	}
	waitIdle(t, srv.URL, bot.ID, "")
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
	if !strings.Contains(string(raw), `"source":"`+source+`"`) || !strings.Contains(string(raw), `"tool":"Bash"`) || !strings.Contains(string(raw), `"decision":"deny"`) {
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
	if gate := os.Getenv("LGB_FAKE_GATE"); gate != "" {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(gate); err == nil {
				break
			}
			time.Sleep(15 * time.Millisecond)
		}
	}
	sid := flagValue(args, "--session-id")
	if sid == "" {
		sid = flagValue(args, "--resume")
	}
	behavior, detail := "deny", "permission host was not configured"
	if url := mcpURL(args); url != "" {
		var err error
		behavior, err = callPermissionTool(url)
		if err != nil {
			fmt.Printf("{\"type\":\"result\",\"is_error\":true,\"result\":%q,\"session_id\":%q}\n", err.Error(), sid)
			os.Exit(1)
		}
	}
	if behavior == "allow" {
		fmt.Printf("{\"type\":\"stream_event\",\"session_id\":%q,\"event\":{\"delta\":{\"type\":\"text_delta\",\"text\":\"approved\"}}}\n", sid)
		fmt.Printf("{\"type\":\"result\",\"result\":\"approved\",\"session_id\":%q}\n", sid)
		os.Exit(0)
	}
	fmt.Printf("{\"type\":\"system\",\"subtype\":\"permission_denied\",\"session_id\":%q,\"tool\":\"Bash\"}\n", sid)
	fmt.Printf("{\"type\":\"result\",\"result\":%q,\"session_id\":%q}\n", detail, sid)
	os.Exit(0)
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

func rpc(url string, id int, method string, params any, dst any) error {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
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

func mcpURL(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] != "--mcp-config" {
			continue
		}
		var cfg struct {
			MCPServers map[string]struct {
				URL string `json:"url"`
			} `json:"mcpServers"`
		}
		if json.Unmarshal([]byte(args[i+1]), &cfg) != nil {
			return ""
		}
		for _, srv := range cfg.MCPServers {
			if srv.URL != "" {
				return srv.URL
			}
		}
	}
	return ""
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
