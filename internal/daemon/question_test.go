package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

const (
	qLib  = `{"header":"Lib","multiSelect":false,"options":[{"description":"Go toolchain","label":"Go"},{"description":"Rust toolchain","label":"Rust"}],"question":"Which library?"}`
	qLibs = `{"header":"Libs","multiSelect":true,"options":[{"description":"Go toolchain","label":"Go"},{"description":"Rust toolchain","label":"Rust"}],"question":"Which libraries?"}`

	qSingleIn = `{"questions":[` + qLib + `]}`
	qMultiIn  = `{"questions":[` + qLibs + `]}`

	qSingleUpdated = `{"answers":{"Which library?":"Go"},"questions":[` + qLib + `]}`
	qMultiUpdated  = `{"answers":{"Which libraries?":"Go, Rust"},"questions":[` + qLibs + `]}`
	qFreeUpdated   = `{"answers":{"Which library?":"my own pick"},"questions":[` + qLib + `]}`

	qAllowSingle = `{"behavior":"allow","updatedInput":` + qSingleUpdated + `}`
	qAllowMulti  = `{"behavior":"allow","updatedInput":` + qMultiUpdated + `}`
	qAllowFree   = `{"behavior":"allow","updatedInput":` + qFreeUpdated + `}`
	qDenyTimeout = `{"behavior":"deny","message":"The user did not answer the question (timeout)."}`
)

func TestAskUserQuestionTransports(t *testing.T) {
	if !lgbSupported {
		t.Fatal("lgb support is required to reject a live run token")
	}
	type spec struct {
		name      string
		transport string
		mode      string
		input     string
		answers   map[string]string
		want      string
		timeout   time.Duration
		auth      bool
		answered  int
		source    string
		decision  string
	}
	cases := []spec{
		{name: "single", transport: policy.TransportMCP, mode: "question", input: qSingleIn, answers: map[string]string{"Which library?": "Go"}, want: qAllowSingle, timeout: 20 * time.Second, auth: true, answered: 1, source: "ui", decision: "answer"},
		{name: "multi", transport: policy.TransportMCP, mode: "question", input: qMultiIn, answers: map[string]string{"Which libraries?": "Go, Rust"}, want: qAllowMulti, timeout: 20 * time.Second, answered: 1, source: "ui", decision: "answer"},
		{name: "free", transport: policy.TransportMCP, mode: "question", input: qSingleIn, answers: map[string]string{"Which library?": "my own pick"}, want: qAllowFree, timeout: 20 * time.Second, answered: 1, source: "ui", decision: "answer"},
		{name: "timeout", transport: policy.TransportMCP, mode: "question-timeout", input: qSingleIn, want: qDenyTimeout, timeout: 400 * time.Millisecond, answered: 0, source: "timeout", decision: "deny"},
		{name: "single", transport: policy.TransportStreamControl, mode: "question", input: qSingleIn, answers: map[string]string{"Which library?": "Go"}, want: qAllowSingle, timeout: 20 * time.Second, auth: true, answered: 1, source: "ui", decision: "answer"},
		{name: "multi", transport: policy.TransportStreamControl, mode: "question", input: qMultiIn, answers: map[string]string{"Which libraries?": "Go, Rust"}, want: qAllowMulti, timeout: 20 * time.Second, answered: 1, source: "ui", decision: "answer"},
		{name: "free", transport: policy.TransportStreamControl, mode: "question", input: qSingleIn, answers: map[string]string{"Which library?": "my own pick"}, want: qAllowFree, timeout: 20 * time.Second, answered: 1, source: "ui", decision: "answer"},
		{name: "timeout", transport: policy.TransportStreamControl, mode: "question-timeout", input: qSingleIn, want: qDenyTimeout, timeout: 400 * time.Millisecond, answered: 0, source: "timeout", decision: "deny"},
	}
	for _, tc := range cases {
		t.Run(tc.transport+"/"+tc.name, func(t *testing.T) {
			f := startQuestion(t, tc.transport, tc.mode, tc.input, tc.timeout)
			f.openGate()
			if tc.answers != nil {
				id, raw := f.waitRequest()
				if !strings.Contains(raw, `"kind":"question"`) || !strings.Contains(raw, `"session_allowed":false`) {
					t.Fatalf("request %s", raw)
				}
				decide := f.decide(id)
				if tc.auth {
					f.rejectRunTokens(decide)
					res, b := do(t, "POST", decide, map[string]any{"decision": "allow_once"}, "sekrit")
					if res.StatusCode != http.StatusBadRequest {
						t.Fatalf("allow_once %d %s", res.StatusCode, b)
					}
					res, b = do(t, "POST", decide, map[string]any{"decision": "allow_session"}, "sekrit")
					if res.StatusCode != http.StatusBadRequest {
						t.Fatalf("allow_session %d %s", res.StatusCode, b)
					}
				}
				res, b := do(t, "POST", decide, map[string]any{"decision": "answer", "answers": tc.answers}, "sekrit")
				if res.StatusCode != http.StatusOK {
					t.Fatalf("answer %d %s", res.StatusCode, b)
				}
				if tc.auth {
					res, b = do(t, "POST", decide, map[string]any{"decision": "answer", "answers": tc.answers}, "sekrit")
					if res.StatusCode != http.StatusConflict {
						t.Fatalf("second answer %d %s", res.StatusCode, b)
					}
				}
			}
			got := f.waitDone()
			if got.LastRunStatus != "done" || got.LastRunError != "" {
				t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
			}
			if body := f.responseBody(); body != tc.want {
				t.Fatalf("response\n%s\nwant\n%s", body, tc.want)
			}
			f.assertQuestionRecord(tc.answered, tc.source, tc.decision, tc.name == "free")
		})
	}
}

func TestHTTPAnswerValidatesAndRedacts(t *testing.T) {
	app := newApp(t, t.TempDir(), nil)
	app.cfg.AuthToken = "sekrit"
	srv := serve(t, app)
	_, frames := app.bus.SubscribePrompts("run-1")
	t.Cleanup(func() { app.bus.Unsubscribe("run-1", frames) })
	secret := "sk-supersecretvalue12"
	question := "Which library " + secret + "?"
	args := map[string]any{
		"questions": []any{map[string]any{
			"question": question, "header": "Lib", "multiSelect": false,
			"options": []any{
				map[string]any{"label": "Go", "description": "Go toolchain"},
				map[string]any{"label": "Rust", "description": "Rust toolchain"},
			},
		}},
	}
	out := make(chan permission.Outcome, 1)
	go func() {
		out <- app.perm.Evaluate(context.Background(), policy.Permission{
			Mode: "bypassPermissions", Allow: []string{"AskUserQuestion"},
			UIPrompts: true, PromptTimeout: 20 * time.Second, AllowSessionGrants: true,
		}, permission.Request{RunID: "run-1", BotID: "bot", Tool: "AskUserQuestion", Args: args})
	}()
	var reqID, raw string
	deadline := time.Now().Add(3 * time.Second)
	for reqID == "" && time.Now().Before(deadline) {
		select {
		case f := <-frames:
			if f.event != "permission_request" {
				continue
			}
			raw = string(f.data)
			var payload struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(f.data, &payload); err != nil {
				t.Fatal(err)
			}
			reqID = payload.ID
		case <-time.After(20 * time.Millisecond):
		}
	}
	if reqID == "" {
		t.Fatal("no permission_request")
	}
	if strings.Contains(raw, secret) || !strings.Contains(raw, `"kind":"question"`) || !strings.Contains(raw, `"session_allowed":false`) || !strings.Contains(raw, `"multiSelect":false`) {
		t.Fatalf("request %s", raw)
	}
	decide := srv.URL + "/api/bots/bot/runs/run-1/permissions/" + reqID
	redacted := "Which library [redacted]?"
	res, b := do(t, "POST", decide, map[string]any{"decision": "answer", "answers": map[string]string{"nope": "Go"}}, "sekrit")
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown question %d %s", res.StatusCode, b)
	}
	res, b = do(t, "POST", decide, map[string]any{
		"decision": "answer",
		"answers":  map[string]string{redacted: "Go"},
		"annotations": map[string]any{
			redacted: map[string]string{"preview": "card", "notes": "because"},
		},
	}, "sekrit")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("answer %d %s", res.StatusCode, b)
	}
	res, b = do(t, "POST", decide, map[string]any{"decision": "answer", "answers": map[string]string{redacted: "Go"}}, "sekrit")
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("second %d %s", res.StatusCode, b)
	}
	select {
	case got := <-out:
		want := `{"annotations":{"` + question + `":{"notes":"because","preview":"card"}},"answers":{"` + question + `":"Go"},"questions":[{"header":"Lib","multiSelect":false,"options":[{"description":"Go toolchain","label":"Go"},{"description":"Rust toolchain","label":"Rust"}],"question":"` + question + `"}]}`
		raw, err := json.Marshal(got.UpdatedInput)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != want || got.Behavior != "allow" || got.Decision != permission.Answer || got.Source != "ui" {
			t.Fatalf("outcome %s %+v", raw, got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("evaluate did not return")
	}

	bash := make(chan permission.Outcome, 1)
	go func() {
		bash <- app.perm.Evaluate(context.Background(), policy.Permission{UIPrompts: true, PromptTimeout: 20 * time.Second}, permission.Request{
			RunID: "run-1", BotID: "bot", Tool: "Bash", Args: map[string]any{"command": "ls"},
		})
	}()
	var bashID string
	deadline = time.Now().Add(3 * time.Second)
	for bashID == "" && time.Now().Before(deadline) {
		select {
		case f := <-frames:
			if f.event != "permission_request" {
				continue
			}
			var payload struct {
				ID   string `json:"id"`
				Tool string `json:"tool"`
			}
			if err := json.Unmarshal(f.data, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Tool == "Bash" {
				bashID = payload.ID
			}
		case <-time.After(20 * time.Millisecond):
		}
	}
	if bashID == "" {
		t.Fatal("no bash request")
	}
	bashURL := srv.URL + "/api/bots/bot/runs/run-1/permissions/" + bashID
	res, b = do(t, "POST", bashURL, map[string]any{"decision": "answer", "answers": map[string]string{"ls": "x"}}, "sekrit")
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("answer on bash %d %s", res.StatusCode, b)
	}
	res, b = do(t, "POST", bashURL, map[string]any{"decision": "deny"}, "sekrit")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("deny %d %s", res.StatusCode, b)
	}
	select {
	case got := <-bash:
		if got.Behavior != permission.Deny || got.Message != "denied by user" {
			t.Fatalf("bash outcome %+v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bash evaluate did not return")
	}
}

func TestRunTokenCannotDecide(t *testing.T) {
	if !lgbSupported {
		t.Fatal("lgb support is required")
	}
	dir := t.TempDir()
	app := newApp(t, dir, nil)
	app.cfg.AuthToken = "sekrit"
	bot, err := app.st.CreateBot("Ada", "d", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	app.rtMu.Lock()
	app.editPol(func(p *policy.Policy) { p.CLILGB = true })
	app.rtMu.Unlock()
	run, _, err := app.startLGB(context.Background(), bot, "run1", ws)
	if err != nil || run == nil || run.token == "" {
		t.Fatalf("start lgb: %v", err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		run.stop()
	}
	t.Cleanup(stop)
	srv := serve(t, app)
	decide := srv.URL + "/api/bots/" + bot.ID + "/runs/run1/permissions/missing"
	res, b := do(t, "POST", decide, map[string]any{"decision": "deny"}, run.token)
	if res.StatusCode != http.StatusForbidden || !strings.Contains(string(b), "run token") {
		t.Fatalf("lgb token %d %s", res.StatusCode, b)
	}
	perm := app.registerPerm(bot.ID, "run1", "sess")
	t.Cleanup(func() { app.unregisterPerm(perm) })
	res, b = do(t, "POST", decide, map[string]any{"decision": "deny"}, perm)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("perm token %d %s", res.StatusCode, b)
	}
	res, b = do(t, "POST", decide, map[string]any{"decision": "deny"}, strings.Repeat("ab", 32))
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown bearer %d %s", res.StatusCode, b)
	}
	res, b = do(t, "GET", srv.URL+"/api/bots", nil, run.token)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("lgb token on the API %d %s", res.StatusCode, b)
	}
	res, b = do(t, "POST", decide, map[string]any{"decision": "deny"}, "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing token %d %s", res.StatusCode, b)
	}
	req, err := http.NewRequest(http.MethodPost, decide, strings.NewReader(`{"decision":"deny"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: authCookie, Value: "sekrit"})
	cookieRes, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cookieBody, _ := io.ReadAll(cookieRes.Body)
	cookieRes.Body.Close()
	if cookieRes.StatusCode != http.StatusNotFound {
		t.Fatalf("admin cookie %d %s", cookieRes.StatusCode, cookieBody)
	}
	spent := run.token
	stop()
	res, b = do(t, "POST", decide, map[string]any{"decision": "deny"}, spent)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stopped lgb token %d %s", res.StatusCode, b)
	}

	open := newApp(t, t.TempDir(), nil)
	open.cfg.AuthToken = ""
	openBot, err := open.st.CreateBot("Bea", "d", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	openWS := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(openWS, 0o755); err != nil {
		t.Fatal(err)
	}
	open.rtMu.Lock()
	open.editPol(func(p *policy.Policy) { p.CLILGB = true })
	open.rtMu.Unlock()
	openRun, _, err := open.startLGB(context.Background(), openBot, "run1", openWS)
	if err != nil || openRun == nil {
		t.Fatal(err)
	}
	t.Cleanup(openRun.stop)
	openSrv := serve(t, open)
	openURL := openSrv.URL + "/api/bots/" + openBot.ID + "/runs/run1/permissions/missing"
	res, b = do(t, "POST", openURL, map[string]any{"decision": "deny"}, openRun.token)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("empty admin, live token %d %s", res.StatusCode, b)
	}
	res, b = do(t, "POST", openURL, map[string]any{"decision": "deny"}, "")
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("empty admin, no token %d %s", res.StatusCode, b)
	}
	res, b = do(t, "GET", openSrv.URL+"/api/bots", nil, openRun.token)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("empty admin still allows other routes %d %s", res.StatusCode, b)
	}
}

type questionFix struct {
	t         *testing.T
	app       *App
	url       string
	bot       store.Bot
	runID     string
	events    <-chan string
	gate      string
	outPath   string
	stdinPath string
	auditPath string
	lg        *audit.Logger
	transport string
}

func startQuestion(t *testing.T, transport, mode, input string, timeout time.Duration) *questionFix {
	t.Helper()
	dir := t.TempDir()
	installFakeClaude(t, dir)
	f := &questionFix{
		t:         t,
		gate:      filepath.Join(dir, "gate"),
		outPath:   filepath.Join(dir, "question.out"),
		stdinPath: filepath.Join(dir, "stdin.log"),
		auditPath: filepath.Join(dir, "audit.log"),
		transport: transport,
	}
	t.Setenv("LGB_FAKE_MODE", mode)
	t.Setenv("LGB_FAKE_GATE", f.gate)
	t.Setenv("LGB_QUESTION_INPUT", input)
	t.Setenv("LGB_QUESTION_OUT", f.outPath)
	t.Setenv("LGB_STDIN_LOG", f.stdinPath)
	t.Setenv("LGB_ARGV_LOG", filepath.Join(dir, "argv.log"))
	app := newApp(t, dir, nil)
	app.cfg.AuthToken = "sekrit"
	lg, err := audit.Open(f.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	app.cliTTY = func() bool { return false }
	app.rtMu.Lock()
	app.setPol(policy.Policy{
		Backend: "claude", CLIPermitted: true, TimersEnabled: true,
		Idle: time.Hour, Imminent: time.Minute, CLILGB: true,
		UIPrompts: true, PromptTimeout: timeout, AllowSessionGrants: true,
		ClaudeTransport: transport, PermissionMode: "bypassPermissions",
		ToolAllow: []string{"AskUserQuestion"},
	})
	app.rtMu.Unlock()
	srv := serve(t, app)
	app.permBase = srv.URL
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Ada", "description": "p"}, "sekrit")
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{"content": "go"}, "sekrit")
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	var posted struct {
		RunID string `json:"run_id"`
	}
	decodeJSON(t, b, &posted)
	if posted.RunID == "" {
		t.Fatalf("no run %s", b)
	}
	f.app = app
	f.url = srv.URL
	f.bot = bot
	f.runID = posted.RunID
	f.lg = lg
	f.events = questionSSE(t, srv.URL, bot.ID, posted.RunID, "sekrit")
	waitSubscribed(t, app, posted.RunID)
	return f
}

func (f *questionFix) openGate() {
	f.t.Helper()
	if err := os.WriteFile(f.gate, []byte("go\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *questionFix) decide(id string) string {
	return f.url + "/api/bots/" + f.bot.ID + "/runs/" + f.runID + "/permissions/" + id
}

func (f *questionFix) waitRequest() (string, string) {
	f.t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case ev := <-f.events:
			if !strings.HasPrefix(ev, "permission_request\n") {
				continue
			}
			raw := strings.TrimPrefix(ev, "permission_request\n")
			var payload struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal([]byte(raw), &payload); err != nil {
				f.t.Fatal(err)
			}
			if payload.ID != "" {
				return payload.ID, raw
			}
		case <-time.After(20 * time.Millisecond):
		}
	}
	f.t.Fatal("no permission_request")
	return "", ""
}

func (f *questionFix) rejectRunTokens(decide string) {
	f.t.Helper()
	toks := f.app.lgbTokens()
	if len(toks) != 1 || !strings.HasPrefix(toks[0], "lgbr_") {
		f.t.Fatalf("lgb tokens %v", toks)
	}
	res, b := do(f.t, "POST", decide, map[string]any{"decision": "answer", "answers": map[string]string{"Which library?": "Go"}}, toks[0])
	if res.StatusCode != http.StatusForbidden {
		f.t.Fatalf("lgb token %d %s", res.StatusCode, b)
	}
	if f.transport == policy.TransportMCP {
		perms := f.app.permTokenList()
		if len(perms) != 1 {
			f.t.Fatalf("perm tokens %v", perms)
		}
		res, b = do(f.t, "POST", decide, map[string]any{"decision": "answer", "answers": map[string]string{"Which library?": "Go"}}, perms[0])
		if res.StatusCode != http.StatusForbidden {
			f.t.Fatalf("perm token %d %s", res.StatusCode, b)
		}
	}
	res, b = do(f.t, "POST", decide, map[string]any{"decision": "answer"}, "not-a-token")
	if res.StatusCode != http.StatusUnauthorized {
		f.t.Fatalf("random token %d %s", res.StatusCode, b)
	}
	res, b = do(f.t, "POST", decide, map[string]any{"decision": "answer"}, "")
	if res.StatusCode != http.StatusUnauthorized {
		f.t.Fatalf("missing token %d %s", res.StatusCode, b)
	}
}

func (f *questionFix) waitDone() store.Bot {
	f.t.Helper()
	waitIdle(f.t, f.url, f.bot.ID, "sekrit")
	got, err := f.app.st.GetBot(f.bot.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	return got
}

func (f *questionFix) responseBody() string {
	f.t.Helper()
	if f.transport == policy.TransportStreamControl {
		return controlResponseBody(f.t, stdinLines(f.t, f.stdinPath))
	}
	b, err := os.ReadFile(f.outPath)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(b)
}

func (f *questionFix) assertQuestionRecord(answered int, source, decision string, free bool) {
	f.t.Helper()
	if err := f.lg.Close(); err != nil {
		f.t.Fatal(err)
	}
	raw, err := os.ReadFile(f.auditPath)
	if err != nil {
		f.t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{`"kind":"question"`, `"source":"` + source + `"`, `"decision":"` + decision + `"`, `"answered":` + strconv.Itoa(answered)} {
		if !strings.Contains(text, want) {
			f.t.Fatalf("audit missing %s in %s", want, text)
		}
	}
	if strings.Count(text, `"kind":"question"`) != 1 {
		f.t.Fatalf("audit decisions %s", text)
	}
	tools, err := f.app.st.RunTools([]string{f.runID})
	if err != nil {
		f.t.Fatal(err)
	}
	var n int
	for _, rec := range tools[f.runID] {
		if rec.Kind != "permission" {
			continue
		}
		n++
		if rec.Name != "AskUserQuestion" || rec.OK != (decision == permission.Answer) {
			f.t.Fatalf("record %+v", rec)
		}
		if !strings.Contains(rec.Result, `"kind":"question"`) || !strings.Contains(rec.Result, `"answered":`+strconv.Itoa(answered)) || !strings.Contains(rec.Result, `"source":"`+source+`"`) {
			f.t.Fatalf("detail %s", rec.Result)
		}
		if free && strings.Contains(rec.Result, "my own pick") {
			f.t.Fatalf("stored the answer: %s", rec.Result)
		}
	}
	if n != 1 {
		f.t.Fatalf("permission records %d in %+v", n, tools[f.runID])
	}
}

func controlResponseBody(t *testing.T, lines []string) string {
	t.Helper()
	for _, line := range lines {
		if !strings.Contains(line, `"request_id":"req_q_1"`) || !strings.Contains(line, `"type":"control_response"`) {
			continue
		}
		var msg struct {
			Response struct {
				Response json.RawMessage `json:"response"`
			} `json:"response"`
		}
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatal(err)
		}
		return string(msg.Response.Response)
	}
	t.Fatalf("missing control response: %#v", lines)
	return ""
}

func questionSSE(t *testing.T, base, botID, runID, token string) <-chan string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+"/api/bots/"+botID+"/thread/stream?run_id="+runID+"&prompts=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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
	events := make(chan string, 64)
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
	return events
}

func TestQuestionSkipSaysSkipped(t *testing.T) {
	const want = `{"behavior":"deny","message":"The user did not answer the question (skipped)."}`
	for _, transport := range []string{policy.TransportMCP, policy.TransportStreamControl} {
		t.Run(transport, func(t *testing.T) {
			f := startQuestion(t, transport, "question", qSingleIn, 20*time.Second)
			f.openGate()
			id, raw := f.waitRequest()
			if !strings.Contains(raw, `"kind":"question"`) {
				t.Fatalf("request %s", raw)
			}
			res, b := do(t, "POST", f.decide(id), map[string]any{"decision": "deny"}, "sekrit")
			if res.StatusCode != http.StatusOK {
				t.Fatalf("skip %d %s", res.StatusCode, b)
			}
			got := f.waitDone()
			if got.LastRunStatus != "done" || got.LastRunError != "" {
				t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
			}
			if body := f.responseBody(); body != want {
				t.Fatalf("response\n%s\nwant\n%s", body, want)
			}
			f.assertQuestionRecord(0, "ui", "deny", false)
		})
	}
}

func TestFreeTextAnswerIs400(t *testing.T) {
	app := newApp(t, t.TempDir(), nil)
	app.cfg.AuthToken = "sekrit"
	srv := serve(t, app)
	_, frames := app.bus.SubscribePrompts("run-1")
	t.Cleanup(func() { app.bus.Unsubscribe("run-1", frames) })
	out := make(chan permission.Outcome, 1)
	go func() {
		out <- app.perm.Evaluate(context.Background(), policy.Permission{
			UIPrompts: true, PromptTimeout: 20 * time.Second,
		}, permission.Request{
			RunID: "run-1", BotID: "bot", Tool: "AskUserQuestion", Args: map[string]any{
				"questions": []any{map[string]any{
					"question": "Which library?", "header": "Lib", "multiSelect": false,
					"options": []any{
						map[string]any{"label": "Go", "description": "Go toolchain"},
						map[string]any{"label": "Rust", "description": "Rust toolchain"},
					},
				}},
			},
		})
	}()
	var reqID string
	deadline := time.Now().Add(3 * time.Second)
	for reqID == "" && time.Now().Before(deadline) {
		select {
		case f := <-frames:
			if f.event != "permission_request" {
				continue
			}
			var payload struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(f.data, &payload); err != nil {
				t.Fatal(err)
			}
			reqID = payload.ID
		case <-time.After(20 * time.Millisecond):
		}
	}
	if reqID == "" {
		t.Fatal("no permission_request")
	}
	decide := srv.URL + "/api/bots/bot/runs/run-1/permissions/" + reqID
	over := strings.Repeat("a", 4<<10+1)
	res, b := do(t, "POST", decide, map[string]any{"decision": "answer", "answers": map[string]string{"Which library?": over}}, "sekrit")
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "too long") {
		t.Fatalf("over 4KiB %d %s", res.StatusCode, b)
	}
	exact := strings.Repeat("b", 4<<10)
	res, b = do(t, "POST", decide, map[string]any{"decision": "answer", "answers": map[string]string{"Which library?": exact}}, "sekrit")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("4KiB answer %d %s", res.StatusCode, b)
	}
	select {
	case got := <-out:
		answers, _ := got.UpdatedInput["answers"].(map[string]any)
		if got.Decision != permission.Answer || answers["Which library?"] != exact {
			t.Fatalf("%+v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("evaluate did not return")
	}
}
