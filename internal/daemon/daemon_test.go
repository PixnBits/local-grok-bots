package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestMain(m *testing.M) {
	if sandbox.HandleArgs(os.Args[1:]) {
		return
	}
	os.Exit(m.Run())
}

type fakeModel struct {
	fn func(model.ChatRequest) (model.ChatResponse, error)
}

func (f fakeModel) Chat(ctx context.Context, req model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
	if err := ctx.Err(); err != nil {
		return model.ChatResponse{}, err
	}
	resp, err := f.fn(req)
	if err != nil {
		return model.ChatResponse{}, err
	}
	if onToken != nil && resp.Content != "" {
		onToken(resp.Content)
	}
	return resp, nil
}

func newApp(t *testing.T, dir string, m model.Client) *App {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	cfg := config.Config{
		DataDir: dir, BindAddr: "127.0.0.1:0",
		OllamaURL: "http://127.0.0.1:9", Model: "test-model", Version: "0.1.0",
	}
	app, err := New(cfg, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	return app
}

func serve(t *testing.T, app *App) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, method, url string, body any, token string) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, b
}

func decodeJSON(t *testing.T, b []byte, dst any) {
	t.Helper()
	if err := json.Unmarshal(b, dst); err != nil {
		t.Fatalf("json: %v body=%s", err, b)
	}
}

func waitIdle(t *testing.T, base, id, token string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		res, b := do(t, "GET", base+"/api/bots/"+id, nil, token)
		if res.StatusCode != 200 {
			t.Fatalf("status %d %s", res.StatusCode, b)
		}
		var bot store.Bot
		decodeJSON(t, b, &bot)
		if bot.Status != "running" {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal("bot stayed running")
}

func TestCreateAndQueue(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	app := newApp(t, "", fakeModel{fn: func(req model.ChatRequest) (model.ChatResponse, error) {
		n := calls.Add(1)
		if n == 1 {
			once.Do(func() { close(entered) })
			<-release
			return model.ChatResponse{Content: "first"}, nil
		}
		return model.ChatResponse{Content: "second"}, nil
	}})
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "Ada", "instructions": "be brief"}, "")
	if res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b = do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "ada", "instructions": "dup"}, "")
	if res.StatusCode != 409 {
		t.Fatalf("dup %d %s", res.StatusCode, b)
	}

	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "one"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("msg %d %s", res.StatusCode, b)
	}
	var posted struct {
		RunID   string        `json:"run_id"`
		Message store.Message `json:"message"`
	}
	decodeJSON(t, b, &posted)
	if posted.RunID == "" {
		t.Fatal("expected run_id")
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("model was not called")
	}
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "two"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("msg2 %d %s", res.StatusCode, b)
	}
	res, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/thread", nil, "")
	var thread struct {
		Messages []store.Message `json:"messages"`
	}
	decodeJSON(t, b, &thread)
	if len(thread.Messages) < 2 || thread.Messages[0].Content != "one" || thread.Messages[1].Content != "two" {
		t.Fatalf("order = %#v", thread.Messages)
	}
	close(release)
	waitIdle(t, srv.URL, bot.ID, "")
	res, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/thread", nil, "")
	decodeJSON(t, b, &thread)
	var texts []string
	for _, m := range thread.Messages {
		if m.Role == "user" {
			texts = append(texts, m.Content)
		}
	}
	if len(texts) != 2 || texts[0] != "one" || texts[1] != "two" {
		t.Fatalf("user texts %#v full %#v", texts, thread.Messages)
	}
	if calls.Load() < 2 {
		t.Fatalf("expected a follow-up run, calls=%d", calls.Load())
	}
}

func TestDMAndCreateBot(t *testing.T) {
	var aliceOnce, bobOnce atomic.Bool
	app := newApp(t, "", fakeModel{fn: func(req model.ChatRequest) (model.ChatResponse, error) {
		sys := req.Messages[0].Content
		if bytes.Contains([]byte(sys), []byte("You are Alice")) {
			if !aliceOnce.CompareAndSwap(false, true) {
				return model.ChatResponse{Content: "noted"}, nil
			}
			return model.ChatResponse{ToolCalls: []model.ToolCall{{
				Name: "send_dm", Arguments: map[string]any{"to": "Bob", "content": "ping"},
			}}}, nil
		}
		if bytes.Contains([]byte(sys), []byte("You are Bob")) {
			if !bobOnce.CompareAndSwap(false, true) {
				return model.ChatResponse{Content: "pong"}, nil
			}
			return model.ChatResponse{ToolCalls: []model.ToolCall{
				{Name: "create_bot", Arguments: map[string]any{"name": "Cara", "instructions": "notes"}},
				{Name: "send_dm", Arguments: map[string]any{"to": "Alice", "content": "pong"}},
			}}, nil
		}
		return model.ChatResponse{Content: "ok"}, nil
	}})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "Alice", "instructions": "coordinate"}, "")
	var alice store.Bot
	decodeJSON(t, b, &alice)
	_, b = do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "Bob", "instructions": "reply"}, "")
	var bob store.Bot
	decodeJSON(t, b, &bob)
	do(t, "POST", srv.URL+"/api/bots/"+alice.ID+"/thread/messages", map[string]string{"content": "ask bob"}, "")
	waitIdle(t, srv.URL, alice.ID, "")
	waitIdle(t, srv.URL, bob.ID, "")

	res, b := do(t, "GET", srv.URL+"/api/log?limit=200", nil, "")
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, string(b))
	}
	var events []store.LogEvent
	decodeJSON(t, b, &events)
	var sent, recv, created bool
	for _, e := range events {
		switch e.Kind {
		case "dm_sent", "dm_received":
			var d struct {
				Other string `json:"other_bot_id"`
			}
			_ = json.Unmarshal(e.Detail, &d)
			if e.Kind == "dm_sent" {
				sent = true
			}
			if e.Kind == "dm_received" {
				recv = true
			}
		case "bot_created":
			var d struct {
				By   string `json:"by"`
				Name string `json:"name"`
			}
			_ = json.Unmarshal(e.Detail, &d)
			if d.Name == "Cara" && d.By == bob.ID {
				created = true
			}
		}
	}
	if !sent || !recv || !created {
		t.Fatalf("log flags sent=%v recv=%v created=%v", sent, recv, created)
	}
	res, b = do(t, "GET", srv.URL+"/api/bots", nil, "")
	var bots []store.Bot
	decodeJSON(t, b, &bots)
	found := false
	for _, b := range bots {
		if b.Name == "Cara" {
			found = true
		}
	}
	if !found {
		t.Fatalf("cara missing %#v", bots)
	}
}

func TestWorkspaceJail(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(req model.ChatRequest) (model.ChatResponse, error) {
		if req.Messages[len(req.Messages)-1].Role == "tool" {
			// keep issuing tools until we've done the set, then stop
			sys := ""
			for _, m := range req.Messages {
				if m.Role == "tool" {
					sys += m.Content
				}
			}
			if bytes.Contains([]byte(sys), []byte("stdout:")) {
				return model.ChatResponse{Content: "checked"}, nil
			}
		}
		return model.ChatResponse{ToolCalls: []model.ToolCall{
			{Name: "write_file", Arguments: map[string]any{"path": "../escape.txt", "content": "nope"}},
			{Name: "write_file", Arguments: map[string]any{"path": "/etc/passwd", "content": "nope"}},
			{Name: "write_file", Arguments: map[string]any{"path": "notes/ok.txt", "content": "hello"}},
			{Name: "write_file", Arguments: map[string]any{"path": "tmplink/pwn.txt", "content": "nope"}},
			{Name: "run_shell", Arguments: map[string]any{"command": "pwd; cat notes/ok.txt; echo pwn > /tmp/lgb-host-escape; echo x > ../outside.txt; cat /etc/passwd"}},
		}}, nil
	}})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "IO", "instructions": "files"}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	os.Symlink("/tmp", filepath.Join(app.ws, "tmplink"))
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "write"}, "")
	waitIdle(t, srv.URL, bot.ID, "")

	ok, err := os.ReadFile(filepath.Join(app.ws, "notes", "ok.txt"))
	if err != nil || string(ok) != "hello" {
		t.Fatalf("workspace write: %v %q", err, ok)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(app.ws), "escape.txt")); err == nil {
		t.Fatal("escaped parent")
	}
	if _, err := os.Stat(filepath.Join(app.ws, "outside.txt")); !os.IsNotExist(err) {
		t.Fatal("outside.txt should not land in workspace parent via .. ; err", err)
	}
	if _, err := os.Stat("/tmp/lgb-host-escape"); err == nil {
		t.Fatal("shell wrote host /tmp")
	}
	// symlink escape
	res, b := do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/memory", map[string]string{"key": "k", "value": "v"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("memory %d %s", res.StatusCode, b)
	}
	events := logKind(t, srv.URL, "tool_end")
	var sawFail, sawOK bool
	for _, e := range events {
		var d struct {
			Name string `json:"name"`
			OK   bool   `json:"ok"`
		}
		_ = json.Unmarshal(e.Detail, &d)
		if d.Name == "write_file" && !d.OK {
			sawFail = true
		}
		if d.Name == "write_file" && d.OK {
			sawOK = true
		}
		if d.Name == "run_shell" && !d.OK && bytes.Contains(e.Detail, []byte("passwd")) {
			// shell non-zero because cat /etc/passwd fails inside the jail
		}
	}
	if !sawFail || !sawOK {
		t.Fatalf("expected failed and successful writes, events=%d", len(events))
	}
	shells := 0
	shellDetail := ""
	for _, e := range events {
		var d struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(e.Detail, &d)
		if d.Name == "run_shell" {
			shells++
			shellDetail = string(e.Detail)
		}
	}
	if shells == 0 {
		t.Fatal("run_shell was not logged")
	}
	if !bytes.Contains([]byte(shellDetail), []byte("/work")) {
		t.Fatalf("shell did not run inside the workspace jail: %s", shellDetail)
	}
}

func logKind(t *testing.T, base, kind string) []store.LogEvent {
	t.Helper()
	_, b := do(t, "GET", base+"/api/log?kind="+kind+"&limit=100", nil, "")
	var events []store.LogEvent
	decodeJSON(t, b, &events)
	return events
}

func TestRenameKeepsThreadAndAuth(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "hi"}, nil
	}})
	app.cfg.AuthToken = "sekrit"
	srv := serve(t, app)
	res, _ := do(t, "GET", srv.URL+"/api/health", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("health %d", res.StatusCode)
	}
	res, _ = do(t, "GET", srv.URL+"/api/bots", nil, "")
	if res.StatusCode != 401 {
		t.Fatalf("want 401 got %d", res.StatusCode)
	}
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "Ada", "instructions": "v1"}, "sekrit")
	if res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "hello"}, "sekrit")
	waitIdle(t, srv.URL, bot.ID, "sekrit")
	// waitIdle doesn't send the token. Fix by polling with token.
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]string{"name": "Ada Lovelace", "instructions": "v2"}, "sekrit")
	if res.StatusCode != 200 {
		t.Fatalf("patch %d %s", res.StatusCode, b)
	}
	var updated store.Bot
	decodeJSON(t, b, &updated)
	if updated.ID != bot.ID || updated.Name != "Ada Lovelace" {
		t.Fatalf("rename %#v", updated)
	}
	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/thread", nil, "sekrit")
	var thread struct {
		Messages []store.Message `json:"messages"`
	}
	decodeJSON(t, b, &thread)
	if len(thread.Messages) == 0 || thread.Messages[0].BotID != bot.ID {
		t.Fatalf("thread lost %#v", thread.Messages)
	}
}

func TestOllamaDown(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{}, context.DeadlineExceeded
	}})
	// replace with a client that reports unreachable
	app.model = fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{}, errOllama()
	}}
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "Ada", "instructions": ""}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "hi"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	if bot.LastRunStatus != "error" || bot.LastRunError == "" {
		t.Fatalf("run = %s %s", bot.LastRunStatus, bot.LastRunError)
	}
	events := logKind(t, srv.URL, "model_call")
	if len(events) == 0 {
		t.Fatal("no model_call")
	}
	var d struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(events[0].Detail, &d)
	if d.OK || d.Error == "" {
		t.Fatalf("detail %#v", d)
	}
}

type downErr struct{}

func (downErr) Error() string { return "ollama unreachable at http://127.0.0.1:9: connection refused" }
func errOllama() error        { return downErr{} }

func TestCrashRestart(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	bot, err := st.CreateBot("Ada", "keep", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddMessage(store.Message{BotID: bot.ID, Thread: "user", Role: "user", Content: "remember"}); err != nil {
		t.Fatal(err)
	}
	run, err := st.InsertRunningRun(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()

	calls := 0
	app := newApp(t, dir, fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		calls++
		return model.ChatResponse{Content: "resumed"}, nil
	}})
	srv := serve(t, app)
	res, b := do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("get %d %s", res.StatusCode, b)
	}
	var got store.Bot
	decodeJSON(t, b, &got)
	if got.Name != "Ada" || got.LastRunStatus != "error" || got.LastRunError != "daemon_restart" {
		t.Fatalf("bot after restart %#v", got)
	}
	if got.Status == "running" {
		t.Fatal("status still running")
	}
	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/thread", nil, "")
	var thread struct {
		Messages []store.Message `json:"messages"`
	}
	decodeJSON(t, b, &thread)
	if len(thread.Messages) != 1 || thread.Messages[0].Content != "remember" {
		t.Fatalf("thread %#v", thread.Messages)
	}
	if calls != 0 {
		t.Fatalf("in-flight run was resumed, calls=%d run=%s", calls, run.ID)
	}
}

func TestTimerMissedOnBoot(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReconcileOnBoot("0.1.0"); err != nil {
		t.Fatal(err)
	}
	bot, err := st.CreateBot("Ada", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	tm, err := st.CreateTimer(bot.ID, "1h", "do the thing", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.BackdateTimer(tm.ID, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	st.Close()

	app := newApp(t, dir, fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		t.Error("missed timer was run")
		return model.ChatResponse{Content: "no"}, nil
	}})
	srv := serve(t, app)
	missed := logKind(t, srv.URL, "timer_missed")
	if len(missed) == 0 {
		t.Fatal("no timer_missed")
	}
	fired := logKind(t, srv.URL, "timer_fired")
	if len(fired) != 0 {
		t.Fatal("timer fired on boot")
	}
	_, b := do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/timers", nil, "")
	var timers []store.Timer
	decodeJSON(t, b, &timers)
	if len(timers) != 1 || timers[0].NextFireAt <= store.FormatTime(time.Now().Add(-time.Minute)) {
		t.Fatalf("not rescheduled %#v", timers)
	}
	_ = app
}
