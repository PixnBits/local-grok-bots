package daemon

import (
	"bufio"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestCLIStreamsTokens(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{}, nil
	}})
	app.runner = runnerFunc(func(_ context.Context, spec clisession.Spec, onEvent func(clisession.Event)) (clisession.Result, error) {
		if onEvent != nil {
			onEvent(clisession.Event{Kind: "token", Text: "He"})
			onEvent(clisession.Event{Kind: "token", Text: "llo"})
			onEvent(clisession.Event{Kind: "tool", ToolName: "read_file", ToolArgs: map[string]any{
				"command": "echo sk-abcdefghijklmnop", "api_key": "hunter2",
			}})
		}
		return clisession.Result{SessionID: spec.SessionID, Text: "Hello!"}, nil
	})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada", "description": "be brief", "cli_backend": "grok",
	}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	_, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "hi"}, "")
	var posted struct {
		RunID string `json:"run_id"`
	}
	decodeJSON(t, b, &posted)
	waitIdle(t, srv.URL, bot.ID, "")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/bots/"+bot.ID+"/thread/stream?run_id="+posted.RunID, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var tokens, tools string
	sc := bufio.NewScanner(res.Body)
	event := ""
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "event:") {
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}
		if event == "token" && strings.HasPrefix(line, "data:") {
			tokens += line
		}
		if event == "tool_call" && strings.HasPrefix(line, "data:") {
			tools += line
		}
		if event == "done" && strings.HasPrefix(line, "data:") {
			break
		}
	}
	if !strings.Contains(tokens, "He") || !strings.Contains(tokens, "llo") {
		t.Fatalf("tokens %q", tokens)
	}
	if !strings.Contains(tools, "read_file") || !strings.Contains(tools, "[redacted]") {
		t.Fatalf("tools %q", tools)
	}
	if strings.Contains(tools, "sk-abcdefghijklmnop") || strings.Contains(tools, "hunter2") {
		t.Fatalf("tools leaked %q", tools)
	}
	var logged bool
	for _, e := range logKind(t, srv.URL, "tool_start") {
		detail := string(e.Detail)
		if !strings.Contains(detail, "read_file") {
			continue
		}
		logged = true
		if strings.Contains(detail, "sk-abcdefghijklmnop") || strings.Contains(detail, "hunter2") || !strings.Contains(detail, "[redacted]") {
			t.Fatalf("log %s", detail)
		}
	}
	if !logged {
		t.Fatal("tool_start was not logged")
	}
	thread := botThread(t, srv.URL, bot.ID)
	var replies []string
	for _, m := range thread {
		if m.Role == "bot" {
			replies = append(replies, m.Content)
		}
	}
	if len(replies) != 1 || replies[0] != "Hello!" {
		t.Fatalf("replies %#v", replies)
	}
}

func TestCLIWorkspaceIsPrivate(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{}, nil
	}})
	var mu sync.Mutex
	got := map[string]string{}
	var preamble string
	app.runner = runnerFunc(func(_ context.Context, spec clisession.Spec, _ func(clisession.Event)) (clisession.Result, error) {
		mu.Lock()
		got[spec.SessionID] = spec.Workspace
		if preamble == "" {
			preamble = spec.Prompt
		}
		mu.Unlock()
		return clisession.Result{SessionID: spec.SessionID, Text: "ok"}, nil
	})
	srv := serve(t, app)
	var ids []string
	for _, name := range []string{"Ada", "Bea"} {
		_, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
			"name": name, "cli_backend": "grok",
		}, "")
		var bot store.Bot
		decodeJSON(t, b, &bot)
		ids = append(ids, bot.ID)
		do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "hi"}, "")
		waitIdle(t, srv.URL, bot.ID, "")
	}
	if len(got) != 2 {
		t.Fatalf("workspaces %#v", got)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		bot, err := app.st.GetBot(id)
		if err != nil {
			t.Fatal(err)
		}
		dir := got[bot.SessionID]
		want := filepath.Join(app.ws, "bots", id)
		if dir != want {
			t.Fatalf("workspace %s want %s", dir, want)
		}
		if seen[dir] {
			t.Fatalf("shared directory %s", dir)
		}
		seen[dir] = true
		st, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o700 {
			t.Fatalf("mode %o", st.Mode().Perm())
		}
	}
	if !strings.Contains(preamble, "private to this bot") || strings.Contains(preamble, "shared by every bot") {
		t.Fatalf("preamble %s", preamble)
	}
}

func TestCLITimerResumesSession(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		t.Errorf("ollama was called")
		return model.ChatResponse{}, nil
	}})
	var mu sync.Mutex
	var specs []clisession.Spec
	app.runner = runnerFunc(func(_ context.Context, spec clisession.Spec, _ func(clisession.Event)) (clisession.Result, error) {
		mu.Lock()
		specs = append(specs, spec)
		mu.Unlock()
		return clisession.Result{SessionID: spec.SessionID, Text: "ok"}, nil
	})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada", "cli_backend": "grok",
	}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "hello"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	res, b := do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	session := bot.SessionID
	if session == "" {
		t.Fatal("no session")
	}
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/timers", map[string]any{
		"name": "garden", "schedule": "1s", "prompt": "check the garden",
	}, "")
	if res.StatusCode != 201 {
		t.Fatalf("timer %d %s", res.StatusCode, b)
	}
	deadline := time.Now().Add(5 * time.Second)
	var got clisession.Spec
	for time.Now().Before(deadline) {
		waitIdle(t, srv.URL, bot.ID, "")
		mu.Lock()
		for _, spec := range specs {
			if strings.Contains(spec.Prompt, "[scheduled] check the garden") {
				got = spec
			}
		}
		mu.Unlock()
		if got.SessionID != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got.Fresh || got.SessionID != session || got.Backend != "grok" {
		t.Fatalf("timer spec %+v session %s", got, session)
	}
}

func TestCLIIdleKillThenResume(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{}, nil
	}})
	app.imminent = 2 * time.Hour
	started := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	var specs []clisession.Spec
	app.runner = runnerFunc(func(ctx context.Context, spec clisession.Spec, _ func(clisession.Event)) (clisession.Result, error) {
		mu.Lock()
		specs = append(specs, spec)
		n := len(specs)
		mu.Unlock()
		if n == 1 {
			if spec.OnStart != nil {
				spec.OnStart(4242)
			}
			once.Do(func() { close(started) })
			<-ctx.Done()
			return clisession.Result{SessionID: spec.SessionID}, ctx.Err()
		}
		return clisession.Result{SessionID: spec.SessionID, Text: "resumed"}, nil
	})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada", "cli_backend": "grok",
	}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "work"}, "")
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("cli did not start")
	}
	res, b := do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/timers", map[string]any{
		"schedule": "1h", "prompt": "later",
	}, "")
	if res.StatusCode != 201 {
		t.Fatalf("timer %d %s", res.StatusCode, b)
	}
	app.rtMu.Lock()
	app.activity[bot.ID] = time.Now().Add(-2 * time.Hour)
	app.rtMu.Unlock()
	app.killIdle()
	time.Sleep(150 * time.Millisecond)
	res, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	if bot.Status != "running" {
		t.Fatalf("imminent timer should keep the process, status %s", bot.Status)
	}
	app.imminent = time.Millisecond
	app.killIdle()
	waitIdle(t, srv.URL, bot.ID, "")
	res, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	if bot.SessionID == "" {
		t.Fatal("idle kill dropped the session")
	}
	session := bot.SessionID
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "next"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	mu.Lock()
	defer mu.Unlock()
	if len(specs) < 2 {
		t.Fatalf("specs %d", len(specs))
	}
	last := specs[len(specs)-1]
	if last.Fresh || last.SessionID != session || !strings.Contains(last.Prompt, "next") {
		t.Fatalf("resume spec %+v session %s", last, session)
	}
	thread := botThread(t, srv.URL, bot.ID)
	var saw bool
	for _, m := range thread {
		if m.Role == "bot" && m.Content == "resumed" {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("thread %#v", thread)
	}
}

func TestCLICancelResume(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{}, nil
	}})
	started := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	var specs []clisession.Spec
	app.runner = runnerFunc(func(ctx context.Context, spec clisession.Spec, _ func(clisession.Event)) (clisession.Result, error) {
		mu.Lock()
		specs = append(specs, spec)
		n := len(specs)
		mu.Unlock()
		if n == 1 {
			if spec.OnStart != nil {
				spec.OnStart(7)
			}
			once.Do(func() { close(started) })
			<-ctx.Done()
			return clisession.Result{SessionID: spec.SessionID}, ctx.Err()
		}
		return clisession.Result{SessionID: spec.SessionID, Text: "after"}, nil
	})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada", "cli_backend": "grok",
	}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	_, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "start"}, "")
	var posted struct {
		RunID string `json:"run_id"`
	}
	decodeJSON(t, b, &posted)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("cli did not start")
	}
	res, b := do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/runs/"+posted.RunID+"/cancel", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("cancel %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, "")
	res, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	session := bot.SessionID
	if session == "" {
		t.Fatal("cancel dropped the session")
	}
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "continue"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	mu.Lock()
	defer mu.Unlock()
	if len(specs) != 2 || specs[1].Fresh || specs[1].SessionID != session || !strings.Contains(specs[1].Prompt, "continue") {
		t.Fatalf("specs %#v session %s", specs, session)
	}
}
