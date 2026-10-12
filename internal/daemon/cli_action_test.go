package daemon

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestCLICannotDMOrCreate(t *testing.T) {
	var notes []string
	var noteMu sync.Mutex
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "got it"}, nil
	}})
	app.notifyFn = func(title, body string) {
		noteMu.Lock()
		notes = append(notes, title+":"+body)
		noteMu.Unlock()
	}
	var mu sync.Mutex
	var specs []clisession.Spec
	app.runner = runnerFunc(func(_ context.Context, spec clisession.Spec, onEvent func(clisession.Event)) (clisession.Result, error) {
		mu.Lock()
		specs = append(specs, spec)
		mu.Unlock()
		if onEvent != nil {
			onEvent(clisession.Event{Kind: "token", Text: "ok"})
		}
		if strings.Contains(spec.Prompt, "Daemon action results") {
			return clisession.Result{SessionID: spec.SessionID, Text: "Stopped."}, nil
		}
		if strings.Contains(spec.Prompt, "make bea") {
			return clisession.Result{SessionID: spec.SessionID, Text: "Created Bea.\n\n```action\n{\"tool\":\"create_bot\",\"name\":\"Bea\",\"description\":\"helps\"}\n```"}, nil
		}
		return clisession.Result{SessionID: spec.SessionID, Text: "Sent.\n\n```action\n{\"tool\":\"send_dm\",\"to\":\"Bob\",\"content\":\"ping\"}\n```"}, nil
	})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada", "description": "coordinator", "cli_backend": "grok",
	}, "")
	var ada store.Bot
	decodeJSON(t, b, &ada)
	_, b = do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Bob", "description": "listener",
	}, "")
	var bob store.Bot
	decodeJSON(t, b, &bob)

	do(t, "POST", srv.URL+"/api/bots/"+ada.ID+"/thread/messages", map[string]string{"content": "ping bob"}, "")
	waitIdle(t, srv.URL, ada.ID, "")
	waitIdle(t, srv.URL, bob.ID, "")

	var replies []string
	for _, m := range botThread(t, srv.URL, ada.ID) {
		if m.Role == "bot" {
			replies = append(replies, m.Content)
		}
	}
	if len(replies) != 1 || replies[0] != "Stopped." || strings.Contains(replies[0], "action") {
		t.Fatalf("ada replies %#v", replies)
	}
	dms, err := app.st.ListMessages(bob.ID, "dm:"+ada.ID, "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(dms) != 0 {
		t.Fatalf("bob dm %#v", dms)
	}
	if hasMessage(botThread(t, srv.URL, bob.ID), "system", "Message from Ada") {
		t.Fatal("notice was posted")
	}
	if len(logKind(t, srv.URL, "dm_sent")) != 0 || len(logKind(t, srv.URL, "dm_received")) != 0 {
		t.Fatal("dm was logged")
	}
	mu.Lock()
	if len(specs) < 1 || !strings.Contains(specs[0].Prompt, "A bot cannot") || strings.Contains(specs[0].Prompt, "send_dm (to, content)") {
		t.Fatalf("preamble still offers send_dm, specs=%d", len(specs))
	}
	mu.Unlock()

	do(t, "POST", srv.URL+"/api/bots/"+ada.ID+"/thread/messages", map[string]string{"content": "make bea"}, "")
	waitIdle(t, srv.URL, ada.ID, "")
	res, b := do(t, "GET", srv.URL+"/api/bots", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("list %d %s", res.StatusCode, b)
	}
	var bots []store.Bot
	decodeJSON(t, b, &bots)
	for i := range bots {
		if bots[i].Name == "Bea" {
			t.Fatal("Bea was created")
		}
	}
	if len(logKind(t, srv.URL, "bot_created")) != 2 {
		t.Fatal("create_bot was logged")
	}
	replies = nil
	for _, m := range botThread(t, srv.URL, ada.ID) {
		if m.Role == "bot" {
			replies = append(replies, m.Content)
		}
	}
	if len(replies) != 2 || replies[1] != "Stopped." {
		t.Fatalf("replies %#v", replies)
	}
	noteMu.Lock()
	defer noteMu.Unlock()
	if len(notes) < 2 || !strings.Contains(notes[0], "Ada:") {
		t.Fatalf("notes %#v", notes)
	}
}

func TestCLINeedsInputNotification(t *testing.T) {
	var title, body string
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{}, nil
	}})
	app.notifyFn = func(ti, bo string) {
		title, body = ti, bo
	}
	app.runner = runnerFunc(func(_ context.Context, spec clisession.Spec, _ func(clisession.Event)) (clisession.Result, error) {
		return clisession.Result{SessionID: spec.SessionID, Text: "which file?", NeedsInput: true}, nil
	})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada", "cli_backend": "grok",
	}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "edit"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	if title != "Ada needs input" || body != "which file?" {
		t.Fatalf("notify %q %q", title, body)
	}
}

func TestCLIQueryFollowUp(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{}, nil
	}})
	var mu sync.Mutex
	var prompts []string
	app.runner = runnerFunc(func(_ context.Context, spec clisession.Spec, _ func(clisession.Event)) (clisession.Result, error) {
		mu.Lock()
		prompts = append(prompts, spec.Prompt)
		n := len(prompts)
		mu.Unlock()
		if n == 1 {
			return clisession.Result{SessionID: spec.SessionID, Text: "```action\n{\"tool\":\"list_bots\"}\n```"}, nil
		}
		return clisession.Result{SessionID: spec.SessionID, Text: "just Ada"}, nil
	})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada", "cli_backend": "grok",
	}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "who"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	mu.Lock()
	defer mu.Unlock()
	if len(prompts) != 2 || !strings.Contains(prompts[1], "Daemon action results") || !strings.Contains(prompts[1], "Ada") {
		t.Fatalf("prompts %#v", prompts)
	}
	var replies []string
	for _, m := range botThread(t, srv.URL, bot.ID) {
		if m.Role == "bot" {
			replies = append(replies, m.Content)
		}
	}
	if len(replies) != 1 || replies[0] != "just Ada" {
		t.Fatalf("replies %#v", replies)
	}
}
