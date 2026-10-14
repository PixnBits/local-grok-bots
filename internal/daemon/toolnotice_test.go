package daemon

import (
	"strings"
	"sync"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestDiffToolsByName(t *testing.T) {
	old := []model.Tool{
		{Name: "set_timer", Description: "d", Parameters: schemaObj(map[string]any{"schedule": prop("string", "x"), "prompt": prop("string", "p")}, "prompt")},
		{Name: "gone", Description: "g", Parameters: schemaObj(map[string]any{})},
		{Name: "same", Description: "s", Parameters: schemaObj(map[string]any{})},
	}
	cur := []model.Tool{
		{Name: "set_timer", Description: "d", Parameters: schemaObj(map[string]any{"in": prop("string", "x"), "at": prop("string", "x"), "every": prop("string", "x"), "prompt": prop("string", "p")}, "prompt")},
		{Name: "same", Description: "s", Parameters: schemaObj(map[string]any{})},
		{Name: "list_timers", Description: "l", Parameters: schemaObj(map[string]any{})},
	}
	h1, s1 := toolSnapshot(old)
	h2, s2 := toolSnapshot(cur)
	if h1 == h2 {
		t.Fatal("hash did not change")
	}
	if h, _ := toolSnapshot(cur); h != h2 {
		t.Fatal("hash not stable")
	}
	got := diffTools(s1, s2)
	for _, want := range []string{"added list_timers", "changed set_timer (now takes at/every/in/prompt)", "removed gone"} {
		if !strings.Contains(got, want) {
			t.Fatalf("diff %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "same") {
		t.Fatalf("unchanged tool reported: %q", got)
	}
}

func lastUserNotices(req model.ChatRequest) []string {
	var out []string
	for _, m := range req.Messages {
		if m.Role == "user" && strings.HasPrefix(m.Content, "Notice: Tools") {
			out = append(out, m.Content)
		}
	}
	return out
}

// A bot from before snapshots, whose history claims it lacks tools, gets a
// one-time Notice listing current tools; the model sees it, and the next
// run posts nothing new. A changed tool list then gets a diff notice.
func TestToolNoticesReachModel(t *testing.T) {
	var mu sync.Mutex
	var reqs []model.ChatRequest
	app := newApp(t, "", fakeModel{fn: func(req model.ChatRequest) (model.ChatResponse, error) {
		mu.Lock()
		reqs = append(reqs, req)
		mu.Unlock()
		return model.ChatResponse{Content: "ok"}, nil
	}})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Stale")
	if _, err := app.st.AddMessage(store.Message{BotID: bot.ID, Thread: "user", Role: "bot", Content: "I only have write_memory and delete_memory."}); err != nil {
		t.Fatal(err)
	}
	send := func(text string) model.ChatRequest {
		do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": text}, "")
		waitIdle(t, srv.URL, bot.ID, "")
		mu.Lock()
		defer mu.Unlock()
		return reqs[len(reqs)-1]
	}
	n := lastUserNotices(send("what tools do you have?"))
	if len(n) != 1 || !strings.Contains(n[0], "Tools available now: ") || !strings.Contains(n[0], "set_timer") {
		t.Fatalf("notices = %q", n)
	}
	if n := lastUserNotices(send("again")); len(n) != 1 {
		t.Fatalf("second run notices = %q, want the same single one", n)
	}
	// Pretend the bot last saw a list without list_timers.
	var older []model.Tool
	for _, d := range toolDefs() {
		if d.Name != "list_timers" {
			older = append(older, d)
		}
	}
	h, s := toolSnapshot(older)
	if err := app.st.SetToolSnapshot(bot.ID, h, s); err != nil {
		t.Fatal(err)
	}
	n = lastUserNotices(send("and now?"))
	if len(n) != 2 || n[1] != "Notice: Tools updated: added list_timers." {
		t.Fatalf("notices = %q", n)
	}
	page, _, err := app.st.ToolSnapshot(bot.ID)
	if want, _ := toolSnapshot(toolDefs()); err != nil || page != want {
		t.Fatalf("snapshot not saved: %v", err)
	}
}

// A brand-new bot records its snapshot without posting a notice.
func TestNewBotGetsNoToolNotice(t *testing.T) {
	var mu sync.Mutex
	var reqs []model.ChatRequest
	app := newApp(t, "", fakeModel{fn: func(req model.ChatRequest) (model.ChatResponse, error) {
		mu.Lock()
		reqs = append(reqs, req)
		mu.Unlock()
		return model.ChatResponse{Content: "ok"}, nil
	}})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Fresh")
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "hi"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	if n := lastUserNotices(reqs[0]); len(n) != 0 {
		t.Fatalf("notices = %q", n)
	}
	if h, _, _ := app.st.ToolSnapshot(bot.ID); h == "" {
		t.Fatal("snapshot not recorded")
	}
}
