package daemon

import (
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestBotStateEndpoint(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "ok"}, nil
	}})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Stateful")
	if _, err := app.st.CreateTimerAt(bot.ID, "walk", "walk the dog", time.Now().Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := app.st.CreateTimer(bot.ID, "standup", "1d", "post standup", true); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"a", "b"} {
		if _, err := app.st.UpsertMemory(bot.ID, k, "v"); err != nil {
			t.Fatal(err)
		}
	}
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "hi"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	_, err := app.st.AddMessage(store.Message{BotID: bot.ID, Thread: "user", Role: "system", Content: "Notice: Tools updated: added x."})
	if err != nil {
		t.Fatal(err)
	}
	res, b := do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/state", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("state %d %s", res.StatusCode, b)
	}
	var got botState
	decodeJSON(t, b, &got)
	if len(got.Timers) != 2 || len(got.Memory) != 2 || len(got.Runs) != 1 {
		t.Fatalf("timers %d memory %d runs %d", len(got.Timers), len(got.Memory), len(got.Runs))
	}
	if !got.Tools.UpToDate || len(got.Tools.Seen) != len(toolDefs()) || len(got.Tools.Current) != len(toolDefs()) {
		t.Fatalf("tools = %+v", got.Tools)
	}
	if got.Tools.LastNotice == nil || got.Tools.LastNotice.Content != "Notice: Tools updated: added x." {
		t.Fatalf("last notice = %+v", got.Tools.LastNotice)
	}
	if res, _ := do(t, "GET", srv.URL+"/api/bots/nope/state", nil, ""); res.StatusCode != 404 {
		t.Fatalf("missing bot status %d", res.StatusCode)
	}
}
