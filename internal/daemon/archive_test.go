package daemon

import (
	"net/http"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// Archiving keeps the bot and thread, pauses only its enabled timers, and
// stops new runs; restoring turns those timers back on and answers the queue.
func TestArchiveAndRestore(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "hi"}, nil
	}})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Arc")
	on, _ := app.st.CreateTimer(bot.ID, "on", "1h", "ping", true)
	off, _ := app.st.CreateTimer(bot.ID, "off", "1h", "ping", false)

	res, b := do(t, http.MethodPatch, srv.URL+"/api/bots/"+bot.ID, map[string]any{"archived": true}, "")
	if res.StatusCode != 200 {
		t.Fatalf("archive %d %s", res.StatusCode, b)
	}
	var got store.Bot
	decodeJSON(t, b, &got)
	if !got.Archived || got.ArchivedAt == nil {
		t.Fatalf("archived bot = %#v", got)
	}
	if tm, _ := app.st.GetTimer(on.ID); tm.Enabled {
		t.Fatal("enabled timer still on after archive")
	}
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "hello?"}, "")
	var posted struct {
		RunID *string `json:"run_id"`
	}
	decodeJSON(t, b, &posted)
	if res.StatusCode != 200 || posted.RunID != nil {
		t.Fatalf("post to archived bot %d %s", res.StatusCode, b)
	}
	_, b = do(t, "GET", srv.URL+"/api/bots", nil, "")
	var list []store.Bot
	decodeJSON(t, b, &list)
	if len(list) != 1 || !list[0].Archived {
		t.Fatalf("list = %#v", list)
	}

	res, b = do(t, http.MethodPatch, srv.URL+"/api/bots/"+bot.ID, map[string]any{"archived": false}, "")
	decodeJSON(t, b, &got)
	if res.StatusCode != 200 || got.Archived {
		t.Fatalf("restore %d %s", res.StatusCode, b)
	}
	if tm, _ := app.st.GetTimer(on.ID); !tm.Enabled {
		t.Fatal("timer not restored")
	}
	if tm, _ := app.st.GetTimer(off.ID); tm.Enabled {
		t.Fatal("timer that was off before archive came back on")
	}
	waitIdle(t, srv.URL, bot.ID, "")
	msgs, _ := app.st.ListMessages(bot.ID, "user", "", 10)
	if len(msgs) != 2 || msgs[1].Role != "bot" {
		t.Fatalf("queued message not answered after restore: %#v", msgs)
	}
}
