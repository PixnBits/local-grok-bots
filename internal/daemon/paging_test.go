package daemon

import (
	"fmt"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

type threadPage struct {
	Messages []store.Message               `json:"messages"`
	Tools    map[string][]store.ToolRecord `json:"tools"`
	HasMore  bool                          `json:"has_more"`
}

// The thread API returns the newest page first (oldest-first within it),
// pages back with before=<id>, and reports has_more until the start.
func TestThreadPaging(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "x"}, nil
	}})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Pager")
	run, _ := app.st.CreateRun(bot.ID)
	_, _ = app.st.FinishRun(run.ID, "done", "")
	for i := 1; i <= 7; i++ {
		m := store.Message{BotID: bot.ID, Thread: "user", Role: "user", Content: fmt.Sprintf("m%d", i)}
		if i == 2 {
			m.Role, m.RunID = "bot", &run.ID
		}
		if _, err := app.st.AddMessage(m); err != nil {
			t.Fatal(err)
		}
	}
	_ = app.st.AddRunTool(run.ID, bot.ID, store.ToolRecord{Name: "list_bots", OK: true, Result: "[]"})
	get := func(q string) threadPage {
		_, b := do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/thread"+q, nil, "")
		var p threadPage
		decodeJSON(t, b, &p)
		return p
	}
	texts := func(p threadPage) string {
		s := ""
		for _, m := range p.Messages {
			s += m.Content + " "
		}
		return s
	}
	p1 := get("?limit=3")
	if texts(p1) != "m5 m6 m7 " || !p1.HasMore || len(p1.Tools) != 0 {
		t.Fatalf("page 1 = %q more=%v tools=%v", texts(p1), p1.HasMore, p1.Tools)
	}
	p2 := get("?limit=3&before=" + p1.Messages[0].ID)
	if texts(p2) != "m2 m3 m4 " || !p2.HasMore || len(p2.Tools[run.ID]) != 1 {
		t.Fatalf("page 2 = %q more=%v tools=%v", texts(p2), p2.HasMore, p2.Tools)
	}
	p3 := get("?limit=3&before=" + p2.Messages[0].ID)
	if texts(p3) != "m1 " || p3.HasMore {
		t.Fatalf("page 3 = %q more=%v", texts(p3), p3.HasMore)
	}
	all := get("")
	if len(all.Messages) != 7 || all.HasMore {
		t.Fatalf("default page = %d more=%v", len(all.Messages), all.HasMore)
	}
	exact := get("?limit=7")
	if len(exact.Messages) != 7 || exact.HasMore {
		t.Fatalf("limit equal to count: more=%v", exact.HasMore)
	}
}
