package daemon

import (
	"sync/atomic"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// Tool calls a run made are served with the thread, keyed by the reply's
// run_id, and the reply text itself is unchanged.
func TestThreadServesRunTools(t *testing.T) {
	m := &scriptModel{toolRounds: 2}
	app := newApp(t, "", m)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Tools")
	res, b := do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "go"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("msg %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, "")
	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/thread", nil, "")
	var thread struct {
		Messages []store.Message               `json:"messages"`
		Tools    map[string][]store.ToolRecord `json:"tools"`
	}
	decodeJSON(t, b, &thread)
	var reply *store.Message
	for i := range thread.Messages {
		if thread.Messages[i].Role == "bot" {
			reply = &thread.Messages[i]
		}
	}
	if reply == nil || reply.RunID == nil || reply.Content != "done talking" {
		t.Fatalf("reply = %#v", reply)
	}
	recs := thread.Tools[*reply.RunID]
	if len(recs) != 2 {
		t.Fatalf("tools for run = %#v", thread.Tools)
	}
	for _, r := range recs {
		if r.Name != "list_bots" || !r.OK || r.Result == "" || string(r.Arguments) != "{}" {
			t.Fatalf("record = %#v", r)
		}
	}
}

// Text written in the same response as a tool call is kept as a "text"
// record before that round's calls, and stays off the thread.
func TestThreadServesPreToolText(t *testing.T) {
	var n atomic.Int32
	app := newApp(t, "", fakeModel{fn: func(req model.ChatRequest) (model.ChatResponse, error) {
		if n.Add(1) == 1 {
			return model.ChatResponse{Content: "Let me look.", ToolCalls: []model.ToolCall{{Name: "list_bots", Arguments: map[string]any{}}}}, nil
		}
		return model.ChatResponse{Content: "Found them."}, nil
	}})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Narrate")
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "go"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	_, b := do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/thread", nil, "")
	var thread struct {
		Messages []store.Message               `json:"messages"`
		Tools    map[string][]store.ToolRecord `json:"tools"`
	}
	decodeJSON(t, b, &thread)
	var replies []string
	var runID string
	for _, m := range thread.Messages {
		if m.Role == "bot" {
			replies = append(replies, m.Content)
			runID = *m.RunID
		}
	}
	if len(replies) != 1 || replies[0] != "Found them." {
		t.Fatalf("replies = %#v", replies)
	}
	recs := thread.Tools[runID]
	if len(recs) != 2 || recs[0].Kind != "text" || recs[0].Result != "Let me look." || recs[1].Kind != "call" || recs[1].Name != "list_bots" {
		t.Fatalf("records = %#v", recs)
	}
}
