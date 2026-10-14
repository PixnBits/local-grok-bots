package daemon

import (
	"testing"

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
