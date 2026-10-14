package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
)

// A message posted while a run is between model calls joins that run's
// transcript before the next call, and no extra run is started for it.
func TestMidRunMessageFoldsIntoLiveRun(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	var reqs []model.ChatRequest
	app := newApp(t, "", fakeModel{fn: func(req model.ChatRequest) (model.ChatResponse, error) {
		mu.Lock()
		reqs = append(reqs, req)
		n := len(reqs)
		mu.Unlock()
		if n == 1 {
			close(entered)
			<-release
			return model.ChatResponse{ToolCalls: []model.ToolCall{{Name: "list_bots", Arguments: map[string]any{}}}}, nil
		}
		return model.ChatResponse{Content: "both answered"}, nil
	}})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Fold")
	res, b := do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "one"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("msg %d %s", res.StatusCode, b)
	}
	var first struct {
		RunID string `json:"run_id"`
	}
	decodeJSON(t, b, &first)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("model not called")
	}
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "two"}, "")
	var second struct {
		RunID string `json:"run_id"`
	}
	decodeJSON(t, b, &second)
	if second.RunID != first.RunID {
		t.Fatalf("second post run %q, live run %q", second.RunID, first.RunID)
	}
	close(release)
	waitIdle(t, srv.URL, bot.ID, "")
	mu.Lock()
	defer mu.Unlock()
	if len(reqs) != 2 {
		t.Fatalf("model calls = %d, want 2 (one run)", len(reqs))
	}
	last := reqs[1].Messages[len(reqs[1].Messages)-1]
	if last.Role != "user" || last.Content != "two" {
		t.Fatalf("last message before call 2 = %#v", last)
	}
	ones := 0
	for _, m := range reqs[1].Messages {
		if m.Content == "one" {
			ones++
		}
	}
	if ones != 1 {
		t.Fatalf("first message appears %d times", ones)
	}
	if n, _ := app.st.LogCount("run_started"); n != 1 {
		t.Fatalf("run_started = %d, want 1", n)
	}
	need, err := app.st.NeedsRun(bot.ID)
	if err != nil || need {
		t.Fatalf("NeedsRun = %v %v after fold", need, err)
	}
}
