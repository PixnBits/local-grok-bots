package daemon

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// scriptModel returns list_bots for the first toolRounds calls, then text.
// blockAt, when set, pauses inside that 1-based call until release or ctx cancel.
type scriptModel struct {
	mu         sync.Mutex
	calls      []model.ChatRequest
	toolRounds int
	blockAt    int
	entered    chan struct{}
	release    chan struct{}
}

func (m *scriptModel) Chat(ctx context.Context, req model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
	m.mu.Lock()
	m.calls = append(m.calls, req)
	n := len(m.calls)
	m.mu.Unlock()
	if m.blockAt > 0 && n == m.blockAt {
		if m.entered != nil {
			close(m.entered)
		}
		select {
		case <-m.release:
		case <-ctx.Done():
			return model.ChatResponse{}, ctx.Err()
		}
	}
	if n <= m.toolRounds {
		return model.ChatResponse{ToolCalls: []model.ToolCall{{
			Name: "list_bots", Arguments: map[string]any{},
		}}}, nil
	}
	const text = "done talking"
	if onToken != nil {
		onToken(text)
	}
	return model.ChatResponse{Content: text}, nil
}

func (m *scriptModel) snapshot() []model.ChatRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]model.ChatRequest, len(m.calls))
	copy(out, m.calls)
	return out
}

func toolCount(req model.ChatRequest) int {
	n := 0
	for _, msg := range req.Messages {
		if msg.Role == "tool" {
			n++
		}
	}
	return n
}

func createBot(t *testing.T, base, name string) store.Bot {
	t.Helper()
	res, b := do(t, http.MethodPost, base+"/api/bots", map[string]string{"name": name, "description": "be brief"}, "")
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	return bot
}

func postUser(t *testing.T, base, id, content string) string {
	t.Helper()
	res, b := do(t, http.MethodPost, base+"/api/bots/"+id+"/thread/messages", map[string]string{"content": content}, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("msg %d %s", res.StatusCode, b)
	}
	var posted struct {
		RunID string `json:"run_id"`
	}
	decodeJSON(t, b, &posted)
	return posted.RunID
}

func fetchBot(t *testing.T, base, id string) store.Bot {
	t.Helper()
	res, b := do(t, http.MethodGet, base+"/api/bots/"+id, nil, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("get %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	return bot
}

func waitBot(t *testing.T, base, id string, ok func(store.Bot) bool) store.Bot {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var bot store.Bot
	for time.Now().Before(deadline) {
		bot = fetchBot(t, base, id)
		if ok(bot) {
			return bot
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("bot condition: status=%s last=%s %s continue=%s", bot.Status, bot.LastRunStatus, bot.LastRunError, bot.ContinueRunID)
	return bot
}

// waitRunReleased waits until continueRun would accept botID. endLoop stores
// status idle before it clears the running flag, so a status poll can still
// get 409 "bot is running".
func waitRunReleased(t *testing.T, app *App, botID string) {
	t.Helper()
	app.rtMu.Lock()
	st := app.loops[botID]
	var released chan struct{}
	running := false
	if st != nil {
		running = st.running
		released = st.released
	}
	app.rtMu.Unlock()
	if !running {
		return
	}
	if released == nil {
		t.Fatalf("bot %s is running without a release signal", botID)
	}
	select {
	case <-released:
	case <-time.After(20 * time.Second):
		t.Fatalf("bot %s did not leave running", botID)
	}
}

func postContinue(t *testing.T, base, botID, runID string) (*http.Response, []byte) {
	t.Helper()
	return do(t, http.MethodPost, base+"/api/bots/"+botID+"/runs/"+runID+"/continue", nil, "")
}

func TestContinueCappedRun(t *testing.T) {
	if maxToolRounds != 8 {
		t.Fatalf("default cap = %d", maxToolRounds)
	}
	mdl := &scriptModel{toolRounds: maxToolRounds}
	app := newApp(t, "", mdl)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Ada")
	capped := postUser(t, srv.URL, bot.ID, "look around")
	got := waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.ContinueRunID != ""
	})
	waitRunReleased(t, app, bot.ID)
	if got.ContinueRunID != capped || got.LastRunStatus != "error" || got.LastRunError != "tool round limit" {
		t.Fatalf("offer = %+v", got)
	}
	if calls := mdl.snapshot(); len(calls) != maxToolRounds {
		t.Fatalf("model calls before continue = %d", len(calls))
	}
	stored, err := app.st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ContinueRunID != "" {
		t.Fatal("continue id was written to the store")
	}
	res, b := do(t, http.MethodGet, srv.URL+"/api/bots", nil, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list %d %s", res.StatusCode, b)
	}
	var listed []store.Bot
	decodeJSON(t, b, &listed)
	var found bool
	for _, item := range listed {
		if item.ID == bot.ID && item.ContinueRunID == capped {
			found = true
		}
	}
	if !found {
		t.Fatalf("list missing offer: %#v", listed)
	}

	res, b = postContinue(t, srv.URL, bot.ID, capped)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("continue %d %s", res.StatusCode, b)
	}
	var next struct {
		RunID string `json:"run_id"`
	}
	decodeJSON(t, b, &next)
	if next.RunID == "" || next.RunID == capped {
		t.Fatalf("next run = %q", next.RunID)
	}
	done := waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.ContinueRunID == "" && b.LastRunStatus == "done"
	})
	if done.LastRunError != "" {
		t.Fatalf("continued run error %s", done.LastRunError)
	}
	calls := mdl.snapshot()
	if len(calls) != maxToolRounds+1 {
		t.Fatalf("model calls = %d", len(calls))
	}
	if n := toolCount(calls[maxToolRounds]); n != maxToolRounds {
		t.Fatalf("continued call saw %d tool results", n)
	}
	if calls[maxToolRounds].Messages[len(calls[maxToolRounds].Messages)-1].Content == "" {
		t.Fatal("continued call missing tool output")
	}
	cappedRun, err := app.st.GetRun(capped)
	if err != nil {
		t.Fatal(err)
	}
	if cappedRun.Status != "error" || cappedRun.Error == nil || *cappedRun.Error != "tool round limit" {
		t.Fatalf("capped run reopened: %+v", cappedRun)
	}
	nextRun, err := app.st.GetRun(next.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if nextRun.Status != "done" {
		t.Fatalf("continuation = %+v", nextRun)
	}
}

func TestContinueAgainAfterSecondCap(t *testing.T) {
	mdl := &scriptModel{toolRounds: maxToolRounds * 2}
	app := newApp(t, "", mdl)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Bea")
	first := postUser(t, srv.URL, bot.ID, "keep looking")
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.ContinueRunID == first
	})
	waitRunReleased(t, app, bot.ID)
	res, b := postContinue(t, srv.URL, bot.ID, first)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("continue %d %s", res.StatusCode, b)
	}
	var second struct {
		RunID string `json:"run_id"`
	}
	decodeJSON(t, b, &second)
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.ContinueRunID == second.RunID
	})
	waitRunReleased(t, app, bot.ID)
	if calls := mdl.snapshot(); len(calls) != maxToolRounds*2 {
		t.Fatalf("calls at second cap = %d", len(calls))
	}
	res, b = postContinue(t, srv.URL, bot.ID, second.RunID)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("second continue %d %s", res.StatusCode, b)
	}
	var third struct {
		RunID string `json:"run_id"`
	}
	decodeJSON(t, b, &third)
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "done" && b.ContinueRunID == ""
	})
	calls := mdl.snapshot()
	if len(calls) != maxToolRounds*2+1 {
		t.Fatalf("calls = %d", len(calls))
	}
	if toolCount(calls[maxToolRounds]) != maxToolRounds || toolCount(calls[maxToolRounds*2]) != maxToolRounds*2 {
		t.Fatalf("tool results = %d then %d", toolCount(calls[maxToolRounds]), toolCount(calls[maxToolRounds*2]))
	}
	firstRun, err := app.st.GetRun(first)
	if err != nil {
		t.Fatal(err)
	}
	secondRun, err := app.st.GetRun(second.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if firstRun.Status != "error" || secondRun.Status != "error" {
		t.Fatalf("caps reopened: %s %s", firstRun.Status, secondRun.Status)
	}
	thirdRun, err := app.st.GetRun(third.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if thirdRun.Status != "done" {
		t.Fatalf("third = %+v", thirdRun)
	}
}

func TestContinueClearedByNewMessage(t *testing.T) {
	mdl := &scriptModel{toolRounds: maxToolRounds}
	app := newApp(t, "", mdl)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Cara")
	capped := postUser(t, srv.URL, bot.ID, "look around")
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool { return b.ContinueRunID == capped })
	waitRunReleased(t, app, bot.ID)
	postUser(t, srv.URL, bot.ID, "start over")
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "done"
	})
	calls := mdl.snapshot()
	if len(calls) != maxToolRounds+1 {
		t.Fatalf("calls = %d", len(calls))
	}
	if toolCount(calls[maxToolRounds]) != 0 {
		t.Fatalf("new message saw %d tool results", toolCount(calls[maxToolRounds]))
	}
	got := fetchBot(t, srv.URL, bot.ID)
	if got.ContinueRunID != "" {
		t.Fatalf("offer remained %s", got.ContinueRunID)
	}
	res, b := postContinue(t, srv.URL, bot.ID, capped)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("old continue %d %s", res.StatusCode, b)
	}
	_ = app
}

func TestContinueClearedByTimer(t *testing.T) {
	mdl := &scriptModel{toolRounds: maxToolRounds}
	app := newApp(t, "", mdl)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Dora")
	capped := postUser(t, srv.URL, bot.ID, "look around")
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool { return b.ContinueRunID == capped })
	waitRunReleased(t, app, bot.ID)
	tm, err := app.st.CreateTimer(bot.ID, "soon", "1h", "look again", true, "user")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.st.BackdateTimer(tm.ID, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.ContinueRunID == "" && b.LastRunStatus == "done"
	})
	calls := mdl.snapshot()
	if len(calls) != maxToolRounds+1 || toolCount(calls[maxToolRounds]) != 0 {
		t.Fatalf("timer call tools=%d len=%d", toolCount(calls[maxToolRounds]), len(calls))
	}
	seen := false
	for _, msg := range calls[maxToolRounds].Messages {
		if msg.Role == "user" && msg.Content == "[scheduled] look again" {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("timer prompt missing: %#v", calls[maxToolRounds].Messages)
	}
	res, b := postContinue(t, srv.URL, bot.ID, capped)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("old continue %d %s", res.StatusCode, b)
	}
}

func TestContinueWhileRunningIsConflict(t *testing.T) {
	mdl := &scriptModel{
		toolRounds: maxToolRounds,
		blockAt:    maxToolRounds + 1,
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
	}
	app := newApp(t, "", mdl)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Eve")
	capped := postUser(t, srv.URL, bot.ID, "look around")
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool { return b.ContinueRunID == capped })
	waitRunReleased(t, app, bot.ID)
	res, b := postContinue(t, srv.URL, bot.ID, capped)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("continue %d %s", res.StatusCode, b)
	}
	select {
	case <-mdl.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("continuation did not reach the model")
	}
	res, b = postContinue(t, srv.URL, bot.ID, capped)
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("second continue %d %s", res.StatusCode, b)
	}
	close(mdl.release)
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "done" && b.ContinueRunID == ""
	})
	calls := mdl.snapshot()
	if len(calls) != maxToolRounds+1 || toolCount(calls[maxToolRounds]) != maxToolRounds {
		t.Fatalf("continuation lost the transcript: calls=%d tools=%d", len(calls), toolCount(safeCall(calls, maxToolRounds)))
	}
	_ = app
}

func TestContinueWithoutOffer(t *testing.T) {
	mdl := &scriptModel{toolRounds: 0}
	app := newApp(t, "", mdl)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Fay")
	res, b := postContinue(t, srv.URL, bot.ID, "00000000-0000-4000-8000-000000000000")
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("missing bot run %d %s", res.StatusCode, b)
	}
	runID := postUser(t, srv.URL, bot.ID, "hello")
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "done"
	})
	waitRunReleased(t, app, bot.ID)
	res, b = postContinue(t, srv.URL, bot.ID, runID)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("finished run %d %s", res.StatusCode, b)
	}
	if fetchBot(t, srv.URL, bot.ID).ContinueRunID != "" {
		t.Fatal("offer appeared")
	}
	_ = app
}

func TestContinuePausedKeepsOffer(t *testing.T) {
	mdl := &scriptModel{toolRounds: maxToolRounds}
	app := newApp(t, "", mdl)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Gia")
	capped := postUser(t, srv.URL, bot.ID, "look around")
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool { return b.ContinueRunID == capped })
	waitRunReleased(t, app, bot.ID)
	res, b := do(t, http.MethodPatch, srv.URL+"/api/bots/"+bot.ID, map[string]string{"status": "paused"}, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("pause %d %s", res.StatusCode, b)
	}
	res, b = postContinue(t, srv.URL, bot.ID, capped)
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("paused continue %d %s", res.StatusCode, b)
	}
	if fetchBot(t, srv.URL, bot.ID).ContinueRunID != capped {
		t.Fatal("pause consumed the offer")
	}
	res, b = do(t, http.MethodPatch, srv.URL+"/api/bots/"+bot.ID, map[string]string{"status": "idle"}, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("idle %d %s", res.StatusCode, b)
	}
	idle := fetchBot(t, srv.URL, bot.ID)
	if idle.Status == "running" || idle.ContinueRunID != capped {
		t.Fatalf("unpause = status %s continue %s", idle.Status, idle.ContinueRunID)
	}
	res, b = postContinue(t, srv.URL, bot.ID, capped)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("continue after unpause %d %s", res.StatusCode, b)
	}
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "done" && b.ContinueRunID == ""
	})
	calls := mdl.snapshot()
	if len(calls) != maxToolRounds+1 || toolCount(calls[maxToolRounds]) != maxToolRounds {
		t.Fatalf("unpause continue lost tools: %d", toolCount(safeCall(calls, maxToolRounds)))
	}
	_ = app
}

func TestContinueDeleteDropsOffer(t *testing.T) {
	mdl := &scriptModel{toolRounds: maxToolRounds}
	app := newApp(t, "", mdl)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Hana")
	capped := postUser(t, srv.URL, bot.ID, "look around")
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool { return b.ContinueRunID == capped })
	waitRunReleased(t, app, bot.ID)
	res, b := do(t, http.MethodDelete, srv.URL+"/api/bots/"+bot.ID, nil, "")
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete %d %s", res.StatusCode, b)
	}
	app.rtMu.Lock()
	_, held := app.resume[bot.ID]
	app.rtMu.Unlock()
	if held {
		t.Fatal("transcript kept after delete")
	}
	res, b = postContinue(t, srv.URL, bot.ID, capped)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("continue after delete %d %s", res.StatusCode, b)
	}
	_ = mdl
}

func safeCall(calls []model.ChatRequest, i int) model.ChatRequest {
	if i < 0 || i >= len(calls) {
		return model.ChatRequest{}
	}
	return calls[i]
}
