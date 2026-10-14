package daemon

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestParseErrorIsDiagnosedOnce(t *testing.T) {
	var mu sync.Mutex
	var reqs [][]model.Message
	var n atomic.Int32
	parseErr := &model.ToolCallParseError{Detail: "XML syntax error on line 3: unexpected end element </parameter>"}
	app := newApp(t, "", fakeModel{fn: func(req model.ChatRequest) (model.ChatResponse, error) {
		mu.Lock()
		reqs = append(reqs, append([]model.Message(nil), req.Messages...))
		mu.Unlock()
		switch n.Add(1) {
		case 1:
			return model.ChatResponse{}, parseErr
		case 2:
			return model.ChatResponse{ToolCalls: []model.ToolCall{{
				Name: "list_bots", Arguments: map[string]any{},
			}}}, nil
		default:
			return model.ChatResponse{Content: "The pull request is open."}, nil
		}
	}})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "Ada", "description": "open a pull request"}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "Create a PR"}, "")
	waitIdle(t, srv.URL, bot.ID, "")

	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	if bot.LastRunStatus != "done" || bot.LastRunError != "" {
		t.Fatalf("run %s %s", bot.LastRunStatus, bot.LastRunError)
	}
	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/thread", nil, "")
	var thread struct {
		Messages []store.Message `json:"messages"`
	}
	decodeJSON(t, b, &thread)
	var botTexts []string
	for _, m := range thread.Messages {
		if m.Role == "bot" {
			botTexts = append(botTexts, m.Content)
		}
		if m.Role == "user" && m.Content != "Create a PR" {
			t.Fatalf("diagnosis stored on the thread: %#v", thread.Messages)
		}
	}
	if len(botTexts) != 1 || botTexts[0] != "The pull request is open." {
		t.Fatalf("bot texts %#v", botTexts)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reqs) != 3 {
		t.Fatalf("model calls %d", len(reqs))
	}
	if !sawRoleContent(reqs[1], "user", "The tool call could not be parsed: "+parseErr.Detail+". Call the tool again with valid arguments, or reply in text.") {
		t.Fatalf("retry missed the diagnosis: %#v", reqs[1])
	}
}

func TestSecondParseErrorEndsTheRun(t *testing.T) {
	var n atomic.Int32
	parseErr := &model.ToolCallParseError{Detail: "XML syntax error on line 3: unexpected end element </parameter>"}
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		n.Add(1)
		return model.ChatResponse{}, parseErr
	}})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "Ada", "description": "try"}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "go"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	if bot.LastRunStatus != "error" || bot.LastRunError != parseErr.Error() {
		t.Fatalf("run %s %s", bot.LastRunStatus, bot.LastRunError)
	}
	if n.Load() != 2 {
		t.Fatalf("calls %d", n.Load())
	}
}

func TestUnreachableModelIsNotRetried(t *testing.T) {
	var n atomic.Int32
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		n.Add(1)
		return model.ChatResponse{}, errOllama()
	}})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "Ada", "description": "try"}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "go"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	if n.Load() != 1 {
		t.Fatalf("calls %d", n.Load())
	}
	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	if bot.LastRunStatus != "error" {
		t.Fatalf("run %s %s", bot.LastRunStatus, bot.LastRunError)
	}
}

func TestParseErrorBeforeTheCapIsRetried(t *testing.T) {
	var mu sync.Mutex
	var last []model.Message
	var n atomic.Int32
	parseErr := &model.ToolCallParseError{Detail: "XML syntax error on line 3: unexpected end element </parameter>"}
	app := newApp(t, "", fakeModel{fn: func(req model.ChatRequest) (model.ChatResponse, error) {
		call := n.Add(1)
		mu.Lock()
		last = append([]model.Message(nil), req.Messages...)
		mu.Unlock()
		if call < int32(maxToolRounds-1) {
			return model.ChatResponse{ToolCalls: []model.ToolCall{{
				Name: "list_bots", Arguments: map[string]any{},
			}}}, nil
		}
		if call == int32(maxToolRounds-1) {
			return model.ChatResponse{}, parseErr
		}
		return model.ChatResponse{Content: "recovered"}, nil
	}})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "Ada", "description": "try"}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "go"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	if bot.LastRunStatus != "done" || bot.LastRunError != "" {
		t.Fatalf("run %s %s", bot.LastRunStatus, bot.LastRunError)
	}
	if n.Load() != int32(maxToolRounds) {
		t.Fatalf("calls %d", n.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if !sawRoleContent(last, "user", "The tool call could not be parsed: "+parseErr.Detail+". Call the tool again with valid arguments, or reply in text.") {
		t.Fatal("last call missed the diagnosis")
	}
}

func TestParseErrorOnTheLastRoundStaysThatError(t *testing.T) {
	var n atomic.Int32
	parseErr := &model.ToolCallParseError{Detail: "XML syntax error on line 3: unexpected end element </parameter>"}
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		if n.Add(1) < int32(maxToolRounds) {
			return model.ChatResponse{ToolCalls: []model.ToolCall{{
				Name: "list_bots", Arguments: map[string]any{},
			}}}, nil
		}
		return model.ChatResponse{}, parseErr
	}})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "Ada", "description": "try"}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "go"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	if bot.LastRunStatus != "error" || bot.LastRunError != parseErr.Error() || bot.ContinueRunID != "" {
		t.Fatalf("run %s %s continue %s", bot.LastRunStatus, bot.LastRunError, bot.ContinueRunID)
	}
	if n.Load() != int32(maxToolRounds) {
		t.Fatalf("calls %d", n.Load())
	}
}
