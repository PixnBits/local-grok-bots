package daemon

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

type runnerFunc func(context.Context, clisession.Spec, func(clisession.Event)) (clisession.Result, error)

func (f runnerFunc) Run(ctx context.Context, spec clisession.Spec, onEvent func(clisession.Event)) (clisession.Result, error) {
	return f(ctx, spec, onEvent)
}

func TestCLITurnPersistsReplyAndResumes(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		t.Errorf("ollama was called")
		return model.ChatResponse{}, nil
	}})
	var mu sync.Mutex
	var specs []clisession.Spec
	app.runner = runnerFunc(func(_ context.Context, spec clisession.Spec, _ func(clisession.Event)) (clisession.Result, error) {
		mu.Lock()
		specs = append(specs, spec)
		n := len(specs)
		mu.Unlock()
		if spec.Backend != "grok" || spec.Workspace == "" {
			t.Errorf("spec backend/workspace %+v", spec)
		}
		if n == 1 {
			if !spec.Fresh || !strings.Contains(spec.Prompt, "You are Ada") || !strings.Contains(spec.Prompt, "hello") {
				t.Errorf("fresh prompt missing pieces: %q fresh=%v", spec.Prompt, spec.Fresh)
			}
		} else {
			if spec.Fresh || !strings.Contains(spec.Prompt, "again") || strings.Contains(spec.Prompt, "You are Ada") {
				t.Errorf("resume prompt = %q fresh=%v", spec.Prompt, spec.Fresh)
			}
		}
		return clisession.Result{SessionID: spec.SessionID, Text: "reply " + spec.Prompt[len(spec.Prompt)-5:]}, nil
	})
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada", "description": "be brief", "cli_backend": "grok",
	}, "")
	if res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	if bot.CLIBackend != "grok" || bot.SessionID != "" {
		t.Fatalf("bot %#v", bot)
	}

	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "hello"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("msg %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, "")

	res, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/thread", nil, "")
	var thread struct {
		Messages []store.Message `json:"messages"`
	}
	decodeJSON(t, b, &thread)
	var replies []string
	for _, m := range thread.Messages {
		if m.Role == "bot" {
			replies = append(replies, m.Content)
		}
	}
	if len(replies) != 1 || !strings.Contains(replies[0], "reply") {
		t.Fatalf("replies %#v", thread.Messages)
	}
	res, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	if bot.SessionID == "" {
		t.Fatal("session id not stored")
	}
	session := bot.SessionID

	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "again"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	res, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	if bot.SessionID != session {
		t.Fatalf("session changed %s -> %s", session, bot.SessionID)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(specs) != 2 || specs[1].SessionID != session || specs[1].Fresh {
		t.Fatalf("specs %#v", specs)
	}
}

func TestPolicyDeniesCLIBackend(t *testing.T) {
	t.Setenv("POLICY_CLI_BACKENDS", "")
	var called atomic.Int32
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		called.Add(1)
		return model.ChatResponse{Content: "no"}, nil
	}})
	app.runner = runnerFunc(func(context.Context, clisession.Spec, func(clisession.Event)) (clisession.Result, error) {
		t.Errorf("runner called")
		return clisession.Result{}, nil
	})
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada", "description": "be brief", "cli_backend": "grok",
	}, "")
	if res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "hi"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	if bot.LastRunStatus != "error" || !strings.Contains(bot.LastRunError, "not allowed by policy") {
		t.Fatalf("run %s %s", bot.LastRunStatus, bot.LastRunError)
	}
	if called.Load() != 0 {
		t.Fatal("ollama ran for a denied cli backend")
	}
}

func TestPolicyEndpoint(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{}, nil
	}})
	app.cfg.AuthToken = "sekrit"
	srv := serve(t, app)
	res, _ := do(t, "GET", srv.URL+"/api/policy", nil, "")
	if res.StatusCode != 401 {
		t.Fatalf("policy %d", res.StatusCode)
	}
	res, b := do(t, "GET", srv.URL+"/api/policy", nil, "sekrit")
	if res.StatusCode != 200 || !strings.Contains(string(b), `"cli_network":"open"`) || !strings.Contains(string(b), `"grok"`) {
		t.Fatalf("policy %d %s", res.StatusCode, b)
	}
}

func TestCLIBackendRejected(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada", "cli_backend": "openai",
	}, "")
	if res.StatusCode != 400 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
}

func TestClaudeBackendReachesRunner(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		t.Errorf("ollama was called")
		return model.ChatResponse{}, nil
	}})
	var got clisession.Spec
	app.runner = runnerFunc(func(_ context.Context, spec clisession.Spec, _ func(clisession.Event)) (clisession.Result, error) {
		got = spec
		return clisession.Result{SessionID: spec.SessionID, Text: "from claude"}, nil
	})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada", "cli_backend": "claude",
	}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "hi"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	if got.Backend != "claude" || !got.Fresh || got.SessionID == "" || !strings.Contains(got.Prompt, "hi") {
		t.Fatalf("spec %+v", got)
	}
	res, b := do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("get %d %s", res.StatusCode, b)
	}
	decodeJSON(t, b, &bot)
	if bot.CLIBackend != "claude" || bot.SessionID != got.SessionID {
		t.Fatalf("bot %#v", bot)
	}
}
