package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestDLPDeniesPromptAndAllowsCleanPrompt(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	t.Setenv("POLICY_AUDIT_LOG", auditPath)
	t.Setenv("POLICY_DLP_PATTERNS", `(?i)secret-prompt`)
	var calls atomic.Int32
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		t.Errorf("ollama was called")
		return model.ChatResponse{}, nil
	}})
	app.runner = runnerFunc(func(_ context.Context, spec clisession.Spec, _ func(clisession.Event)) (clisession.Result, error) {
		calls.Add(1)
		return clisession.Result{SessionID: spec.SessionID, Text: "Hi"}, nil
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
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "secret-prompt"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	if bot.LastRunStatus != "error" || !strings.Contains(bot.LastRunError, "dlp:") || strings.Contains(bot.LastRunError, "secret-prompt") {
		t.Fatalf("run %s %s", bot.LastRunStatus, bot.LastRunError)
	}
	if calls.Load() != 0 {
		t.Fatal("cli ran after a dlp denial")
	}
	if bot.SessionID != "" {
		t.Fatalf("session kept after denial: %s", bot.SessionID)
	}
	events := logKind(t, srv.URL, "dlp_denied")
	if len(events) != 1 || strings.Contains(string(events[0].Detail), "secret-prompt") {
		t.Fatalf("log %#v", events)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil || !strings.Contains(string(raw), `"event":"dlp"`) || strings.Contains(string(raw), "secret-prompt") {
		t.Fatalf("audit %s %v", raw, err)
	}

	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "hello"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	if calls.Load() != 1 || bot.LastRunStatus != "done" {
		t.Fatalf("calls %d run %s %s", calls.Load(), bot.LastRunStatus, bot.LastRunError)
	}
}

func TestDLPScansToolResultsWhenEnabled(t *testing.T) {
	t.Setenv("POLICY_DLP_PATTERNS", "BLOCKME")
	t.Setenv("POLICY_DLP_SCAN_TOOLS", "true")
	var calls atomic.Int32
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{}, nil
	}})
	app.runner = runnerFunc(func(_ context.Context, spec clisession.Spec, _ func(clisession.Event)) (clisession.Result, error) {
		calls.Add(1)
		text := "```action\n{\"tool\":\"write_memory\",\"arguments\":{\"key\":\"k\",\"value\":\"BLOCKME\"}}\n```"
		return clisession.Result{SessionID: spec.SessionID, Text: text}, nil
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
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "hello"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	if calls.Load() != 1 || bot.LastRunStatus != "error" || !strings.Contains(bot.LastRunError, "dlp:") || strings.Contains(bot.LastRunError, "BLOCKME") {
		t.Fatalf("calls %d run %s %s", calls.Load(), bot.LastRunStatus, bot.LastRunError)
	}
}
