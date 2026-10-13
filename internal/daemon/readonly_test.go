package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestWorkspaceReadonlyBlocksWriteFile(t *testing.T) {
	t.Setenv("POLICY_WORKSPACE_READONLY", "true")
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Read", "description": "stay"}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	_, err := app.dispatchTool(context.Background(), bot, "write_file", map[string]any{
		"path": "notes.txt", "content": "hello",
	})
	if err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatal(err)
	}
	events := logKind(t, srv.URL, "sandbox_block")
	if len(events) != 1 || !strings.Contains(string(events[0].Detail), "read-only") {
		t.Fatalf("%+v", events)
	}
}
