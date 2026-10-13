package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestTurnTimeoutStopsShell(t *testing.T) {
	t.Setenv("POLICY_TURN_TIMEOUT", "1s")
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Cap", "description": "stay"}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	_, err := app.dispatchTool(context.Background(), bot, "run_shell", map[string]any{"command": "sleep 5"})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatal(err)
	}
	if events := logKind(t, srv.URL, "turn_timeout"); len(events) != 1 {
		t.Fatalf("%+v", events)
	}
}
