package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestAuditRecordsCLIProcessAndRedactsGrants(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	t.Setenv("POLICY_AUDIT_LOG", logPath)
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		t.Errorf("ollama was called")
		return model.ChatResponse{}, nil
	}})
	app.runner = runnerFunc(func(_ context.Context, spec clisession.Spec, _ func(clisession.Event)) (clisession.Result, error) {
		if spec.OnStart != nil {
			spec.OnStart(4242)
		}
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
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "hello secret-prompt"}, "")
	waitIdle(t, srv.URL, bot.ID, "")

	app.recordSandbox(bot.ID, sandbox.Event{
		Kind: "grant_use", Grant: "net", Host: "allowed.test", Port: 443,
		Detail: "via http://user:s3cret@proxy.example:8080",
	})
	app.recordSandbox(bot.ID, sandbox.Event{
		Kind: "grant_denied", Grant: "git", Detail: "XAI_API_KEY=supersecret",
	})

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		`"event":"cli_start"`, `"event":"cli_stop"`, `"pid":4242`, `"backend":"grok"`,
		`"cli_network":"open"`, `"result":"ok"`,
		`"event":"net_decision"`, `"action":"allow"`, `"host":"allowed.test"`, `"port":443`,
		`"event":"grant"`, `"action":"deny"`, `"grant":"git"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s in %s", want, text)
		}
	}
	for _, bad := range []string{"s3cret", "supersecret", "secret-prompt"} {
		if strings.Contains(text, bad) {
			t.Fatalf("audit leaked %s: %s", bad, text)
		}
	}
}
