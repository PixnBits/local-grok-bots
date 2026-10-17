package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestDurableAllowAutoAllowsReadOnly(t *testing.T) {
	app := newApp(t, t.TempDir(), nil)
	bot, err := app.st.CreateBot("perm", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"gh pr view 7", "gh pr view 8", "gh pr view 9 --comments"} {
		if err := app.st.AddRunTool("run-h", bot.ID, store.ToolRecord{
			Kind: "permission", Name: "Bash", OK: true,
			Arguments: []byte(`{"command":"` + cmd + `"}`),
			Result:    `{"decision":"allow_once","source":"ui"}`,
		}); err != nil {
			t.Fatal(err)
		}
	}
	srv := serve(t, app)
	base := srv.URL + "/api/bots/" + bot.ID
	res, body := do(t, "POST", base+"/permission-suggestions/analyze", map[string]any{}, "")
	if res.StatusCode != 200 || !strings.Contains(string(body), "Bash(gh pr view *)") || !strings.Contains(string(body), `"risk":"low"`) {
		t.Fatalf("analyze %d %s", res.StatusCode, body)
	}
	var listed struct {
		Suggestions []store.PermSuggestion `json:"suggestions"`
	}
	decodeJSON(t, body, &listed)
	if len(listed.Suggestions) != 1 || listed.Suggestions[0].Status != "pending" {
		t.Fatalf("%+v", listed.Suggestions)
	}
	res, body = do(t, "POST", base+"/permission-suggestions/"+listed.Suggestions[0].ID+"/accept", nil, "")
	if res.StatusCode != 201 || !strings.Contains(string(body), "Bash(gh pr view *)") {
		t.Fatalf("accept suggestion %d %s", res.StatusCode, body)
	}
	native, err := os.ReadFile(filepath.Join(app.cfg.DataDir, "cli", bot.ID, "user-permissions.json"))
	if err != nil || !strings.Contains(string(native), "Bash(gh pr view *)") {
		t.Fatalf("native %v %s", err, native)
	}
	grok, err := os.ReadFile(filepath.Join(app.cfg.DataDir, "cli", bot.ID, "grok-permission-rules"))
	if err != nil || !strings.Contains(string(grok), "allow Bash(gh pr view *)") {
		t.Fatalf("grok %v %s", err, grok)
	}
	res, body = do(t, "POST", base+"/permission-rules", map[string]any{
		"effect": "allow", "pattern": "Bash(git push *)",
	}, "")
	if res.StatusCode != 400 {
		t.Fatalf("push pattern %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", base+"/permission-rules", map[string]any{
		"effect": "allow", "pattern": "Bash(rm -rf *)",
	}, "")
	if res.StatusCode != 400 {
		t.Fatalf("rm pattern %d %s", res.StatusCode, body)
	}

	app.rtMu.Lock()
	app.policy.UIPrompts = true
	app.policy.PromptTimeout = 30 * time.Millisecond
	app.rtMu.Unlock()
	pol := app.policy.Permission()
	allow := app.perm.Evaluate(context.Background(), pol, app.withUserRules(bot.ID, permission.Request{
		ID: "r1", RunID: "run-1", BotID: bot.ID, Tool: "Bash",
		Args: map[string]any{"command": "gh pr view 42"},
	}))
	if allow.Decision != permission.Allow || allow.Source != "user" || allow.Rule != "Bash(gh pr view *)" {
		t.Fatalf("auto-allow %+v", allow)
	}
	tools, err := app.st.RunTools([]string{"run-1"})
	if err != nil {
		t.Fatal(err)
	}
	recs := tools["run-1"]
	if len(recs) != 1 || recs[0].Kind != "permission" || !recs[0].OK {
		t.Fatalf("records %+v", recs)
	}
	if !strings.Contains(recs[0].Result, `"rule_id"`) || !strings.Contains(recs[0].Result, `"classification":"read_only"`) || !strings.Contains(recs[0].Result, `"source":"user"`) {
		t.Fatalf("audit record %s", recs[0].Result)
	}

	composed := app.perm.Evaluate(context.Background(), pol, app.withUserRules(bot.ID, permission.Request{
		ID: "r2", RunID: "run-2", BotID: bot.ID, Tool: "Bash",
		Args: map[string]any{"command": "gh pr view 42; rm -rf /tmp/x"},
	}))
	if composed.Source == "user" || composed.Decision == permission.Allow {
		t.Fatalf("composed auto-allowed %+v", composed)
	}
	if composed.Source != "timeout" {
		t.Fatalf("composed was not asked: %+v", composed)
	}
	push := app.perm.Evaluate(context.Background(), pol, app.withUserRules(bot.ID, permission.Request{
		ID: "r3", RunID: "run-3", BotID: bot.ID, Tool: "Bash",
		Args: map[string]any{"command": "git push origin main"},
	}))
	if push.Source == "user" || push.Decision == permission.Allow {
		t.Fatalf("push auto-allowed %+v", push)
	}
	if push.Source != "timeout" {
		t.Fatalf("push was not asked: %+v", push)
	}
}
