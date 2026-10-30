package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/permbroker"
)

func TestGolden_RulesRevokeImmediateAndAdminOnly(t *testing.T) {
	app := newApp(t, "", nil)
	srv := serve(t, app)
	base := srv.URL
	token := "lgbr_admintesttokenvalue"
	app.cfg.AuthToken = token

	res, body := do(t, "GET", base+"/api/permbroker/rules", nil, "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token %d %s", res.StatusCode, body)
	}
	res, body = do(t, "DELETE", base+"/api/permbroker/rules/r_missing", nil, "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token delete %d %s", res.StatusCode, body)
	}
	app.noteRunToken("lgbr_testtokenvalue", "b1", "run")
	res, body = do(t, "GET", base+"/api/permbroker/rules", nil, "lgbr_testtokenvalue")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("run token %d %s", res.StatusCode, body)
	}
	res, body = do(t, "DELETE", base+"/api/permbroker/rules/r_missing", nil, "lgbr_testtokenvalue")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("run token delete %d %s", res.StatusCode, body)
	}
	req, err := http.NewRequest(http.MethodDelete, base+"/api/permbroker/rules/r_missing", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = req.URL.Host
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resHTTP, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resHTTP.Body.Close()
	if resHTTP.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site %d", resHTTP.StatusCode)
	}

	saved, err := app.broker.SaveRule(permbroker.Rule{
		Effect: permbroker.EffectAllow, Argv: []string{"git", "status"},
		Tool: permbroker.ToolShell, Scope: permbroker.ScopeBot, BotID: "bot",
	})
	if err != nil {
		t.Fatal(err)
	}
	res, body = do(t, "GET", base+"/api/permbroker/rules", nil, token)
	if res.StatusCode != 200 || !strings.Contains(string(body), saved.ID) || !strings.Contains(string(body), `"kind":"exact"`) {
		t.Fatalf("list %d %s", res.StatusCode, body)
	}
	var listed struct {
		Rules []permbroker.RuleView `json:"rules"`
	}
	decodeJSON(t, body, &listed)
	if len(listed.Rules) != 1 || listed.Rules[0].Effect != "allow" || listed.Rules[0].Scope != "bot" || listed.Rules[0].BotID != "bot" || listed.Rules[0].Uses != 0 {
		t.Fatalf("view %+v", listed.Rules)
	}
	ctx := context.Background()
	ws := t.TempDir()
	allow := app.broker.Evaluate(ctx, shellEval("bot", ws, "git status"))
	if allow.Verdict != permbroker.VerdictAllow {
		t.Fatalf("before revoke %+v", allow)
	}
	asked := app.broker.Evaluate(ctx, shellEval("bot", ws, "echo hi"))
	if asked.PendingID == "" {
		t.Fatalf("no pending %+v", asked)
	}
	res, body = do(t, "DELETE", base+"/api/permbroker/rules/r_missing", nil, token)
	if res.StatusCode != http.StatusNotFound || !strings.Contains(string(body), "rule not found") {
		t.Fatalf("unknown %d %s", res.StatusCode, body)
	}
	before := app.broker.Ruleset()
	res, body = do(t, "DELETE", base+"/api/permbroker/rules/"+saved.ID, nil, token)
	if res.StatusCode != 200 {
		t.Fatalf("revoke %d %s", res.StatusCode, body)
	}
	if app.broker.Ruleset() <= before || app.broker.RuleCount() != 0 {
		t.Fatalf("ruleset %d count %d", app.broker.Ruleset(), app.broker.RuleCount())
	}
	if err := app.broker.Decide(asked.PendingID, "approve", permbroker.ScopeOnce); err != permbroker.ErrStale {
		t.Fatalf("pending after revoke %v", err)
	}
	next := app.broker.Evaluate(ctx, shellEval("bot", ws, "git status"))
	if next.Verdict == permbroker.VerdictAllow || next.PendingID == "" {
		t.Fatalf("after revoke %+v", next)
	}
	audit, err := os.ReadFile(filepath.Join(app.cfg.DataDir, "permbroker", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var revokeLine string
	for _, line := range strings.Split(string(audit), "\n") {
		if strings.Contains(line, `"decision":"revoke"`) && strings.Contains(line, saved.ID) {
			revokeLine = line
		}
	}
	if revokeLine == "" || strings.Contains(revokeLine, `"argv"`) || strings.Contains(revokeLine, "git status") {
		t.Fatalf("audit %s", revokeLine)
	}

	if err := app.broker.MigrateLegacy([]permbroker.LegacyRule{{
		BotID: "bot", Effect: permbroker.EffectAllow, Text: "Bash(git diff*)",
	}}); err != nil {
		t.Fatal(err)
	}
	var legacyID string
	for _, rule := range app.broker.ListRules() {
		if rule.Kind == "legacy" && rule.Source == "migrated" {
			legacyID = rule.ID
		}
	}
	if legacyID == "" {
		t.Fatal("legacy row missing")
	}
	legacy := app.broker.Evaluate(ctx, shellEval("bot", ws, "git diff"))
	if legacy.Verdict != permbroker.VerdictAllow {
		t.Fatalf("legacy before %+v", legacy)
	}
	res, body = do(t, "DELETE", base+"/api/permbroker/rules/"+legacyID, nil, token)
	if res.StatusCode != 200 {
		t.Fatalf("revoke legacy %d %s", res.StatusCode, body)
	}
	after := app.broker.Evaluate(ctx, shellEval("bot", ws, "git diff"))
	if after.Verdict == permbroker.VerdictAllow {
		t.Fatalf("legacy after %+v", after)
	}
	_ = json.Valid(body)
}

func shellEval(bot, ws, cmd string) permbroker.Request {
	raw, _ := json.Marshal(map[string]string{"command": cmd})
	return permbroker.Request{
		BotID: bot, SessionID: "sess", RunID: "run", TaskID: "task",
		Cwd: ws, Workspace: ws, ToolName: "run_shell", ToolInput: raw,
	}
}
