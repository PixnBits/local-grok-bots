package daemon

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/permbroker"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestGolden_GitRebaselineAdminOnly(t *testing.T) {
	app := newApp(t, "", nil)
	srv := serve(t, app)
	const token = "lgbr_admintesttokenvalue"
	app.cfg.AuthToken = token
	audPath := filepath.Join(app.cfg.DataDir, "daemon-audit.jsonl")
	lg, err := audit.Open(audPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	ws := t.TempDir()
	home := t.TempDir()
	userHome := t.TempDir()
	if err := os.Mkdir(filepath.Join(ws, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(ws, ".git", "config")
	original := []byte("[core]\n\trepositoryformatversion = 0\n")
	if err := os.WriteFile(cfg, original, 0o644); err != nil {
		t.Fatal(err)
	}
	const bot = "bot"
	app.broker.SetBotContext(bot, ws, nil)
	app.broker.SetBotRuntime(bot, home, userHome, nil)
	app.broker.SnapshotBot(bot)
	if _, err := app.broker.SaveRule(permbroker.Rule{
		Effect: permbroker.EffectAllow, Argv: []string{"git", "status"},
		Tool: permbroker.ToolShell, Scope: permbroker.ScopeBot, BotID: bot,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, append(original, []byte("\tlogallrefupdates = true\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if d := app.broker.Evaluate(ctx, shellEval(bot, ws, "git status")); d.Verdict == permbroker.VerdictAllow || d.PendingID == "" {
		t.Fatalf("drift %+v", d)
	}
	url := srv.URL + "/api/permbroker/bots/" + bot + "/git-baseline"
	res, body := do(t, "POST", url, map[string]any{}, "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token %d %s", res.StatusCode, body)
	}
	app.noteRunToken("lgbr_testtokenvalue", bot, "run")
	res, body = do(t, "POST", url, map[string]any{}, "lgbr_testtokenvalue")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("run token %d %s", res.StatusCode, body)
	}
	req, err := http.NewRequest(http.MethodPost, url, nil)
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
	if d := app.broker.Evaluate(ctx, shellEval(bot, ws, "git status")); d.Verdict == permbroker.VerdictAllow {
		t.Fatalf("cross-site recorded a baseline %+v", d)
	}
	before := app.broker.Ruleset()
	res, body = do(t, "POST", url, map[string]any{}, token)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("admin %d %s", res.StatusCode, body)
	}
	if app.broker.Ruleset() != before {
		t.Fatalf("ruleset %d -> %d", before, app.broker.Ruleset())
	}
	aud, err := os.ReadFile(audPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(aud), `"action":"git_rebaseline"`) || !strings.Contains(string(aud), `"bot_id":"bot"`) || !strings.Contains(string(aud), `"event":"permbroker"`) {
		t.Fatalf("audit %s", aud)
	}
	if d := app.broker.Evaluate(ctx, shellEval(bot, ws, "git status")); d.Verdict != permbroker.VerdictAllow {
		t.Fatalf("after rebaseline %+v", d)
	}
	if err := os.WriteFile(cfg, []byte("[core]\n\thooksPath = x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if d := app.broker.Evaluate(ctx, shellEval(bot, ws, "git status")); d.Verdict == permbroker.VerdictAllow || d.PendingID == "" {
		t.Fatalf("risky key %+v", d)
	}
}

func TestGolden_LegacyAllowInactiveUntilConfirm(t *testing.T) {
	app := newApp(t, "", nil)
	srv := serve(t, app)
	const token = "lgbr_admintesttokenvalue"
	app.cfg.AuthToken = token
	audPath := filepath.Join(app.cfg.DataDir, "daemon-audit.jsonl")
	lg, err := audit.Open(audPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	if _, err := app.broker.SaveRule(permbroker.Rule{
		Effect: permbroker.EffectAllow, Argv: []string{"git", "status"},
		Tool: permbroker.ToolShell, Scope: permbroker.ScopeBot, BotID: "bot",
	}); err != nil {
		t.Fatal(err)
	}
	if err := app.broker.MigrateLegacy([]permbroker.LegacyRule{{
		BotID: "bot", Effect: permbroker.EffectAllow, Text: "Bash(git diff*)",
	}}); err != nil {
		t.Fatal(err)
	}
	res, body := do(t, "GET", srv.URL+"/api/permbroker/rules", nil, token)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"needs_confirm":true`) || !strings.Contains(string(body), `"active":false`) {
		t.Fatalf("list %d %s", res.StatusCode, body)
	}
	var legacyID string
	for _, rule := range app.broker.ListRules() {
		if rule.Kind == "legacy" && rule.NeedsConfirm {
			legacyID = rule.ID
		}
	}
	if legacyID == "" {
		t.Fatal("inactive row missing")
	}
	ctx := context.Background()
	ws := t.TempDir()
	if d := app.broker.Evaluate(ctx, shellEval("bot", ws, "git status")); d.Verdict != permbroker.VerdictAllow {
		t.Fatalf("exact %+v", d)
	}
	if d := app.broker.Evaluate(ctx, shellEval("bot", ws, "git diff")); d.Verdict == permbroker.VerdictAllow || d.PendingID == "" {
		t.Fatalf("inactive %+v", d)
	}
	url := srv.URL + "/api/permbroker/rules/" + legacyID + "/confirm"
	res, body = do(t, "POST", url, map[string]any{}, "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token %d %s", res.StatusCode, body)
	}
	app.noteRunToken("lgbr_testtokenvalue", "bot", "run")
	res, body = do(t, "POST", url, map[string]any{}, "lgbr_testtokenvalue")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("run token %d %s", res.StatusCode, body)
	}
	req, err := http.NewRequest(http.MethodPost, url, nil)
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
	if d := app.broker.Evaluate(ctx, shellEval("bot", ws, "git diff")); d.Verdict == permbroker.VerdictAllow {
		t.Fatalf("unconfirmed %+v", d)
	}
	before := app.broker.Ruleset()
	res, body = do(t, "POST", url, map[string]any{}, token)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("confirm %d %s", res.StatusCode, body)
	}
	if app.broker.Ruleset() <= before {
		t.Fatalf("ruleset %d", app.broker.Ruleset())
	}
	aud, err := os.ReadFile(audPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(aud), `"action":"rule_confirm"`) || !strings.Contains(string(aud), legacyID) || !strings.Contains(string(aud), `"event":"permbroker"`) {
		t.Fatalf("daemon audit %s", aud)
	}
	brokerAudit, err := os.ReadFile(filepath.Join(app.cfg.DataDir, "permbroker", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var confirmLine string
	for _, line := range strings.Split(string(brokerAudit), "\n") {
		if strings.Contains(line, `"decision":"rule_confirm"`) && strings.Contains(line, legacyID) {
			confirmLine = line
		}
	}
	if confirmLine == "" || !strings.Contains(confirmLine, `"input_hash":"`) || strings.Contains(confirmLine, `"input_hash":""`) {
		t.Fatalf("broker audit %s", confirmLine)
	}
	if d := app.broker.Evaluate(ctx, shellEval("bot", ws, "git diff")); d.Verdict != permbroker.VerdictAllow {
		t.Fatalf("confirmed %+v", d)
	}
	res, body = do(t, "GET", srv.URL+"/api/permbroker/rules", nil, token)
	if res.StatusCode != http.StatusOK || strings.Contains(string(body), `"needs_confirm":true`) {
		t.Fatalf("after list %d %s", res.StatusCode, body)
	}
}

func TestGolden_BootMigratesProfileRules(t *testing.T) {
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	bot, err := st.CreateBot("boot", "rules", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertUserPermRule(store.UserPermRule{
		BotID: bot.ID, Effect: "allow", Pattern: "Bash(git status)",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	app := newApp(t, dir, nil)
	found := false
	for _, rule := range app.broker.ListRules() {
		if rule.Source == "migrated" && rule.BotID == bot.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("boot did not migrate %+v", app.broker.ListRules())
	}
}

func TestGolden_BrokerAdminRequiresToken(t *testing.T) {
	app := newApp(t, "", nil)
	srv := serve(t, app)
	routes := []struct {
		method string
		path   string
	}{
		{"GET", "/api/permbroker/pending"},
		{"POST", "/api/permbroker/pending/deny-all"},
		{"POST", "/api/permbroker/pending/p_missing"},
		{"POST", "/api/permbroker/hook/repin"},
		{"GET", "/api/permbroker/rules"},
		{"DELETE", "/api/permbroker/rules/r_missing"},
		{"POST", "/api/permbroker/rules/r_missing/confirm"},
		{"POST", "/api/permbroker/bots/bot/git-baseline"},
	}
	for _, rt := range routes {
		res, body := do(t, rt.method, srv.URL+rt.path, map[string]any{}, "")
		if res.StatusCode != http.StatusForbidden || !strings.Contains(string(body), `"error":"admin token required"`) {
			t.Fatalf("unset %s %s %d %s", rt.method, rt.path, res.StatusCode, body)
		}
	}
	res, body := do(t, "GET", srv.URL+"/api/health", nil, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("health %d %s", res.StatusCode, body)
	}
	const token = "lgbr_admintesttokenvalue"
	app.cfg.AuthToken = token
	for _, rt := range routes {
		res, body := do(t, rt.method, srv.URL+rt.path, map[string]any{}, "")
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("missing %s %s %d %s", rt.method, rt.path, res.StatusCode, body)
		}
	}
	res, body = do(t, "GET", srv.URL+"/api/health", nil, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("health with token configured %d %s", res.StatusCode, body)
	}
}
