package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestDurableAllowAutoAllowsReadOnly(t *testing.T) {
	app := newApp(t, t.TempDir(), nil)
	bot, err := app.st.CreateBot("perm", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"pwd", "pwd", "pwd", "gh pr view 7", "git status"} {
		if err := app.st.AddRunTool("run-h", bot.ID, store.ToolRecord{
			Kind: "permission", Name: "Bash", OK: true,
			Arguments: []byte(`{"command":"` + cmd + `"}`),
			Result:    `{"decision":"allow_once","source":"ui"}`,
		}); err != nil {
			t.Fatal(err)
		}
	}
	srv := serve(t, app)
	tok := armAdmin(app)
	base := srv.URL + "/api/bots/" + bot.ID
	res, body := do(t, "POST", base+"/permission-suggestions/analyze", map[string]any{}, tok)
	if res.StatusCode != 200 || !strings.Contains(string(body), "Bash(pwd)") || !strings.Contains(string(body), `"risk":"low"`) || strings.Contains(string(body), "gh pr") || strings.Contains(string(body), "git status") {
		t.Fatalf("analyze %d %s", res.StatusCode, body)
	}
	var listed struct {
		Suggestions []store.PermSuggestion `json:"suggestions"`
	}
	decodeJSON(t, body, &listed)
	if len(listed.Suggestions) != 1 || listed.Suggestions[0].Status != "pending" {
		t.Fatalf("%+v", listed.Suggestions)
	}
	res, body = do(t, "POST", base+"/permission-suggestions/"+listed.Suggestions[0].ID+"/accept", nil, tok)
	if res.StatusCode != 201 || !strings.Contains(string(body), "Bash(pwd)") {
		t.Fatalf("accept suggestion %d %s", res.StatusCode, body)
	}
	native, err := os.ReadFile(filepath.Join(app.cfg.DataDir, "cli", bot.ID, "user-permissions.json"))
	if err != nil || !strings.Contains(string(native), "Bash(pwd)") {
		t.Fatalf("native %v %s", err, native)
	}
	grok, err := os.ReadFile(filepath.Join(app.cfg.DataDir, "cli", bot.ID, "grok-permission-rules"))
	if err != nil || !strings.Contains(string(grok), "allow Bash(pwd)") {
		t.Fatalf("grok %v %s", err, grok)
	}
	res, body = do(t, "POST", base+"/permission-rules", map[string]any{
		"effect": "allow", "pattern": "Bash(git status*)",
	}, tok)
	if res.StatusCode != 400 {
		t.Fatalf("git status pattern %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", base+"/permission-rules", map[string]any{
		"effect": "allow", "pattern": "Bash(git push *)",
	}, tok)
	if res.StatusCode != 400 {
		t.Fatalf("push pattern %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", base+"/permission-rules", map[string]any{
		"effect": "allow", "pattern": "Bash(rm -rf *)",
	}, tok)
	if res.StatusCode != 400 {
		t.Fatalf("rm pattern %d %s", res.StatusCode, body)
	}

	app.rtMu.Lock()
	app.editPol(func(p *policy.Policy) { p.UIPrompts = true })
	app.editPol(func(p *policy.Policy) { p.PromptTimeout = 30 * time.Millisecond })
	app.rtMu.Unlock()
	pol := app.pol().Permission()
	allow := app.perm.Evaluate(context.Background(), pol, app.withUserRules(bot.ID, permission.Request{
		ID: "r1", RunID: "run-1", BotID: bot.ID, Tool: "Bash",
		Args: map[string]any{"command": "pwd"},
	}))
	if allow.Decision != permission.Allow || allow.Source != "user" || allow.Rule != "Bash(pwd)" {
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
		Args: map[string]any{"command": "pwd; rm -rf /tmp/x"},
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

type captureRunner struct {
	spec clisession.Spec
}

func (r *captureRunner) Run(_ context.Context, spec clisession.Spec, _ func(clisession.Event)) (clisession.Result, error) {
	r.spec = spec
	return clisession.Result{Text: "ok", SessionID: "sess-rules"}, nil
}

func TestUserRulesDoNotWidenCLI(t *testing.T) {
	dir := t.TempDir()
	app := newApp(t, dir, nil)
	cap := &captureRunner{}
	app.runner = cap
	app.rtMu.Lock()
	app.setPol(policy.Policy{
		Backend: "claude", CLIPermitted: true, DaemonJail: false,
		TimersEnabled: true, Idle: time.Hour, Imminent: time.Minute,
		ToolAllow: []string{"Read"},
		ToolDeny:  []string{"Bash(rm *)"},
	})
	app.rtMu.Unlock()
	bot, err := app.st.CreateBot("rules", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	srv := serve(t, app)
	tok := armAdmin(app)
	base := srv.URL + "/api/bots/" + bot.ID
	res, body := do(t, "POST", base+"/permission-rules", map[string]any{
		"effect": "allow", "pattern": "Bash(pwd)",
	}, tok)
	if res.StatusCode != 201 {
		t.Fatalf("allow %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", base+"/permission-rules", map[string]any{
		"effect": "deny", "pattern": "Bash(*push*)",
	}, tok)
	if res.StatusCode != 201 {
		t.Fatalf("deny %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", base+"/thread/messages", map[string]any{"content": "go"}, tok)
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, body)
	}
	waitIdle(t, srv.URL, bot.ID, tok)
	got, err := app.st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastRunStatus != "done" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	if !containsRule(cap.spec.AllowRules, "Read") {
		t.Fatalf("policy allow missing: %v", cap.spec.AllowRules)
	}
	for _, rule := range append(append([]string{}, cap.spec.AllowRules...), cap.spec.DenyRules...) {
		if strings.Contains(rule, "pwd") || strings.Contains(rule, "push") {
			t.Fatalf("user rule on argv spec: %v deny %v", cap.spec.AllowRules, cap.spec.DenyRules)
		}
	}
	if !containsRule(cap.spec.DenyRules, "Bash(rm *)") {
		t.Fatalf("policy deny missing: %v", cap.spec.DenyRules)
	}
	argv, err := clisession.Args(cap.spec)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "--allowedTools", "--disallowedTools", "--allow", "--deny":
			if i+1 >= len(argv) {
				continue
			}
			rule := argv[i+1]
			if strings.Contains(rule, "pwd") || strings.Contains(rule, "push") {
				t.Fatalf("user pattern on %s %s", argv[i], rule)
			}
		}
	}
	settings, err := os.ReadFile(filepath.Join(dir, "cli", bot.ID, "claude-settings.json"))
	if err != nil || strings.Contains(string(settings), "pwd") || strings.Contains(string(settings), `Bash(*push*)`) {
		t.Fatalf("settings %v %s", err, settings)
	}
	native, err := os.ReadFile(filepath.Join(dir, "cli", bot.ID, "user-permissions.json"))
	if err != nil || !strings.Contains(string(native), "Bash(pwd)") || !strings.Contains(string(native), "Bash(*push*)") {
		t.Fatalf("native %v %s", err, native)
	}
}

func containsRule(rules []string, want string) bool {
	for _, rule := range rules {
		if rule == want {
			return true
		}
	}
	return false
}

func TestPermRuleApplyRollsBack(t *testing.T) {
	app := newApp(t, t.TempDir(), nil)
	bot, err := app.st.CreateBot("perm", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	srv := serve(t, app)
	tok := armAdmin(app)
	base := srv.URL + "/api/bots/" + bot.ID
	dir := filepath.Join(app.cfg.DataDir, "cli", bot.ID)

	t.Cleanup(func() { permApplyHook = nil })
	permApplyHook = func(stage string) error {
		if stage == "before_files" {
			return errors.New("injected before files")
		}
		return nil
	}
	res, body := do(t, "POST", base+"/permission-rules", map[string]any{
		"effect": "allow", "pattern": "Bash(pwd)",
	}, tok)
	if res.StatusCode != 500 || !strings.Contains(string(body), "injected before files") {
		t.Fatalf("before_files %d %s", res.StatusCode, body)
	}
	assertNoRule(t, app, bot.ID, dir)

	permApplyHook = func(stage string) error {
		if stage == "after_files" {
			return errors.New("injected after files")
		}
		return nil
	}
	res, body = do(t, "POST", base+"/permission-rules", map[string]any{
		"effect": "allow", "pattern": "Bash(pwd)",
	}, tok)
	if res.StatusCode != 500 || !strings.Contains(string(body), "injected after files") {
		t.Fatalf("after_files %d %s", res.StatusCode, body)
	}
	assertNoRule(t, app, bot.ID, dir)

	permApplyHook = nil
	res, body = do(t, "POST", base+"/permission-rules", map[string]any{
		"effect": "allow", "pattern": "Bash(pwd)",
	}, tok)
	if res.StatusCode != 201 {
		t.Fatalf("accept %d %s", res.StatusCode, body)
	}
	var rule store.UserPermRule
	decodeJSON(t, body, &rule)
	native, err := os.ReadFile(filepath.Join(dir, "user-permissions.json"))
	if err != nil || !strings.Contains(string(native), "Bash(pwd)") {
		t.Fatalf("native %v %s", err, native)
	}
	logs, err := app.st.ListLog(bot.ID, "user_perm_rule", "", 10)
	if err != nil || len(logs) != 1 {
		t.Fatalf("audit %v %+v", err, logs)
	}

	permApplyHook = func(stage string) error {
		if stage == "after_files" {
			return errors.New("injected revoke")
		}
		return nil
	}
	res, body = do(t, "DELETE", base+"/permission-rules/"+rule.ID, nil, tok)
	if res.StatusCode != 500 || !strings.Contains(string(body), "injected revoke") {
		t.Fatalf("revoke %d %s", res.StatusCode, body)
	}
	got, err := app.st.ListUserPermRules(bot.ID)
	if err != nil || len(got) != 1 {
		t.Fatalf("revoke rolled back row %+v %v", got, err)
	}
	native, err = os.ReadFile(filepath.Join(dir, "user-permissions.json"))
	if err != nil || !strings.Contains(string(native), "Bash(pwd)") {
		t.Fatalf("revoke restored files %v %s", err, native)
	}
	logs, err = app.st.ListLog(bot.ID, "user_perm_rule", "", 10)
	if err != nil || len(logs) != 1 {
		t.Fatalf("revoke audit %v %+v", err, logs)
	}
}

func assertNoRule(t *testing.T, app *App, botID, dir string) {
	t.Helper()
	got, err := app.st.ListUserPermRules(botID)
	if err != nil || len(got) != 0 {
		t.Fatalf("row %+v %v", got, err)
	}
	logs, err := app.st.ListLog(botID, "user_perm_rule", "", 10)
	if err != nil || len(logs) != 0 {
		t.Fatalf("audit %+v %v", logs, err)
	}
	for _, name := range []string{"user-permissions.json", "grok-permission-rules"} {
		p := filepath.Join(dir, name)
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("%s left behind: %v", name, err)
		}
	}
}

func TestRefusedSuggestionWhitespace(t *testing.T) {
	app := newApp(t, t.TempDir(), nil)
	bot, err := app.st.CreateBot("perm", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	sug, err := app.st.SaveSuggestion(store.PermSuggestion{
		BotID: bot.ID, Pattern: "Bash(pwd)", Effect: "allow",
		Summary: "classification refused auto-allow", Status: "refused", Count: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := serve(t, app)
	tok := armAdmin(app)
	base := srv.URL + "/api/bots/" + bot.ID + "/permission-suggestions/" + sug.ID + "/accept"
	res, body := do(t, "POST", base, map[string]any{"effect": "allow", "pattern": "  Bash( pwd )  "}, tok)
	if res.StatusCode != 400 || !strings.Contains(string(body), "classification refused") {
		t.Fatalf("padded refused %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", base, map[string]any{"effect": "allow", "pattern": "Bash(ls *)"}, tok)
	if res.StatusCode != 201 {
		t.Fatalf("edited %d %s", res.StatusCode, body)
	}
}
