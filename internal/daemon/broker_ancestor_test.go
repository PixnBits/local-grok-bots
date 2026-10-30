package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/permbroker"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestGolden_StartupCriticalPathsWithoutLaunch(t *testing.T) {
	app := newApp(t, "", nil)
	app.editPol(func(p *policy.Policy) { p.Broker = "hook" })
	bot, err := app.st.CreateBot("Ada", "help", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	admin := filepath.Join(app.cfg.DataDir, adminTokenFile)
	ws := app.botWorkspace(bot.ID)
	for _, c := range []string{
		filepath.Join(app.cfg.DataDir, "permbroker"),
		filepath.Join(app.cfg.DataDir, "cli"),
		admin,
	} {
		if c == ws || strings.HasPrefix(c, ws+string(os.PathSeparator)) {
			t.Fatalf("workspace %s is an ancestor of %s", ws, c)
		}
	}
	ctx := context.Background()
	read := "cat " + admin
	shell := app.broker.Evaluate(ctx, shellEval(bot.ID, ws, read))
	if shell.Level != permbroker.LevelCritical || shell.Eligible {
		t.Fatalf("run_shell %+v", shell)
	}
	bashReq := shellEval(bot.ID, ws, read)
	bashReq.ToolName = "Bash"
	bash := app.broker.Evaluate(ctx, bashReq)
	if bash.Level != permbroker.LevelCritical || bash.Eligible {
		t.Fatalf("bash %+v", bash)
	}
	if _, err := app.execTool(ctx, bot, "run_shell", map[string]any{"command": read}); err == nil || !strings.Contains(err.Error(), "pending approval") {
		t.Fatalf("gate %v", err)
	}
	for _, cmd := range []string{"ls", "grep -r token ."} {
		d := app.broker.Evaluate(ctx, shellEval(bot.ID, ws, cmd))
		if d.Level == permbroker.LevelCritical {
			t.Fatalf("workspace %s %+v", cmd, d)
		}
	}
}

func TestGolden_RunShellCmdAliasGated(t *testing.T) {
	app := newApp(t, "", nil)
	app.editPol(func(p *policy.Policy) { p.Broker = "hook" })
	bot, err := app.st.CreateBot("Ada", "help", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	cmd := "cat " + filepath.Join(app.cfg.DataDir, adminTokenFile)
	for _, args := range []map[string]any{
		{"cmd": cmd},
		{"command": cmd},
	} {
		_, err := app.execTool(context.Background(), bot, "run_shell", args)
		if err == nil || !strings.Contains(err.Error(), "pending approval") {
			t.Fatalf("args %v err %v", args, err)
		}
	}
}

func TestGolden_HookLatchSurvivesRestore(t *testing.T) {
	body := "#!/bin/sh\nexit 0\n"
	hook := writeHookScript(t, body)
	h := startBrokerClaude(t, hook, "hook")
	before, err := permbroker.PinHook(hook)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nexit 9\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	first := h.post(t)
	if first.status != "error" || !strings.Contains(first.errText, "hook changed") {
		t.Fatalf("swap %s %q", first.status, first.errText)
	}
	if err := os.WriteFile(hook, []byte(body), before.Mode); err != nil {
		t.Fatal(err)
	}
	when := time.Unix(0, before.Mtime)
	if err := os.Chtimes(hook, when, when); err != nil {
		t.Fatal(err)
	}
	after, err := permbroker.PinHook(hook)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("restore did not match the pin\nbefore %+v\nafter %+v", before, after)
	}
	second := h.post(t)
	if second.status != "error" || !strings.Contains(second.errText, "hook changed") {
		t.Fatalf("restored bytes cleared the latch %s %q", second.status, second.errText)
	}
	const token = "lgbr_admintesttokenvalue"
	h.app.cfg.AuthToken = token
	res, resp := do(t, "POST", h.srv.URL+"/api/permbroker/hook/repin", map[string]any{}, token)
	if res.StatusCode != 200 {
		t.Fatalf("repin %d %s", res.StatusCode, resp)
	}
	h.app.cfg.AuthToken = ""
	third := h.post(t)
	if third.status != "done" || third.errText != "" {
		t.Fatalf("after repin %s %q", third.status, third.errText)
	}
}

func TestGolden_RevokeAuditRow(t *testing.T) {
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
	saved, err := app.broker.SaveRule(permbroker.Rule{
		Effect: permbroker.EffectAllow, Argv: []string{"git", "status"},
		Tool: permbroker.ToolShell, Scope: permbroker.ScopeBot, BotID: "bot",
	})
	if err != nil {
		t.Fatal(err)
	}
	res, body := do(t, "DELETE", srv.URL+"/api/permbroker/rules/"+saved.ID, nil, token)
	if res.StatusCode != 200 {
		t.Fatalf("revoke %d %s", res.StatusCode, body)
	}
	aud, err := os.ReadFile(audPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(aud), `"action":"rule_revoke"`) || !strings.Contains(string(aud), saved.ID) {
		t.Fatalf("daemon audit %s", aud)
	}
	brokerAudit, err := os.ReadFile(filepath.Join(app.cfg.DataDir, "permbroker", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(brokerAudit), `"decision":"revoke"`) || !strings.Contains(string(brokerAudit), saved.ID) {
		t.Fatalf("broker audit %s", brokerAudit)
	}
}
