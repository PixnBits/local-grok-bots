package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/permbroker"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestGolden_PolicyCannotLowerShippedLevel(t *testing.T) {
	t.Run("startup", func(t *testing.T) {
		err := newAppPolicy(t, `
[backend]
backend = "ollama"

[cli.permission]
broker = "hook"

[[cli.permission.risk]]
tool = "run_shell"
argv = ["git", "status"]
level = "unclassified"
`)
		if !errors.Is(err, permbroker.ErrLevelLowered) {
			t.Fatalf("startup err = %v", err)
		}
	})
	t.Run("unknown broker", func(t *testing.T) {
		err := newAppPolicy(t, `
[backend]
backend = "ollama"

[cli.permission]
broker = "yes"
`)
		if err == nil || !strings.Contains(err.Error(), "broker") {
			t.Fatalf("startup err = %v", err)
		}
	})
}

func newAppPolicy(t *testing.T, body string) error {
	t.Helper()
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(config.Config{
		DataDir: dir, PolicyPath: path, BindAddr: "127.0.0.1:0",
		OllamaURL: "http://127.0.0.1:9", Model: "test-model", Version: "0.1.0",
	}, nil)
	return err
}

func TestBrokerStreamControlDeniesWithoutCard(t *testing.T) {
	app := newApp(t, "", nil)
	app.setBrokerOn("bot", true)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	dec := app.decideStreamControl(ctx, "bot", "run", "sess", clisession.ControlAsk{
		Tool: "Bash", Args: map[string]any{"command": "echo hi"},
	})
	if time.Since(start) > 200*time.Millisecond {
		t.Fatalf("stream ask waited %s", time.Since(start))
	}
	if dec.Silent || dec.Behavior != permission.Deny {
		t.Fatalf("decision %+v", dec)
	}
}

func TestBrokerRunShellAskDoesNotExecute(t *testing.T) {
	app := newApp(t, "", nil)
	app.editPol(func(p *policy.Policy) { p.Broker = "hook" })
	bot, err := app.st.CreateBot("Ada", "help", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	out, err := app.execTool(context.Background(), bot, "run_shell", map[string]any{"command": "echo hi"})
	if err == nil || !strings.Contains(err.Error(), "pending approval") {
		t.Fatalf("out %q err %v", out, err)
	}
	if strings.Contains(out, "hi") {
		t.Fatalf("command ran: %q", out)
	}
	if len(app.broker.ListPending()) != 1 {
		t.Fatalf("pending %+v", app.broker.ListPending())
	}
	clean, gerr := app.gateShell(context.Background(), bot, "git push origin main")
	if gerr != nil || !clean {
		t.Fatalf("git push clean %v err %v", clean, gerr)
	}
	if len(app.broker.ListPending()) != 1 {
		t.Fatal("git push created an ask")
	}
	_, err = app.gateShell(context.Background(), bot, "git push origin main && true")
	if err == nil || !strings.Contains(err.Error(), "pending approval") {
		t.Fatalf("compound git push err %v", err)
	}
}

func TestUserMessageEndsPreviousTask(t *testing.T) {
	app := newApp(t, "", nil)
	app.editPol(func(p *policy.Policy) { p.Broker = "hook" })
	bot, err := app.st.CreateBot("Ada", "help", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	app.noteUserMessage(bot.ID, "m1", "")
	_, err = app.gateShell(context.Background(), bot, "echo hi")
	if err == nil || !strings.Contains(err.Error(), "pending approval") {
		t.Fatal(err)
	}
	pending := app.broker.ListPending()
	if len(pending) != 1 || pending[0].TaskID != "m1" {
		t.Fatalf("pending %+v", pending)
	}
	app.noteUserMessage(bot.ID, "m2", "")
	if err := app.broker.Decide(pending[0].ID, "approve", permbroker.ScopeOnce); err != permbroker.ErrStale {
		t.Fatalf("old task err %v", err)
	}
}

func TestGolden_HookSIGKILLed(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		hook := writeHookScript(t, "#!/bin/sh\nprintf '%s\\n' '{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\",\"permissionDecisionReason\":\"allowed\"}}'\nexit 0\n")
		t.Setenv("LGB_FAKE_HOOK", "kill")
		t.Setenv("LGB_FAKE_TOOL", "Read")
		ran := runBrokerClaude(t, hook, nil)
		if ran.marker {
			t.Fatal("read ran after the hook was killed")
		}
		if ran.status != "done" || ran.errText != "" {
			t.Fatalf("run %s %s", ran.status, ran.errText)
		}
		if strings.Contains(ran.argv, "--allowedTools") || strings.Contains(ran.argv, "dangerously-skip-permissions") {
			t.Fatalf("launch can allow:\n%s", ran.argv)
		}
	})
	t.Run("bash", func(t *testing.T) {
		hook := writeHookScript(t, "#!/bin/sh\nprintf '%s\\n' '{\"hookSpecificOutput\":{\"permissionDecision\":\"allow\"}}'\nexit 0\n")
		t.Setenv("LGB_FAKE_HOOK", "kill")
		ran := runBrokerClaude(t, hook, nil)
		if ran.marker {
			t.Fatal("bash ran after the hook was killed")
		}
		if ran.status != "done" || ran.errText != "" {
			t.Fatalf("run %s %s", ran.status, ran.errText)
		}
	})
}

func TestGolden_HookOverCLITimeout(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		hook := writeHookScript(t, "#!/bin/sh\nsleep 30\nprintf '%s\\n' '{\"hookSpecificOutput\":{\"permissionDecision\":\"allow\"}}'\nexit 0\n")
		t.Setenv("LGB_FAKE_HOOK", "timeout")
		t.Setenv("LGB_FAKE_HOOK_TIMEOUT_MS", "200")
		t.Setenv("LGB_FAKE_TOOL", "Read")
		start := time.Now()
		ran := runBrokerClaude(t, hook, nil)
		if time.Since(start) > 10*time.Second {
			t.Fatalf("timeout case waited %s", time.Since(start))
		}
		if ran.marker {
			t.Fatal("read ran after the hook timed out")
		}
		if ran.status != "done" || ran.errText != "" {
			t.Fatalf("run %s %s", ran.status, ran.errText)
		}
	})
	t.Run("bash", func(t *testing.T) {
		hook := writeHookScript(t, "#!/bin/sh\nsleep 30\nexit 0\n")
		t.Setenv("LGB_FAKE_HOOK", "timeout")
		t.Setenv("LGB_FAKE_HOOK_TIMEOUT_MS", "200")
		start := time.Now()
		ran := runBrokerClaude(t, hook, nil)
		if time.Since(start) > 10*time.Second {
			t.Fatalf("timeout case waited %s", time.Since(start))
		}
		if ran.marker {
			t.Fatal("bash ran after the hook timed out")
		}
	})
}

func TestGolden_DenyLetsRunContinue(t *testing.T) {
	ran := runBrokerClaude(t, builtHook(t), nil)
	if ran.marker {
		t.Fatal("denied tool ran")
	}
	if ran.status != "done" || ran.errText != "" || strings.Contains(ran.errText, "stopped after denial") {
		t.Fatalf("run %s %q", ran.status, ran.errText)
	}
	if !strings.Contains(ran.reply, "continued") {
		t.Fatalf("reply %q", ran.reply)
	}
	if len(ran.pending) == 0 {
		t.Fatal("deny did not record a pending item")
	}
}

func TestGolden_ProjectUserSettingsIgnored(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "project-hook-ran")
	user := filepath.Join(t.TempDir(), "user-settings.json")
	if err := os.WriteFile(user, []byte(`{"permissions":{"allow":["Bash(echo-from-user-settings)"]},"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"touch `+marker+`"}]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LGB_FAKE_USER_SETTINGS", user)
	t.Setenv("LGB_PROJECT_HOOK_MARKER", marker)
	ran := runBrokerClaude(t, builtHook(t), func(ws string) {
		dir := filepath.Join(ws, ".claude")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		proj := `{"permissions":{"allow":["Bash(echo-from-project)"]},"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"touch ` + marker + `"}]}]}}`
		local := `{"permissions":{"allow":["Bash(echo-from-local)"]}}`
		if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(proj), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "settings.local.json"), []byte(local), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if ran.marker {
		t.Fatal("tool ran from project or user settings")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("project or user hook ran")
	}
	if !strings.Contains(ran.argv, "--setting-sources=\n") {
		t.Fatalf("missing empty setting sources:\n%s", ran.argv)
	}
	settings := settingsArg(t, ran.argv)
	body, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, bad := range []string{"echo-from-project", "echo-from-local", "echo-from-user-settings", "disableAllHooks", marker} {
		if strings.Contains(text, bad) {
			t.Fatalf("settings contain %s\nlogs %s", bad, ran.logs)
		}
	}
	var doc struct {
		Permissions struct {
			Allow []string `json:"allow"`
		} `json:"permissions"`
	}
	if json.Unmarshal(body, &doc) != nil || len(doc.Permissions.Allow) != 0 {
		t.Fatalf("settings allow list: %s", text)
	}
	if !strings.Contains(text, `"matcher": "*"`) || !strings.Contains(text, "PreToolUse") {
		t.Fatalf("settings missing the broker hook\nlogs %s", ran.logs)
	}
	if strings.Contains(ran.argv, "--allowedTools") {
		t.Fatalf("broker launch kept an allow list:\n%s", ran.argv)
	}
}

func TestFakeFallthroughDeniesLockedLaunch(t *testing.T) {
	locked := []string{"claude", "--setting-sources=", "--permission-prompts", "none", "--disallowedTools", "Bash(rm *)"}
	if fakeFallthroughAllows(locked) {
		t.Fatal("locked launch allowed the tool")
	}
	if !fakeFallthroughAllows([]string{"claude", "--allowedTools", "Bash"}) {
		t.Fatal("allow list did not fall open")
	}
	if !fakeFallthroughAllows([]string{"claude", "--permission-mode", "acceptEdits"}) {
		t.Fatal("acceptEdits did not fall open")
	}
}

func TestGolden_AdminPendingIsAdminOnly(t *testing.T) {
	app := newApp(t, "", nil)
	srv := serve(t, app)
	base := srv.URL
	const token = "lgbr_admintesttokenvalue"
	app.cfg.AuthToken = token
	first := askPending(t, app, "echo hi")
	res, body := do(t, "GET", base+"/api/permbroker/pending", nil, "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token %d %s", res.StatusCode, body)
	}
	res, body = do(t, "GET", base+"/api/permbroker/pending", nil, token)
	if res.StatusCode != 200 || !strings.Contains(string(body), first) {
		t.Fatalf("list %d %s", res.StatusCode, body)
	}
	app.noteRunToken("lgbr_testtokenvalue", "b1", "run")
	res, body = do(t, "GET", base+"/api/permbroker/pending", nil, "lgbr_testtokenvalue")
	if res.StatusCode != 403 {
		t.Fatalf("run token %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", base+"/api/permbroker/pending/"+first, map[string]string{"decision": "approve", "scope": "once"}, "lgbr_testtokenvalue")
	if res.StatusCode != 403 {
		t.Fatalf("run token decide %d %s", res.StatusCode, body)
	}
	if len(app.broker.ListPending()) != 1 {
		t.Fatal("run token changed pending")
	}
	req, err := http.NewRequest(http.MethodPost, base+"/api/permbroker/pending/"+first, strings.NewReader(`{"decision":"approve","scope":"once"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = req.URL.Host
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resHTTP, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resHTTP.Body.Close()
	if resHTTP.StatusCode != 403 {
		t.Fatalf("cross-site %d", resHTTP.StatusCode)
	}
	res, body = do(t, "POST", base+"/api/permbroker/pending/"+first, map[string]string{"decision": "approve", "scope": "once"}, token)
	if res.StatusCode != 200 {
		t.Fatalf("approve %d %s", res.StatusCode, body)
	}
	if d := askRaw(t, app, "echo hi"); d.Verdict != permbroker.VerdictAllow {
		t.Fatalf("retry %+v", d)
	}
	crit := askPending(t, app, "gh auth token")
	res, body = do(t, "POST", base+"/api/permbroker/pending/"+crit, map[string]string{"decision": "approve", "scope": "bot"}, token)
	if res.StatusCode != 400 {
		t.Fatalf("critical bot rule %d %s", res.StatusCode, body)
	}
	app.broker.CancelSession("b1", "s1")
	res, body = do(t, "POST", base+"/api/permbroker/pending/"+crit, map[string]string{"decision": "approve", "scope": "once"}, token)
	if res.StatusCode != 409 {
		t.Fatalf("stale %d %s", res.StatusCode, body)
	}
	keep := askPending(t, app, "echo ok")
	other := askPending(t, app, "echo no")
	res, body = do(t, "POST", base+"/api/permbroker/pending/deny-all", map[string]any{"ids": []string{keep, "missing"}}, token)
	if res.StatusCode != 200 || !strings.Contains(string(body), `"ok":true`) || !strings.Contains(string(body), "missing") {
		t.Fatalf("partial deny-all %d %s", res.StatusCode, body)
	}
	if len(app.broker.ListPending()) != 1 {
		t.Fatalf("partial deny %+v", app.broker.ListPending())
	}
	res, body = do(t, "POST", base+"/api/permbroker/pending/deny-all", map[string]any{"ids": []string{}}, token)
	if res.StatusCode != 400 || len(app.broker.ListPending()) != 1 {
		t.Fatalf("empty deny-all %d %s pending %d", res.StatusCode, body, len(app.broker.ListPending()))
	}
	res, body = do(t, "POST", base+"/api/permbroker/pending/deny-all", map[string]any{}, token)
	if res.StatusCode != 400 || len(app.broker.ListPending()) != 1 {
		t.Fatalf("empty body deny-all %d %s pending %+v", res.StatusCode, body, app.broker.ListPending())
	}
	left := app.broker.ListPending()
	res, body = do(t, "POST", base+"/api/permbroker/pending/deny-all", map[string]any{"ids": []string{left[0].ID}}, token)
	if res.StatusCode != 200 || len(app.broker.ListPending()) != 0 {
		t.Fatalf("deny-all %d %s pending %+v", res.StatusCode, body, app.broker.ListPending())
	}
	_ = other
}

func TestGolden_UnusableHookRefusesTurn(t *testing.T) {
	t.Run("group-writable", func(t *testing.T) {
		hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
		if err := os.Chmod(hook, 0o775); err != nil {
			t.Fatal(err)
		}
		ran := runClaudeTurn(t, claudeTurn{hook: hook, broker: "hook"})
		assertHookRefused(t, ran, "group or world writable")
	})
	t.Run("missing", func(t *testing.T) {
		hook := filepath.Join(t.TempDir(), "lgb-permhook")
		ran := runClaudeTurn(t, claudeTurn{hook: hook, broker: "hook"})
		assertHookRefused(t, ran, "hook binary")
		if !strings.Contains(ran.errText, hook) {
			t.Fatalf("error %q", ran.errText)
		}
	})
	t.Run("long socket", func(t *testing.T) {
		parent, err := os.MkdirTemp("", "lgb")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(parent) })
		dir := filepath.Join(parent, strings.Repeat("d", 90))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
		ran := runClaudeTurn(t, claudeTurn{hook: hook, broker: "hook", dataDir: dir})
		assertHookRefused(t, ran, "socket path is too long")
	})
	t.Run("broker off", func(t *testing.T) {
		hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
		if err := os.Chmod(hook, 0o775); err != nil {
			t.Fatal(err)
		}
		ran := runClaudeTurn(t, claudeTurn{hook: hook, broker: "off"})
		if ran.status != "done" || ran.errText != "" || ran.argv == "" || ran.marker {
			t.Fatalf("status %s err %q argv %q marker %v", ran.status, ran.errText, ran.argv, ran.marker)
		}
		body, err := os.ReadFile(settingsArg(t, ran.argv))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "disableAllHooks") {
			t.Fatalf("settings %s", body)
		}
	})
	t.Run("startup warning", func(t *testing.T) {
		t.Setenv("MANAGED_POLICY", "")
		bad := writeHookScript(t, "#!/bin/sh\nexit 0\n")
		if err := os.Chmod(bad, 0o775); err != nil {
			t.Fatal(err)
		}
		_, out := startWithBrokerPolicy(t, "hook", bad)
		if !strings.Contains(out, "local-grok-bots: ") || !strings.Contains(out, "permission broker hook cannot be used") || !strings.Contains(out, "group or world writable") {
			t.Fatalf("stderr %s", out)
		}
		missing := filepath.Join(t.TempDir(), "lgb-permhook")
		_, out = startWithBrokerPolicy(t, "hook", missing)
		if !strings.Contains(out, "permission broker hook cannot be used") || !strings.Contains(out, missing) {
			t.Fatalf("stderr %s", out)
		}
		_, out = startWithBrokerPolicy(t, "hook", "")
		if !strings.Contains(out, "permission broker hook cannot be used") || !strings.Contains(out, "lgb-permhook") {
			t.Fatalf("derived stderr %s", out)
		}
		good := writeHookScript(t, "#!/bin/sh\nexit 0\n")
		_, out = startWithBrokerPolicy(t, "hook", good)
		if strings.Contains(out, "permission broker hook cannot be used") {
			t.Fatalf("good hook warned: %s", out)
		}
		_, out = startWithBrokerPolicy(t, "off", missing)
		if strings.Contains(out, "permission broker hook cannot be used") {
			t.Fatalf("broker off warned: %s", out)
		}
	})
}

func TestStaleApprovalWritesNoAllow(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  string
	}{
		{name: "session ended", end: "session"},
		{name: "ruleset changed", end: "ruleset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := newApp(t, "", nil)
			srv := serve(t, app)
			const token = "lgbr_admintesttokenvalue"
			app.cfg.AuthToken = token
			id := askPending(t, app, "echo hi")
			if tc.end == "session" {
				app.broker.CancelSession("b1", "s1")
			} else if _, err := app.broker.SaveRule(permbroker.Rule{
				Effect: permbroker.EffectDeny, Argv: []string{"git", "status"},
				Tool: permbroker.ToolShell, Scope: permbroker.ScopeBot, BotID: "b1",
			}); err != nil {
				t.Fatal(err)
			}
			res, body := do(t, "POST", srv.URL+"/api/permbroker/pending/"+id, map[string]string{"decision": "approve", "scope": "once"}, token)
			if res.StatusCode != http.StatusConflict {
				t.Fatalf("status %d %s", res.StatusCode, body)
			}
			if d := askRaw(t, app, "echo hi"); d.Verdict == permbroker.VerdictAllow {
				t.Fatalf("allowed %+v", d)
			}
			rules, err := os.ReadFile(filepath.Join(app.cfg.DataDir, "permbroker", "rules.json"))
			if err == nil && strings.Contains(string(rules), `"effect": "allow"`) {
				t.Fatalf("rules %s", rules)
			}
			if tc.end == "session" && app.broker.RuleCount() != 0 {
				t.Fatalf("rules %d", app.broker.RuleCount())
			}
			audit, err := os.ReadFile(filepath.Join(app.cfg.DataDir, "permbroker", "audit.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(audit), `"decision":"approve"`) || strings.Contains(string(audit), `"decision":"allow"`) {
				t.Fatalf("audit\n%s", audit)
			}
		})
	}
}

type brokerRun struct {
	status  string
	errText string
	reply   string
	argv    string
	marker  bool
	pending []permbroker.Pending
	logs    string
}

type brokerHarness struct {
	app      *App
	srv      *httptest.Server
	bot      store.Bot
	argvPath string
	marker   string
}

func runBrokerClaude(t *testing.T, hook string, before func(ws string)) brokerRun {
	t.Helper()
	h := startBrokerClaude(t, hook, "hook")
	if before != nil {
		before(filepath.Join(h.app.ws, "bots", h.bot.ID))
	}
	return h.post(t)
}

func startBrokerClaude(t *testing.T, hook, broker string) brokerHarness {
	t.Helper()
	// The per-bot socket path has to fit in a Unix sun_path (108 bytes).
	// t.TempDir includes the test name and is too long for that.
	dir, err := os.MkdirTemp("", "lgbp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return startBrokerClaudeDir(t, dir, hook, broker)
}

func startBrokerClaudeDir(t *testing.T, dir, hook, broker string) brokerHarness {
	t.Helper()
	installFakeClaude(t, dir)
	argvPath := filepath.Join(dir, "argv.log")
	marker := filepath.Join(dir, "tool-marker")
	t.Setenv("LGB_ARGV_LOG", argvPath)
	t.Setenv("LGB_TOOL_MARKER", marker)
	app := newApp(t, dir, nil)
	app.cliTTY = func() bool { return false }
	app.editPol(func(p *policy.Policy) {
		p.Backend = "claude"
		p.CLIPermitted = true
		p.Broker = broker
		if hook != "" {
			p.HookPath = hook
		}
		p.UIPrompts = false
		p.ClaudeTransport = policy.TransportNone
		p.TimersEnabled = true
		p.Idle = time.Hour
		p.Imminent = time.Minute
	})
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Ada", "description": "p"}, "")
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	return brokerHarness{app: app, srv: srv, bot: bot, argvPath: argvPath, marker: marker}
}

func (h brokerHarness) post(t *testing.T) brokerRun {
	t.Helper()
	res, b := do(t, "POST", h.srv.URL+"/api/bots/"+h.bot.ID+"/thread/messages", map[string]any{"content": "go"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	waitIdle(t, h.srv.URL, h.bot.ID, "")
	got, err := h.app.st.GetBot(h.bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, statErr := os.Stat(h.marker)
	reply := ""
	for _, m := range thread(t, h.srv.URL, h.bot.ID, "") {
		if m.Role == "bot" {
			reply = m.Content
		}
	}
	var logs strings.Builder
	if ev, lerr := h.app.st.ListLog(h.bot.ID, "", "", 50); lerr == nil {
		for _, e := range ev {
			if e.Kind == "permbroker" || e.Kind == "cli_override" || e.Kind == "model_call" {
				fmt.Fprintf(&logs, "%s %s\n", e.Kind, e.Detail)
			}
		}
	}
	// A turn refused before the CLI starts never creates the argv log.
	argv := ""
	if body, rerr := os.ReadFile(h.argvPath); rerr == nil {
		argv = string(body)
	} else if !os.IsNotExist(rerr) {
		t.Fatal(rerr)
	}
	return brokerRun{
		status: got.LastRunStatus, errText: got.LastRunError, reply: reply,
		argv: argv, marker: statErr == nil,
		pending: h.app.broker.ListPending(), logs: logs.String(),
	}
}

type claudeTurn struct {
	hook    string
	broker  string
	dataDir string
}

func runClaudeTurn(t *testing.T, opt claudeTurn) brokerRun {
	t.Helper()
	dir := opt.dataDir
	if dir == "" {
		var err error
		dir, err = os.MkdirTemp("", "lgbp")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
	}
	installFakeClaude(t, dir)
	argvPath := filepath.Join(dir, "argv.log")
	marker := filepath.Join(dir, "tool-marker")
	t.Setenv("LGB_ARGV_LOG", argvPath)
	t.Setenv("LGB_TOOL_MARKER", marker)
	app := newApp(t, dir, nil)
	app.cliTTY = func() bool { return false }
	app.editPol(func(p *policy.Policy) {
		p.Backend = "claude"
		p.CLIPermitted = true
		p.Broker = opt.broker
		if opt.hook != "" {
			p.HookPath = opt.hook
		}
		p.UIPrompts = false
		p.ClaudeTransport = policy.TransportNone
		p.TimersEnabled = true
		p.Idle = time.Hour
		p.Imminent = time.Minute
	})
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Ada", "description": "p"}, "")
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{"content": "go"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, "")
	got, err := app.st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	argv := ""
	if body, rerr := os.ReadFile(argvPath); rerr == nil {
		argv = string(body)
	}
	_, statErr := os.Stat(marker)
	return brokerRun{
		status: got.LastRunStatus, errText: got.LastRunError, argv: argv, marker: statErr == nil,
	}
}

func assertHookRefused(t *testing.T, ran brokerRun, reason string) {
	t.Helper()
	if ran.status != "error" || !strings.Contains(ran.errText, "permission broker is enabled but its hook cannot be used") || !strings.Contains(ran.errText, reason) || !strings.Contains(ran.errText, "so the turn was refused") {
		t.Fatalf("run %s %q", ran.status, ran.errText)
	}
	if ran.argv != "" || ran.marker {
		t.Fatalf("claude started argv %q marker %v", ran.argv, ran.marker)
	}
}

func startWithBrokerPolicy(t *testing.T, broker, hook string) (*App, string) {
	t.Helper()
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	var body strings.Builder
	body.WriteString("[backend]\nbackend = \"ollama\"\n\n[cli.permission]\nbroker = " + fmt.Sprintf("%q", broker) + "\n")
	if hook != "" {
		body.WriteString("hook_path = " + fmt.Sprintf("%q", hook) + "\n")
	}
	path := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(path, []byte(body.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	var app *App
	var err error
	out := captureStderrDuring(t, func() {
		app, err = New(config.Config{
			DataDir: dir, PolicyPath: path, BindAddr: "127.0.0.1:0",
			OllamaURL: "http://127.0.0.1:9", Model: "test-model", Version: "0.1.0",
		}, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	return app, out
}

func captureStderrDuring(t *testing.T, fn func()) (out string) {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	defer func() {
		os.Stderr = old
		_ = w.Close()
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		_ = r.Close()
		out = buf.String()
	}()
	fn()
	return ""
}

func askPending(t *testing.T, app *App, command string) string {
	t.Helper()
	d := askRaw(t, app, command)
	if d.Verdict == permbroker.VerdictAllow || d.PendingID == "" {
		t.Fatalf("ask %s -> %+v", command, d)
	}
	return d.PendingID
}

func askRaw(t *testing.T, app *App, command string) permbroker.Decision {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	return app.broker.Evaluate(context.Background(), permbroker.Request{
		BotID: "b1", SessionID: "s1", Cwd: "/work",
		ToolName: "Bash", ToolInput: raw,
	})
}

func settingsArg(t *testing.T, argv string) string {
	t.Helper()
	lines := strings.Split(argv, "\n")
	for i, line := range lines {
		if line == "--settings" && i+1 < len(lines) {
			return lines[i+1]
		}
	}
	t.Fatalf("no --settings in\n%s", argv)
	return ""
}

// hookHome is the real user home captured before tests replace HOME.
// Hook binaries cannot live under a group or world writable directory.
var hookHome string

func init() {
	home, err := os.UserHomeDir()
	if err == nil {
		hookHome = home
	}
}

func hookTempDir(t *testing.T, pattern string) string {
	t.Helper()
	if hookHome == "" {
		t.Fatal("home is unknown")
	}
	dir, err := os.MkdirTemp(hookHome, pattern)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func writeHookScript(t *testing.T, body string) string {
	t.Helper()
	dir := hookTempDir(t, ".lgb-hook-")
	path := filepath.Join(dir, "hook")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

var (
	builtHookOnce sync.Once
	builtHookBin  string
	builtHookErr  error
	hookKeep      []string
)

func builtHook(t *testing.T) string {
	t.Helper()
	builtHookOnce.Do(func() {
		root, err := findModuleRoot()
		if err != nil {
			builtHookErr = err
			return
		}
		if hookHome == "" {
			builtHookErr = errors.New("home is unknown")
			return
		}
		dir, err := os.MkdirTemp(hookHome, ".lgb-permhook-bin-")
		if err != nil {
			builtHookErr = err
			return
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			builtHookErr = err
			return
		}
		bin := filepath.Join(dir, "lgb-permhook")
		cmd := exec.Command("go", "build", "-o", bin, "./cmd/lgb-permhook")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			builtHookErr = fmt.Errorf("%w: %s", err, out)
			return
		}
		if err := os.Chmod(bin, 0o755); err != nil {
			builtHookErr = err
			return
		}
		builtHookBin = bin
		hookKeep = append(hookKeep, dir)
	})
	if builtHookErr != nil {
		t.Fatal(builtHookErr)
	}
	return builtHookBin
}

func findModuleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found")
		}
		dir = parent
	}
}
