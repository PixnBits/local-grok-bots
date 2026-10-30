package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/permbroker"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestGolden_BrokerSettingsBlockOnFailure(t *testing.T) {
	hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
	h := startBrokerClaude(t, hook, "hook")
	ran := h.post(t)
	if ran.status != "done" || ran.errText != "" {
		t.Fatalf("run %s %s", ran.status, ran.errText)
	}
	body, err := os.ReadFile(settingsArg(t, ran.argv))
	if err != nil {
		t.Fatal(err)
	}
	assertBrokerSettings(t, body, hook)
	raw, err := json.Marshal(map[string]string{"file_path": hook})
	if err != nil {
		t.Fatal(err)
	}
	d := h.app.broker.Evaluate(context.Background(), permbroker.Request{
		BotID: h.bot.ID, SessionID: "s-review", Cwd: h.app.ws,
		ToolName: "Read", ToolInput: raw,
	})
	if d.Level != permbroker.LevelCritical || d.Verdict == permbroker.VerdictAllow || d.PendingID == "" {
		t.Fatalf("hook path decision %+v", d)
	}
}

func TestGolden_OldClaudeRefusesBroker(t *testing.T) {
	t.Setenv("LGB_FAKE_CLAUDE_VERSION", "2.1.294 (Claude Code)")
	hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
	ran := runBrokerClaude(t, hook, nil)
	if ran.status != "error" || !strings.Contains(ran.errText, "2.1.294") || !strings.Contains(ran.errText, "so the turn was refused") {
		t.Fatalf("run %s %q", ran.status, ran.errText)
	}
	if ran.marker || strings.Contains(ran.argv, "--settings") || strings.Contains(ran.argv, "-p") {
		t.Fatalf("turn started argv %q marker %v", ran.argv, ran.marker)
	}
	if !strings.Contains(ran.argv, "--version") {
		t.Fatalf("version probe missing\n%s", ran.argv)
	}
}

func TestGolden_HookUnpinnedAtStartupRefusesTurn(t *testing.T) {
	hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(hook, 0o775); err != nil {
		t.Fatal(err)
	}
	h := startBrokerClaude(t, hook, "hook")
	if err := os.Chmod(hook, 0o755); err != nil {
		t.Fatal(err)
	}
	ran := h.post(t)
	const sentence = "hook was not pinned when the policy loaded"
	if ran.status != "error" || !strings.Contains(ran.errText, sentence) || !strings.Contains(ran.errText, "so the turn was refused") {
		t.Fatalf("run %s %q", ran.status, ran.errText)
	}
	if strings.Contains(ran.argv, "-p") || strings.Contains(ran.argv, "--version") || ran.marker {
		t.Fatalf("claude started argv %q marker %v", ran.argv, ran.marker)
	}
	if !strings.Contains(ran.logs, sentence) {
		t.Fatalf("logs %s", ran.logs)
	}
	audit, err := os.ReadFile(filepath.Join(h.app.cfg.DataDir, "permbroker", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), sentence) {
		t.Fatalf("audit\n%s", audit)
	}
}

func TestGolden_LaunchEnvPathChecksThatClaude(t *testing.T) {
	hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
	h := startBrokerClaude(t, hook, "hook")
	oldDir := filepath.Join(h.app.cfg.DataDir, "oldbin")
	if err := os.MkdirAll(oldDir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"if [ -n \"$LGB_ARGV_LOG\" ]; then\n" +
		"  printf '%s\\n' \"$@\" >> \"$LGB_ARGV_LOG\"\n" +
		"  printf '%s\\n' '---' >> \"$LGB_ARGV_LOG\"\n" +
		"fi\n" +
		"printf '%s\\n' '2.1.294 (Claude Code)'\n"
	if err := os.WriteFile(filepath.Join(oldDir, "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	h.app.editPol(func(p *policy.Policy) {
		if p.CLIEnv == nil {
			p.CLIEnv = map[string]string{}
		}
		p.CLIEnv["PATH"] = oldDir
	})
	ran := h.post(t)
	if ran.status != "error" || !strings.Contains(ran.errText, "2.1.294") || !strings.Contains(ran.errText, "so the turn was refused") {
		t.Fatalf("run %s %q", ran.status, ran.errText)
	}
	if strings.Contains(ran.argv, "-p") || ran.marker {
		t.Fatalf("turn started argv %q marker %v", ran.argv, ran.marker)
	}
	if !strings.Contains(ran.argv, "--version") {
		t.Fatalf("version probe missing\n%s", ran.argv)
	}
}

func TestGolden_HookIntegrityChangeRefusesTurn(t *testing.T) {
	t.Run("mode loosened", func(t *testing.T) {
		hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
		h := startBrokerClaude(t, hook, "hook")
		if err := os.Chmod(hook, 0o775); err != nil {
			t.Fatal(err)
		}
		assertIntegrityRefused(t, h, h.post(t))
	})
	t.Run("content swapped", func(t *testing.T) {
		hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
		h := startBrokerClaude(t, hook, "hook")
		if err := os.WriteFile(hook, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		assertIntegrityRefused(t, h, h.post(t))
	})
	t.Run("inode swapped", func(t *testing.T) {
		hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
		h := startBrokerClaude(t, hook, "hook")
		copyPath := hook + ".next"
		if err := os.WriteFile(copyPath, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(copyPath, hook); err != nil {
			t.Fatal(err)
		}
		assertIntegrityRefused(t, h, h.post(t))
	})
	t.Run("parent group writable", func(t *testing.T) {
		hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
		h := startBrokerClaude(t, hook, "hook")
		if err := os.Chmod(filepath.Dir(hook), 0o775); err != nil {
			t.Fatal(err)
		}
		ran := h.post(t)
		if ran.status != "error" || !strings.Contains(ran.errText, "so the turn was refused") || !strings.Contains(ran.errText, "group or world writable") {
			t.Fatalf("run %s %q", ran.status, ran.errText)
		}
		if ran.argv != "" || ran.marker {
			t.Fatalf("claude started argv %q marker %v", ran.argv, ran.marker)
		}
	})
	t.Run("owner writable parent ok", func(t *testing.T) {
		hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
		h := startBrokerClaude(t, hook, "hook")
		if err := os.Chmod(filepath.Dir(hook), 0o700); err != nil {
			t.Fatal(err)
		}
		ran := h.post(t)
		if ran.status != "done" || ran.errText != "" || !strings.Contains(ran.argv, "--settings") {
			t.Fatalf("run %s %q argv %q", ran.status, ran.errText, ran.argv)
		}
	})
	t.Run("reload repins", func(t *testing.T) {
		hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
		h := startBrokerClaude(t, hook, "hook")
		if err := os.WriteFile(hook, []byte("#!/bin/sh\nexit 0\n# pinned again\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		h.app.editPol(func(p *policy.Policy) { p.HookPath = hook })
		ran := h.post(t)
		if ran.status != "done" || ran.errText != "" || !strings.Contains(ran.argv, "--settings") {
			t.Fatalf("run %s %q", ran.status, ran.errText)
		}
	})
	t.Run("deny list", func(t *testing.T) {
		hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
		h := startBrokerClaude(t, hook, "hook")
		ran := h.post(t)
		if ran.status != "done" || ran.errText != "" {
			t.Fatalf("run %s %s", ran.status, ran.errText)
		}
		body, err := os.ReadFile(settingsArg(t, ran.argv))
		if err != nil {
			t.Fatal(err)
		}
		assertBrokerSettings(t, body, hook)
	})
}

func assertIntegrityRefused(t *testing.T, h brokerHarness, ran brokerRun) {
	t.Helper()
	if ran.status != "error" || !strings.Contains(ran.errText, "permission broker hook changed since startup") || !strings.Contains(ran.errText, "so the turn was refused") {
		t.Fatalf("run %s %q", ran.status, ran.errText)
	}
	if ran.argv != "" || ran.marker {
		t.Fatalf("claude started argv %q marker %v", ran.argv, ran.marker)
	}
	audit, err := os.ReadFile(filepath.Join(h.app.cfg.DataDir, "permbroker", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), "permission broker hook changed since startup") {
		t.Fatalf("audit\n%s", audit)
	}
}

func assertBrokerSettings(t *testing.T, body []byte, hook string) {
	t.Helper()
	if strings.Contains(string(body), "disableAllHooks") {
		t.Fatalf("disableAllHooks\n%s", body)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	perms, _ := doc["permissions"].(map[string]any)
	if allow, ok := perms["allow"]; ok && allow != nil {
		if rows, ok := allow.([]any); ok && len(rows) > 0 {
			t.Fatalf("allow %v", allow)
		}
	}
	hooks, _ := doc["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Fatalf("PreToolUse %#v", hooks)
	}
	group, _ := pre[0].(map[string]any)
	if group["matcher"] != "*" {
		t.Fatalf("matcher %#v", group["matcher"])
	}
	list, _ := group["hooks"].([]any)
	if len(list) != 1 {
		t.Fatalf("hooks %#v", group)
	}
	entry, _ := list[0].(map[string]any)
	timeout, _ := entry["timeout"].(float64)
	if entry["type"] != "command" || entry["onFailure"] != "block" || timeout != 30 {
		t.Fatalf("entry %#v", entry)
	}
	text := string(body)
	for _, want := range []string{hook, "permbroker", "claude-settings.json"} {
		if !strings.Contains(text, want) {
			t.Fatalf("deny list missing %s\n%s", want, text)
		}
	}
	deny, _ := perms["deny"].([]any)
	sawRead, sawEdit := false, false
	for _, item := range deny {
		s, _ := item.(string)
		if strings.Contains(s, hook) && strings.HasPrefix(s, "Read(") {
			sawRead = true
		}
		if strings.Contains(s, hook) && strings.HasPrefix(s, "Edit(") {
			sawEdit = true
		}
	}
	if !sawRead || !sawEdit {
		t.Fatalf("hook deny rules %#v", deny)
	}
}

func TestFakeHookFailureRespectsOnFailure(t *testing.T) {
	dir := t.TempDir()
	with := filepath.Join(dir, "with.json")
	without := filepath.Join(dir, "without.json")
	if err := os.WriteFile(with, []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"true","onFailure":"block"}]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(without, []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"true"}]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	argsWith := []string{"--settings", with}
	argsWithout := []string{"--settings", without}
	if fakeHookPermits(argsWith, "Read", false, false) {
		t.Fatal("onFailure block ran Read")
	}
	if !fakeHookPermits(argsWithout, "Read", false, false) {
		t.Fatal("Read did not fall through")
	}
	if fakeHookPermits(argsWithout, "Bash", false, false) {
		t.Fatal("Bash fell through a locked launch")
	}
	if !fakeHookPermits(argsWith, "Read", false, true) {
		t.Fatal("explicit allow did not run")
	}
	if fakeHookPermits(argsWithout, "Read", true, false) {
		t.Fatal("blocking hook result ran Read")
	}
}

func TestBrokerResidualSource(t *testing.T) {
	t.Setenv("LGB_FAKE_RESIDUAL", "1")
	hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
	h := startBrokerClaude(t, hook, "hook")
	ran := h.post(t)
	if ran.status != "done" || ran.errText != "" {
		t.Fatalf("run %s %s", ran.status, ran.errText)
	}
	msgs, err := h.app.st.ListMessages(h.bot.ID, "user", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	var runID string
	for _, m := range msgs {
		if m.Role == "bot" && m.RunID != nil {
			runID = *m.RunID
		}
	}
	if runID == "" {
		t.Fatal("no run")
	}
	tools, err := h.app.st.RunTools([]string{runID})
	if err != nil {
		t.Fatal(err)
	}
	var saw bool
	for _, rec := range tools[runID] {
		if rec.Kind != "permission" {
			continue
		}
		if strings.Contains(rec.Result, `"source":"no_ui"`) {
			t.Fatalf("residual source no_ui: %s", rec.Result)
		}
		if strings.Contains(rec.Result, `"source":"broker"`) {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("no broker residual in %+v", tools[runID])
	}
}
