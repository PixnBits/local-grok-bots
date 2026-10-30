package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/permbroker"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestGolden_JailMountsClaudeDeny(t *testing.T) {
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
	text := string(body)
	data := h.app.cfg.DataDir
	for _, want := range []string{
		hook,
		filepath.Join(data, "permbroker"),
		filepath.Join(data, "admin-token"),
		"claude-settings.json",
		"/launch/",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("deny list missing %s\n%s", want, text)
		}
	}
}

func TestGolden_HookRepinOnlyByAdmin(t *testing.T) {
	hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
	h := startBrokerClaude(t, hook, "hook")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nexit 0\n# swapped\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.app.editPol(func(p *policy.Policy) { p.HookPath = hook })
	ran := h.post(t)
	if ran.status != "error" || !strings.Contains(ran.errText, "hook changed") || strings.Contains(ran.argv, "-p") {
		t.Fatalf("publish %s %q argv %q", ran.status, ran.errText, ran.argv)
	}
	audit, err := os.ReadFile(filepath.Join(h.app.cfg.DataDir, "permbroker", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), "hook changed; re-pin required") {
		t.Fatalf("audit\n%s", audit)
	}
	const token = "lgbr_admintesttokenvalue"
	h.app.cfg.AuthToken = token
	res, body := do(t, "POST", h.srv.URL+"/api/permbroker/hook/repin", map[string]any{}, "")
	if res.StatusCode != 401 {
		t.Fatalf("open repin %d %s", res.StatusCode, body)
	}
	h.app.noteRunToken("lgbr_testtokenvalue", h.bot.ID, "run")
	res, body = do(t, "POST", h.srv.URL+"/api/permbroker/hook/repin", map[string]any{}, "lgbr_testtokenvalue")
	if res.StatusCode != 403 {
		t.Fatalf("run token %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", h.srv.URL+"/api/permbroker/hook/repin", map[string]any{}, token)
	if res.StatusCode != 200 {
		t.Fatalf("admin repin %d %s", res.StatusCode, body)
	}
	h.app.cfg.AuthToken = ""
	again := h.post(t)
	if again.status != "done" || again.errText != "" || !strings.Contains(again.argv, "--settings") {
		t.Fatalf("after repin %s %q argv %q", again.status, again.errText, again.argv)
	}
}

func TestGolden_HookSwappedMidTurnRefused(t *testing.T) {
	t.Run("evaluate", func(t *testing.T) {
		hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
		h := startBrokerClaude(t, hook, "hook")
		raw, err := json.Marshal(map[string]string{"command": "echo hi"})
		if err != nil {
			t.Fatal(err)
		}
		req := permbroker.Request{
			BotID: h.bot.ID, SessionID: "s-hook", Cwd: h.app.ws,
			ToolName: "Bash", ToolInput: raw,
		}
		first := h.app.broker.Evaluate(context.Background(), req)
		if first.Reason == "hook changed" {
			t.Fatalf("clean %+v", first)
		}
		if err := os.WriteFile(hook, []byte("#!/bin/sh\nexit 9\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		second := h.app.broker.Evaluate(context.Background(), req)
		if second.Verdict != permbroker.VerdictDeny || second.Reason != "hook changed" || second.PendingID != "" {
			t.Fatalf("evaluate %+v", second)
		}
	})
	t.Run("stream", func(t *testing.T) {
		hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
		dir := t.TempDir()
		between := filepath.Join(dir, "between")
		gate := filepath.Join(dir, "gate")
		t.Setenv("LGB_FAKE_TWO_TOOLS", "1")
		t.Setenv("LGB_FAKE_BETWEEN", between)
		t.Setenv("LGB_FAKE_SECOND_GATE", gate)
		h := startBrokerClaude(t, hook, "hook")
		done := make(chan brokerRun, 1)
		go func() { done <- h.post(t) }()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(between); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if _, err := os.Stat(between); err != nil {
			t.Fatal("first tool did not start")
		}
		seen := false
		for time.Now().Before(deadline) {
			ev, lerr := h.app.st.ListLog(h.bot.ID, "", "", 50)
			if lerr == nil {
				for _, e := range ev {
					if e.Kind == "tool_start" {
						seen = true
					}
				}
			}
			if seen {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !seen {
			t.Fatal("tool_start was not logged")
		}
		if err := os.WriteFile(hook, []byte("#!/bin/sh\nexit 9\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(gate, []byte("go\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		select {
		case ran := <-done:
			if ran.status != "error" || !strings.Contains(ran.errText, "hook changed") {
				t.Fatalf("run %s %q", ran.status, ran.errText)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("turn did not end")
		}
		if err := os.WriteFile(h.argvPath, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		next := h.post(t)
		if next.status != "error" || !strings.Contains(next.errText, "hook changed") || strings.Contains(next.argv, "-p") {
			t.Fatalf("later launch %s %q argv %q", next.status, next.errText, next.argv)
		}
	})
}

func TestGolden_LaunchUsesCheckedClaudePath(t *testing.T) {
	hook := writeHookScript(t, "#!/bin/sh\nexit 0\n")
	h := startBrokerClaude(t, hook, "hook")
	checked := filepath.Join(h.app.cfg.DataDir, "bin", "claude")
	decoyDir := filepath.Join(h.app.cfg.DataDir, "decoy")
	if err := os.MkdirAll(decoyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	argv0 := filepath.Join(h.app.cfg.DataDir, "argv0.log")
	decoy := "#!/bin/sh\n" +
		"if [ -n \"$LGB_ARGV0_LOG\" ]; then printf '%s\\n' \"$0\" >> \"$LGB_ARGV0_LOG\"; fi\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(decoyDir, "claude"), []byte(decoy), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LGB_ARGV0_LOG", argv0)
	afterClaudePathCheck = func(iso *clisession.Isolation) {
		if iso == nil {
			return
		}
		env := make([]string, 0, len(iso.Env))
		for _, kv := range iso.Env {
			if strings.HasPrefix(kv, "PATH=") {
				continue
			}
			env = append(env, kv)
		}
		iso.Env = append(env, "PATH="+decoyDir)
	}
	t.Cleanup(func() { afterClaudePathCheck = nil })
	ran := h.post(t)
	if ran.status != "done" || !strings.Contains(ran.argv, "-p") {
		t.Fatalf("run %s %q argv %q", ran.status, ran.errText, ran.argv)
	}
	body, err := os.ReadFile(argv0)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, checked) || strings.Contains(text, decoyDir) {
		t.Fatalf("argv0\n%s", text)
	}
}
