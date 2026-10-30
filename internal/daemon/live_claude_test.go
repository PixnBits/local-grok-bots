package daemon

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/permbroker"
)

// TestLiveClaudeHookFailureBlocksRead is opt-in. It skips unless
// LGB_LIVE_CLAUDE_BIN is an absolute Claude binary.
func TestLiveClaudeHookFailureBlocksRead(t *testing.T) {
	bin := os.Getenv("LGB_LIVE_CLAUDE_BIN")
	if bin == "" || !filepath.IsAbs(bin) {
		t.Skip("LGB_LIVE_CLAUDE_BIN is not an absolute claude path")
	}
	canary := "lgb-canary-" + strings.ReplaceAll(t.Name(), "/", "-")
	ws := t.TempDir()
	target := filepath.Join(ws, "notes.txt")
	if err := os.WriteFile(target, []byte(canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prompt := "Read the file " + target + " and include its exact contents in your reply."
	run := func(name, mode string, strip bool) string {
		t.Helper()
		script := filepath.Join(t.TempDir(), "hook.sh")
		body := "#!/bin/sh\n"
		switch mode {
		case "kill":
			body += "kill -9 $$\n"
		case "slow":
			body += "sleep 40\n"
		}
		body += "printf '%s\\n' '{\"hookSpecificOutput\":{\"permissionDecision\":\"allow\"}}'\nexit 0\n"
		if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		iso, err := clisession.PrepareIsolation(clisession.IsolationOptions{
			Backend:         "claude",
			StateDir:        filepath.Join(dir, "state"),
			Workspace:       ws,
			UserHome:        filepath.Join(dir, "home"),
			Base:            []string{"PATH=" + os.Getenv("PATH")},
			PermHookCommand: permbroker.HookCommand(script, filepath.Join(dir, "sock")),
		})
		if err != nil {
			t.Fatal(err)
		}
		if strip {
			stripHookOnFailure(t, iso.SettingsPath)
		} else {
			body, err := os.ReadFile(iso.SettingsPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), `"onFailure": "block"`) || !strings.Contains(string(body), `"timeout": 30`) {
				t.Fatalf("settings\n%s", body)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		args := []string{
			"-p", prompt,
			"--output-format", "stream-json",
			"--verbose",
			"--setting-sources=",
			"--settings", iso.SettingsPath,
			"--tools", "Read",
		}
		if model := strings.TrimSpace(os.Getenv("LGB_LIVE_CLAUDE_MODEL")); model != "" {
			args = append(args, "--model", model)
		}
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = ws
		cmd.Env = liveClaudeEnv(filepath.Join(dir, "live-home"))
		out, _ := cmd.CombinedOutput()
		if evidence := os.Getenv("LGB_LIVE_CLAUDE_EVIDENCE"); evidence != "" {
			if err := os.MkdirAll(evidence, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(evidence, name+".jsonl"), out, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return string(out)
	}
	killOut := run("kill", "kill", false)
	if strings.Contains(killOut, canary) || !liveBlocked(killOut) {
		t.Fatalf("kill case did not block\n%s", killOut)
	}
	slowOut := run("slow", "slow", false)
	if strings.Contains(slowOut, canary) || !liveBlocked(slowOut) {
		t.Fatalf("slow case did not block\n%s", slowOut)
	}
	control := run("control", "kill", true)
	if !strings.Contains(control, canary) {
		t.Fatalf("control did not read the file\n%s", control)
	}
}

func stripHookOnFailure(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	hooks, _ := doc["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	group, _ := pre[0].(map[string]any)
	list, _ := group["hooks"].([]any)
	entry, _ := list[0].(map[string]any)
	if entry["timeout"].(float64) != 30 {
		t.Fatalf("timeout %#v", entry["timeout"])
	}
	delete(entry, "onFailure")
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func liveClaudeEnv(home string) []string {
	if err := os.MkdirAll(home, 0o700); err != nil {
		return []string{"HOME=" + home}
	}
	env := []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	for _, pair := range strings.Split(os.Getenv("LGB_LIVE_CLAUDE_ENV"), ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" || !strings.Contains(pair, "=") {
			continue
		}
		env = append(env, pair)
	}
	return env
}

func liveBlocked(out string) bool {
	if strings.Contains(out, "permission_denial") || strings.Contains(out, `"is_error":true`) || strings.Contains(out, `"is_error": true`) {
		return true
	}
	return strings.Contains(out, "blocked") && strings.Contains(out, "permission")
}
