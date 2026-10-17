package permission

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestUserAllowAutoAllowsOnlyLowRisk(t *testing.T) {
	ws := t.TempDir()
	rules := []UserRule{{ID: "rule-1", Effect: "allow", Pattern: "Bash(git status*)"}}
	var audited map[string]any
	b := New(Options{Audit: func(fields map[string]any) { audited = fields }})
	pol := policy.Permission{Mode: "default", UIPrompts: true, PromptTimeout: 20 * time.Millisecond}
	ok := b.Evaluate(context.Background(), pol, Request{
		ID: "1", RunID: "run", BotID: "bot", Tool: "Bash", Workspace: ws, UserRules: rules,
		Args: map[string]any{"command": "git status"},
	})
	if ok.Decision != Allow || ok.Source != "user" || ok.Rule != "Bash(git status*)" || ok.Behavior != "allow" {
		t.Fatalf("%+v", ok)
	}
	if audited["rule_id"] != "rule-1" || audited["classification"] != "read_only" || audited["risk"] != "low" {
		t.Fatalf("audit %#v", audited)
	}

	bad := b.Evaluate(context.Background(), pol, Request{
		ID: "2", RunID: "run", BotID: "bot", Tool: "Bash", Workspace: ws, UserRules: rules,
		Args: map[string]any{"command": "git status; rm -rf /tmp/x"},
	})
	if bad.Source == "user" || bad.Decision == Allow {
		t.Fatalf("composed command auto-allowed: %+v", bad)
	}
	if bad.Source != "timeout" {
		t.Fatalf("composed command was not asked: %+v", bad)
	}

	write := b.Evaluate(context.Background(), pol, Request{
		ID: "3", RunID: "run", BotID: "bot", Tool: "Bash", Workspace: ws, UserRules: rules,
		Args: map[string]any{"command": "git push origin"},
	})
	if write.Source == "user" || write.Decision == Allow {
		t.Fatalf("push auto-allowed: %+v", write)
	}
}

func TestUserRulePrecedence(t *testing.T) {
	ws := t.TempDir()
	allow := []UserRule{{ID: "a", Effect: "allow", Pattern: "Bash(git status*)"}}
	b := New(Options{})
	denied := b.Evaluate(context.Background(), policy.Permission{
		Mode: "bypassPermissions", Deny: []string{"Bash(git status*)"}, UIPrompts: true,
	}, Request{
		ID: "1", RunID: "run", BotID: "bot", Tool: "Bash", Workspace: ws, UserRules: allow,
		Args: map[string]any{"command": "git status"},
	})
	if denied.Source != "policy" || denied.Decision != Deny {
		t.Fatalf("managed deny lost: %+v", denied)
	}

	asked := b.Evaluate(context.Background(), policy.Permission{
		Mode: "bypassPermissions", Ask: []string{"Bash(git status*)"}, UIPrompts: false,
	}, Request{
		ID: "2", RunID: "run", BotID: "bot", Tool: "Bash", Workspace: ws, UserRules: allow,
		Args: map[string]any{"command": "git status -sb"},
	})
	if asked.Source != "no_ui" || asked.Decision != Deny || asked.Rule != "Bash(git status*)" {
		t.Fatalf("managed ask lost: %+v", asked)
	}

	userDeny := []UserRule{{ID: "d", Effect: "deny", Pattern: "Bash(*push*)"}}
	push := b.Evaluate(context.Background(), policy.Permission{Mode: "bypassPermissions", UIPrompts: true}, Request{
		ID: "3", RunID: "run", BotID: "bot", Tool: "Bash", Workspace: ws, UserRules: userDeny,
		Args: map[string]any{"command": "git push origin"},
	})
	if push.Source != "user" || push.Decision != Deny || push.Rule != "Bash(*push*)" {
		t.Fatalf("user deny did not beat bypass: %+v", push)
	}

	lsRule := []UserRule{{ID: "ls", Effect: "allow", Pattern: "Bash(ls *)"}}
	outside := b.Evaluate(context.Background(), policy.Permission{UIPrompts: false}, Request{
		ID: "4", RunID: "run", BotID: "bot", Tool: "Bash", Workspace: ws, UserRules: lsRule,
		Args: map[string]any{"command": "ls /etc"},
	})
	if outside.Source == "user" || outside.Decision == Allow {
		t.Fatalf("ls /etc auto-allowed: %+v", outside)
	}
	dir := filepath.Join(ws, "src")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := b.Evaluate(context.Background(), policy.Permission{UIPrompts: false}, Request{
		ID: "5", RunID: "run", BotID: "bot", Tool: "Bash", Workspace: ws, UserRules: lsRule,
		Args: map[string]any{"command": "ls -- " + dir},
	})
	if inside.Decision != Allow || inside.Source != "user" {
		t.Fatalf("ls inside workspace: %+v", inside)
	}
}

func TestNativeRulesFiles(t *testing.T) {
	dir := t.TempDir()
	if err := WriteNativeRules(dir, []NativeRule{
		{Effect: "allow", Pattern: "Bash(gh pr view *)"},
		{Effect: "deny", Pattern: "Bash(*push*)"},
		{Effect: "ask", Pattern: "Bash(git commit *)"},
	}); err != nil {
		t.Fatal(err)
	}
	jsonBody := mustRead(t, filepath.Join(dir, "user-permissions.json"))
	grokBody := mustRead(t, filepath.Join(dir, "grok-permission-rules"))
	for _, s := range []string{`"Bash(gh pr view *)"`, `"Bash(*push*)"`, `"Bash(git commit *)"`} {
		if !strings.Contains(jsonBody, s) {
			t.Fatalf("json missing %s in %s", s, jsonBody)
		}
	}
	if !strings.Contains(grokBody, "allow Bash(gh pr view *)") || !strings.Contains(grokBody, "deny Bash(*push*)") || !strings.Contains(grokBody, "# ask Bash(git commit *)") {
		t.Fatalf("grok file %s", grokBody)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNativeRulesAreRegularFiles(t *testing.T) {
	dir := t.TempDir()
	rules := []NativeRule{{Effect: "allow", Pattern: "Bash(git status*)"}}
	if err := WriteNativeRules(filepath.Join(dir, "cli", "bot"), rules); err != nil {
		t.Fatal(err)
	}
	if err := WriteNativeRules(filepath.Join(dir, "cli", "bot"), []NativeRule{{Effect: "deny", Pattern: "Bash(*push*)"}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"user-permissions.json", "grok-permission-rules"} {
		path := filepath.Join(dir, "cli", "bot", name)
		st, err := os.Lstat(path)
		if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v %v", name, st, err)
		}
	}
	body := mustRead(t, filepath.Join(dir, "cli", "bot", "user-permissions.json"))
	if strings.Contains(body, "git status") || !strings.Contains(body, `Bash(*push*)`) {
		t.Fatalf("rewrite did not replace the file: %s", body)
	}
}

func TestNativeRulesRefuseSymlinkParents(t *testing.T) {
	rules := []NativeRule{{Effect: "allow", Pattern: "Bash(git status*)"}}
	canaryBody := []byte("keep-canary\n")
	check := func(t *testing.T, canary string) {
		t.Helper()
		got, err := os.ReadFile(canary)
		if err != nil || string(got) != string(canaryBody) {
			t.Fatalf("canary changed: %q %v", got, err)
		}
	}
	t.Run("cli", func(t *testing.T) {
		data := t.TempDir()
		outside := t.TempDir()
		if err := os.MkdirAll(filepath.Join(outside, "bot"), 0o700); err != nil {
			t.Fatal(err)
		}
		canary := filepath.Join(outside, "bot", "user-permissions.json")
		if err := os.WriteFile(canary, canaryBody, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(data, "cli")); err != nil {
			t.Fatal(err)
		}
		err := WriteNativeRules(filepath.Join(data, "cli", "bot"), rules)
		if !errors.Is(err, clisession.ErrCredSymlink) {
			t.Fatalf("err %v", err)
		}
		check(t, canary)
	})
	t.Run("bot", func(t *testing.T) {
		data := t.TempDir()
		outside := t.TempDir()
		canary := filepath.Join(outside, "grok-permission-rules")
		if err := os.WriteFile(canary, canaryBody, 0o600); err != nil {
			t.Fatal(err)
		}
		bot := filepath.Join(data, "cli", "bot")
		if err := os.MkdirAll(filepath.Dir(bot), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, bot); err != nil {
			t.Fatal(err)
		}
		err := WriteNativeRules(bot, rules)
		if !errors.Is(err, clisession.ErrCredSymlink) {
			t.Fatalf("err %v", err)
		}
		check(t, canary)
	})
	t.Run("file", func(t *testing.T) {
		data := t.TempDir()
		outside := t.TempDir()
		canary := filepath.Join(outside, "secret")
		if err := os.WriteFile(canary, canaryBody, 0o600); err != nil {
			t.Fatal(err)
		}
		bot := filepath.Join(data, "cli", "bot")
		if err := os.MkdirAll(bot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(canary, filepath.Join(bot, "user-permissions.json")); err != nil {
			t.Fatal(err)
		}
		err := WriteNativeRules(bot, rules)
		if !errors.Is(err, clisession.ErrCredSymlink) {
			t.Fatalf("err %v", err)
		}
		check(t, canary)
		if _, err := os.Lstat(filepath.Join(bot, "grok-permission-rules")); !os.IsNotExist(err) {
			t.Fatalf("wrote the second file after a symlink refusal: %v", err)
		}
	})
}
