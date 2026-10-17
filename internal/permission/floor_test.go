package permission

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

// TestUserAllowFloor checks that a stored allow, even one that matches the
// call, cannot auto-allow composition, redirects, network commands, credential
// paths, writes, or paths outside the workspace.
func TestUserAllowFloor(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()
	data := filepath.Join(filepath.Dir(ws), "state.db")
	b := New(Options{})
	pol := policy.Permission{UIPrompts: false}

	eval := func(tool, pattern, text string) Outcome {
		t.Helper()
		args := map[string]any{"command": text}
		if tool != "Bash" {
			args = map[string]any{"file_path": text}
		}
		return b.Evaluate(context.Background(), pol, Request{
			ID: "1", RunID: "run", BotID: "bot", Tool: tool, Workspace: ws,
			UserRules: []UserRule{{ID: "r", Effect: "allow", Pattern: pattern}},
			Args:      args,
		})
	}
	mustAllow := func(tool, pattern, text string) {
		t.Helper()
		out := eval(tool, pattern, text)
		if out.Decision != Allow || out.Source != "user" || out.Rule != pattern {
			t.Fatalf("%s %q allowed as %+v", tool, text, out)
		}
		if !ClassifyCall(tool, map[string]any{"command": text, "file_path": text}, ws).AutoAllow {
			t.Fatalf("%s %q classified closed", tool, text)
		}
	}
	mustHold := func(tool, pattern, text string) {
		t.Helper()
		if ClassifyCall(tool, map[string]any{"command": text, "file_path": text}, ws).AutoAllow {
			t.Fatalf("%s %q classified as auto-allow", tool, text)
		}
		out := eval(tool, pattern, text)
		if out.Decision == Allow || out.Source == "user" {
			t.Fatalf("%s %q auto-allowed: %+v", tool, text, out)
		}
		if out.Source != "no_ui" || out.Decision != Deny {
			t.Fatalf("%s %q floor %+v", tool, text, out)
		}
	}

	mustAllow("Bash", "Bash(git status*)", "git status")
	mustAllow("Bash", "Bash(git status*)", "git status -sb")
	mustAllow("Bash", "Bash(git diff *)", "git diff -- src/a.go")
	mustAllow("Read", "Read(./src/**)", "./src/main.go")

	for _, cmd := range []string{
		"git status; rm x",
		"git status && rm x",
		"git status || true",
		"git status | cat",
		"git status $(id)",
		"git status `id`",
		"git status > /etc/x",
		"git status >> /etc/x",
		"git status < /etc/x",
		"git status 2> /etc/x",
		"git status > notes.txt",
	} {
		mustHold("Bash", "Bash(git status*)", cmd)
	}
	mustHold("Bash", "Bash(git status\nrm *)", "git status\nrm x")
	for _, cmd := range []string{
		"curl https://example.com",
		"wget https://example.com",
		"nc example.com 22",
		"ncat example.com 22",
		"ssh host",
		"scp a host:b",
		"sftp host",
		"socat STDIO TCP:example.com:22",
		"npm install",
		"docker ps",
		"rsync a b",
	} {
		mustHold("Bash", "Bash(*)", cmd)
	}
	for _, cmd := range []string{
		"touch notes.txt",
		"rm notes.txt",
		"tee notes.txt",
		"mv a b",
		"cp a b",
		"chmod 644 notes.txt",
		"sed -i s/a/b/ notes.txt",
	} {
		mustHold("Bash", "Bash(*)", cmd)
	}
	for _, cmd := range []string{
		"cat ~/.ssh/id_rsa",
		"cat ~/.grok/auth.json",
		"cat ~/.grok/config",
		"cat .env",
		"cat " + filepath.Join(ws, ".env"),
		"cat " + filepath.Join(ws, "auth.json"),
		"cat " + filepath.Join(ws, "state.db"),
		"cat " + filepath.Join(ws, "state.db-wal"),
		"cat " + filepath.Join(ws, ".grok", "settings"),
		"cat " + filepath.Join(ws, "user-permissions.json"),
		"cat " + filepath.Join(ws, "grok-permission-rules"),
		"cat " + data,
	} {
		mustHold("Bash", "Bash(cat *)", cmd)
	}
	mustHold("Bash", "Bash(ls *)", "ls /etc")
	mustHold("Bash", "Bash(ls *)", "ls "+outside)
	mustHold("Bash", "Bash(git diff *)", "git diff --output=/etc/x")
	mustHold("Bash", "Bash(git diff *)", "git diff --output=notes.txt")
	mustHold("Bash", "Bash(git diff *)", "git diff --output notes.txt")
	mustHold("Edit", "Edit(**)", "src/main.go")
	mustHold("Read", "Read(**)", "/etc/passwd")
	mustHold("Read", "Read(**)", "~/.ssh/id_rsa")
	mustHold("Read", "Read(**)", filepath.Join(ws, ".grok", "config"))
}

func TestUserRuleOrder(t *testing.T) {
	ws := t.TempDir()
	b := New(Options{})
	allow := []UserRule{{ID: "a", Effect: "allow", Pattern: "Bash(git status*)"}}
	req := Request{
		ID: "1", RunID: "run", BotID: "bot", Tool: "Bash", Workspace: ws,
		Args: map[string]any{"command": "git status"},
	}

	bypass := b.Evaluate(context.Background(), policy.Permission{
		Mode: "bypassPermissions", UIPrompts: true,
	}, withRules(req, allow))
	if bypass.Source != "policy" || bypass.Decision != Allow || bypass.Rule != "bypassPermissions" {
		t.Fatalf("bypass lost to user allow: %+v", bypass)
	}

	denied := b.Evaluate(context.Background(), policy.Permission{
		Allow: []string{"Bash(git status*)"}, UIPrompts: true,
	}, withRules(req, []UserRule{{ID: "d", Effect: "deny", Pattern: "Bash(git status*)"}}))
	if denied.Source != "user" || denied.Decision != Deny || denied.Rule != "Bash(git status*)" {
		t.Fatalf("user deny lost to managed allow: %+v", denied)
	}

	ask := []UserRule{{ID: "q", Effect: "ask", Pattern: "Bash(git status*)"}}
	asked := b.Evaluate(context.Background(), policy.Permission{
		Allow: []string{"Bash(git status*)"}, UIPrompts: false,
	}, withRules(req, ask))
	if asked.Source != "no_ui" || asked.Decision != Deny || asked.Rule != "Bash(git status*)" {
		t.Fatalf("user ask lost to managed allow: %+v", asked)
	}
	overBypass := b.Evaluate(context.Background(), policy.Permission{
		Mode: "bypassPermissions", UIPrompts: false,
	}, withRules(req, ask))
	if overBypass.Source != "no_ui" || overBypass.Decision != Deny || overBypass.Rule != "Bash(git status*)" {
		t.Fatalf("user ask lost to bypass: %+v", overBypass)
	}
}

func withRules(req Request, rules []UserRule) Request {
	req.UserRules = rules
	return req
}
