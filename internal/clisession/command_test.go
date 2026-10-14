package clisession

import (
	"strings"
	"testing"
)

func TestFreshSessionDoesNotResume(t *testing.T) {
	args, err := Args(Spec{Backend: "claude", SessionID: "11111111-1111-4111-8111-111111111111", Fresh: true, Prompt: "hi", Workspace: "/work"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\n")
	if !strings.Contains(joined, "--session-id\n11111111-1111-4111-8111-111111111111") {
		t.Fatalf("args %v", args)
	}
	if strings.Contains(joined, "--resume") || strings.Contains(joined, "bypassPermissions") || strings.Contains(joined, "--permission-mode") {
		t.Fatalf("fresh turn invented a permission mode: %v", args)
	}
	if !strings.Contains(joined, "--output-format\nstream-json") {
		t.Fatalf("format %v", args)
	}
}

func TestResumeAndExplicitPermission(t *testing.T) {
	args, err := Args(Spec{
		Backend: "claude", SessionID: "abc", Fresh: false, Prompt: "[scheduled] tick",
		Workspace: "/work", PermissionMode: "bypassPermissions", Model: "opus",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\n")
	if strings.Contains(joined, "--session-id") || !strings.Contains(joined, "--resume\nabc") {
		t.Fatalf("resume args %v", args)
	}
	if !strings.Contains(joined, "--permission-mode\nbypassPermissions") {
		t.Fatalf("permission %v", args)
	}
	if !strings.Contains(joined, "--model\nopus") {
		t.Fatalf("model %v", args)
	}
}

func TestGrokDoesNotAlwaysApproveUnlessPolicySaysSo(t *testing.T) {
	plain, err := Args(Spec{Backend: "grok", SessionID: "s", Fresh: true, Prompt: "hi", Workspace: "/w"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(plain, " "), "--always-approve") {
		t.Fatalf("default grok approved itself: %v", plain)
	}
	if !strings.Contains(strings.Join(plain, "\n"), "--output-format\nstreaming-json") {
		t.Fatalf("format %v", plain)
	}
	allow, err := Args(Spec{Backend: "grok", SessionID: "s", Fresh: false, Prompt: "hi", Workspace: "/w", PermissionMode: "always-allow"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(allow, "\n")
	if !strings.Contains(joined, "--always-approve") || !strings.Contains(joined, "--resume\ns") {
		t.Fatalf("allow args %v", allow)
	}
	if strings.Contains(joined, "--permission-mode") {
		t.Fatalf("bypass mode was also passed as --permission-mode: %v", allow)
	}
}

func TestPermissionRulesArePassedThrough(t *testing.T) {
	grok, err := Args(Spec{
		Backend: "grok", Prompt: "hi", Workspace: "/w", PermissionMode: "ask",
		AllowRules: []string{"Bash(git status*)"}, DenyRules: []string{"Bash(rm *)"},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(grok, "\n")
	if !strings.Contains(joined, "--allow\nBash(git status*)") || !strings.Contains(joined, "--deny\nBash(rm *)") {
		t.Fatalf("grok rules %v", grok)
	}
	if strings.Contains(joined, "--always-approve") || !strings.Contains(joined, "--permission-mode\nask") {
		t.Fatalf("grok mode %v", grok)
	}
	claude, err := Args(Spec{
		Backend: "claude", Prompt: "hi", Workspace: "/w", PermissionMode: "default",
		AllowRules: []string{"Read"}, DenyRules: []string{"Bash(rm *)"},
		MCPConfig: `{"mcpServers":{"lgbperm":{"type":"http","url":"http://127.0.0.1:9/api/mcp/permission/abc"}}}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(claude, "\n")
	if !strings.Contains(joined, "--allowedTools\nRead") || !strings.Contains(joined, "--disallowedTools\nBash(rm *)") {
		t.Fatalf("claude rules %v", claude)
	}
	if !strings.Contains(joined, "--permission-mode\ndefault") || !strings.Contains(joined, "--permission-prompt-tool\nmcp__lgbperm__approve") {
		t.Fatalf("claude prompt tool %v", claude)
	}
	if !strings.Contains(joined, "--mcp-config\n{\"mcpServers\"") {
		t.Fatalf("mcp config %v", claude)
	}
}
