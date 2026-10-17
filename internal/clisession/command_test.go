package clisession

import (
	"context"
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

func grokSpec(spec Spec) Spec {
	if spec.Isolate == nil {
		spec.Isolate = &Isolation{GrokSandbox: GrokProfile}
	}
	return spec
}

func TestGrokACPArgvDoesNotApproveItself(t *testing.T) {
	plain, err := Args(grokSpec(Spec{
		Backend: "grok", SessionID: "s", Fresh: true, Prompt: "hi", Workspace: "/w", Model: "m",
		AllowRules: []string{"Bash(git status*)", "Bash(lgb)", "Bash(lgb *)"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(plain, "\n")
	for _, want := range []string{"-m\nm", "agent\n--no-leader\nstdio", "--sandbox\n" + GrokProfile, "--cwd\n/w", "--no-auto-update", "--allow\nBash(lgb)", "--allow\nBash(lgb *)"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %v", want, plain)
		}
	}
	for _, bad := range []string{"--always-approve", "--permission-mode", "--output-format", "streaming-json", "--session-id", "--resume", "\n-p\n", "\nhi\n", "Bash(git status*)", "yoloMode"} {
		if strings.Contains(joined, bad) {
			t.Fatalf("argv has %q: %v", bad, plain)
		}
	}
	bypass, err := Args(grokSpec(Spec{Backend: "grok", SessionID: "s", Fresh: false, Prompt: "hi", Workspace: "/w", PermissionMode: "always-allow"}))
	if err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(bypass, "\n")
	if strings.Contains(joined, "--always-approve") || strings.Contains(joined, "--permission-mode") || strings.Contains(joined, "--resume") || strings.Contains(joined, "--session-id") {
		t.Fatalf("bypass argv %v", bypass)
	}
}

func TestPermissionRulesArePassedThrough(t *testing.T) {
	grok, err := Args(grokSpec(Spec{
		Backend: "grok", Prompt: "hi", Workspace: "/w", PermissionMode: "ask",
		AllowRules: []string{"Bash(git status*)"}, DenyRules: []string{"Bash(rm *)"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(grok, "\n")
	if strings.Contains(joined, "--allow\nBash(git status*)") || !strings.Contains(joined, "--deny\nBash(rm *)") {
		t.Fatalf("grok rules %v", grok)
	}
	if strings.Contains(joined, "--always-approve") || strings.Contains(joined, "--permission-mode") {
		t.Fatalf("grok mode %v", grok)
	}
	if !strings.Contains(joined, "agent\n--no-leader\nstdio") {
		t.Fatalf("grok argv %v", grok)
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

func TestGrokBuiltinSandboxRefuses(t *testing.T) {
	for _, name := range []string{"", "workspace", "strict", "off", "devbox", "read-only"} {
		spec := Spec{Backend: "grok", Prompt: "hi", Workspace: t.TempDir()}
		if name != "" {
			spec.Isolate = &Isolation{GrokSandbox: name}
		}
		args, err := Args(spec)
		if err == nil || !strings.Contains(err.Error(), "unenforced") || !strings.Contains(err.Error(), "refused") {
			t.Fatalf("profile %q: args %v err %v", name, args, err)
		}
		if strings.Contains(strings.Join(args, " "), "--sandbox") {
			t.Fatalf("profile %q still launched: %v", name, args)
		}
	}
	args, err := Args(Spec{Backend: "grok", Prompt: "hi", Workspace: t.TempDir(), Isolate: &Isolation{GrokSandbox: GrokProfile}})
	if err != nil || !strings.Contains(strings.Join(args, " "), "--sandbox "+GrokProfile) {
		t.Fatalf("custom profile: %v %v", args, err)
	}
	_, err = (ExecRunner{HasTTY: func() bool { return false }}).Run(context.Background(), Spec{
		Backend: "grok", Prompt: "hi", Workspace: t.TempDir(),
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "unenforced") {
		t.Fatalf("runner started a built-in sandbox: %v", err)
	}
}

func TestClaudePromptsNoneSkipsThePromptTool(t *testing.T) {
	args, err := Args(Spec{
		Backend: "claude", Prompt: "hi", Workspace: "/w",
		PermissionPrompts: "none",
		MCPConfig:         `{"mcpServers":{"lgbperm":{"type":"http","url":"http://127.0.0.1:9/t"}}}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\n")
	if !strings.Contains(joined, "--permission-prompts\nnone") {
		t.Fatalf("flag %v", args)
	}
	if strings.Contains(joined, "--permission-prompt-tool") || strings.Contains(joined, "--mcp-config") {
		t.Fatalf("none still attached a host: %v", args)
	}
}

func TestClaudeStreamControlArgv(t *testing.T) {
	args, err := Args(Spec{
		Backend: "claude", SessionID: "abc", Fresh: false, Prompt: "secret prompt",
		Workspace: "/w", Model: "opus", PermissionMode: "default",
		AllowRules: []string{"Read"}, DenyRules: []string{"Bash(rm *)"},
		StreamControl:     true,
		PermissionPrompts: "none",
		MCPConfig:         `{"mcpServers":{"lgbperm":{"type":"http","url":"http://127.0.0.1:9/t"}}}`,
		PermissionTool:    "mcp__lgbperm__approve",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"claude",
		"--model", "opus",
		"--resume", "abc",
		"--input-format", "stream-json",
		"--output-format", "stream-json",
		"--verbose",
		"--permission-prompt-tool", "stdio",
		"--permission-mode", "default",
		"--allowedTools", "Read",
		"--disallowedTools", "Bash(rm *)",
	}
	if strings.Join(args, "\n") != strings.Join(want, "\n") {
		t.Fatalf("argv\n%s", strings.Join(args, "\n"))
	}
	fresh, err := Args(Spec{
		Backend: "claude", SessionID: "11111111-1111-4111-8111-111111111111", Fresh: true,
		Prompt: "hi", Workspace: "/w", StreamControl: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(fresh, "\n")
	if !strings.Contains(joined, "--session-id\n11111111-1111-4111-8111-111111111111") {
		t.Fatalf("fresh %v", fresh)
	}
	if strings.Contains(joined, "\n-p\n") || strings.Contains(joined, "--mcp-config") || strings.Contains(joined, "--include-partial-messages") || strings.Contains(joined, "hi") {
		t.Fatalf("stream control still looks like a print turn: %v", fresh)
	}
}
