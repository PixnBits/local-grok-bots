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
}
