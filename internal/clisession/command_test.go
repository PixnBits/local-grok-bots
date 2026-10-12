package clisession

import (
	"strings"
	"testing"
)

func TestGrokResumeFlags(t *testing.T) {
	argv, err := Args(Spec{
		Backend: "grok", SessionID: "sess-1", Fresh: false,
		Prompt: "hello", Workspace: "/work/shared", Model: "grok-4",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(argv, "\n")
	want := []string{
		"grok",
		"-m", "grok-4",
		"--resume", "sess-1",
		"-p", "hello",
		"--sandbox", "workspace",
		"--cwd", "/work/shared",
		"--output-format", "streaming-json",
		"--always-approve",
		"--no-auto-update",
	}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv:\n%s", got)
	}
}

func TestGrokFreshSessionUsesSessionID(t *testing.T) {
	argv, err := Args(Spec{
		Backend: "grok", SessionID: "new-1", Fresh: true,
		Prompt: "hi", Workspace: "/work",
	})
	if err != nil {
		t.Fatal(err)
	}
	if argv[1] != "--session-id" || argv[2] != "new-1" {
		t.Fatalf("argv %q", argv)
	}
	for _, a := range argv {
		if a == "--resume" {
			t.Fatal("fresh turn must not pass --resume")
		}
	}
}

func TestClaudeStub(t *testing.T) {
	_, err := Args(Spec{Backend: "claude", Prompt: "hi"})
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("err %v", err)
	}
}
