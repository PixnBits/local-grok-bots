package clisession

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestExecRunnerCapturesStream(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-grok.sh")
	body := "#!/bin/sh\nprintf '%s\\n' '{\"type\":\"text\",\"data\":\"Hi\"}' '{\"type\":\"end\",\"stopReason\":\"end_turn\",\"sessionId\":\"abc123\"}'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	var tokens string
	res, err := ExecRunner{}.Run(context.Background(), Spec{
		Backend: "grok", Bin: script, Fresh: true, SessionID: "abc123",
		Prompt: "ping", Workspace: dir,
	}, func(ev Event) {
		if ev.Kind == "token" {
			tokens += ev.Text
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Text != "Hi" || res.SessionID != "abc123" || tokens != "Hi" {
		t.Fatalf("res %+v tokens %q", res, tokens)
	}
}
