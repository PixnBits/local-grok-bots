package clisession

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestExecRunnerPrefersFinalText(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-grok.sh")
	body := "#!/bin/sh\nprintf '%s\\n' '{\"type\":\"text\",\"data\":\"Hel\"}' '{\"type\":\"text\",\"data\":\"lo\"}' '{\"type\":\"end\",\"text\":\"Hello!\",\"stopReason\":\"end_turn\",\"sessionId\":\"abc123\"}'\n"
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
	if res.Text != "Hello!" || tokens != "Hello" {
		t.Fatalf("res %+v tokens %q", res, tokens)
	}
}

func TestExecRunnerCancelKillsProcess(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-grok.sh")
	body := "#!/bin/sh\nsleep 30\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	var err error
	start := time.Now()
	go func() {
		_, err = ExecRunner{}.Run(ctx, Spec{
			Backend: "grok", Bin: script, Fresh: true, SessionID: "abc123",
			Prompt: "ping", Workspace: dir,
		}, nil)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("process still running")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("cancel was slow")
	}
	if err == nil {
		t.Fatal("expected cancel error")
	}
}
