package clisession

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestExecRunnerDropsEnvAndHidesHost(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "fake-grok.sh")
	body := "#!/bin/sh\n" +
		"secret=missing\n" +
		"if [ -r " + shellQuote(secret) + " ]; then secret=visible; fi\n" +
		"printf '%s\\n' \"{\\\"type\\\":\\\"text\\\",\\\"data\\\":\\\"home=$HOME sock=$SSH_AUTH_SOCK key=$XAI_API_KEY aws=$AWS_SECRET_ACCESS_KEY secret=$secret\\\"}\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	t.Setenv("XAI_API_KEY", "supersecret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "cloudsecret")
	res, err := ExecRunner{}.Run(context.Background(), Spec{
		Backend: "grok", Bin: script, Fresh: true, SessionID: "abc123",
		Prompt: "ping", Workspace: dir,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "home=/lgb-home sock= key= aws= secret=missing"
	if runtime.GOOS == "darwin" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		home, err = filepath.Abs(home)
		if err != nil {
			t.Fatal(err)
		}
		want = "home=" + home + " sock= key= aws= secret=missing"
	}
	if res.Text != want {
		t.Fatalf("text %q", res.Text)
	}
}

func TestConfineArgsClearEnvAndKeepNet(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XAI_API_KEY", "supersecret")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	args, err := confineArgs(filepath.Join(dir, "missing"), nil, dir)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\x00")
	for _, bad := range []string{"--unshare-net", "--disable-userns", "supersecret", "SSH_AUTH_SOCK", "XAI_API_KEY"} {
		if strings.Contains(joined, bad) {
			t.Fatalf("args contain %s", bad)
		}
	}
	if !strings.Contains(joined, "--clearenv") {
		t.Fatal("missing --clearenv")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(args)-1; i++ {
		if args[i] != "--bind" && args[i] != "--ro-bind" {
			continue
		}
		src := args[i+1]
		if src == home || src == filepath.Join(home, ".ssh") {
			t.Fatalf("bound %s", src)
		}
	}
}

func TestConfineRejectsRootAndHome(t *testing.T) {
	if _, err := confineArgs("/bin/true", nil, "/"); err == nil {
		t.Fatal("accepted /")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := confineArgs("/bin/true", nil, home); err == nil {
		t.Fatal("accepted home")
	}
}

func TestExecRunnerRequiresBwrap(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	dir := t.TempDir()
	_, err := ExecRunner{}.Run(context.Background(), Spec{
		Backend: "grok", Bin: "/bin/true", Fresh: true, SessionID: "abc123",
		Prompt: "ping", Workspace: dir,
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "confinement unavailable") {
		t.Fatalf("err %v", err)
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
