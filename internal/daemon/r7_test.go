package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestGrokVersionRefusedAudited(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	ran := filepath.Join(dir, "ran")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = --version ]; then echo grok 9.9.9; exit 0; fi\n" +
		"echo ran > " + shellQuote(ran) + "\n" +
		"exit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "grok"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	app := newApp(t, dir, nil)
	app.rtMu.Lock()
	app.setPol(policy.Policy{
		Backend: "grok", CLIPermitted: true, TimersEnabled: true,
		Idle: time.Hour, Imminent: time.Minute,
	})
	app.rtMu.Unlock()
	auditPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	bot, err := app.st.CreateBot("Ada", "local", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.st.AddMessage(store.Message{BotID: bot.ID, Thread: "user", Role: "user", Content: "hi"}); err != nil {
		t.Fatal(err)
	}
	if app.kick(bot.ID) == "" {
		t.Fatal("run did not start")
	}
	waitIdleDirect(t, app, bot.ID)
	got, err := app.st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastRunStatus != "error" || !strings.Contains(got.LastRunError, "cli version is not allowed") || strings.Contains(got.LastRunError, "9.9.9") {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	if _, err := os.Stat(ran); !os.IsNotExist(err) {
		t.Fatalf("turn started: %v", err)
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "cli_version_refused") || !strings.Contains(text, "9.9.9") || !strings.Contains(text, `"action":"refuse"`) {
		t.Fatalf("audit %s", text)
	}
}
