package store

import (
	"path/filepath"
	"testing"
)

func TestNormalizeCLIBackend(t *testing.T) {
	for _, s := range []string{"", "ollama", "Grok", " claude "} {
		got, err := NormalizeCLIBackend(s)
		if err != nil {
			t.Fatal(s, err)
		}
		switch s {
		case "Grok":
			if got != "grok" {
				t.Fatal(got)
			}
		case " claude ":
			if got != "claude" {
				t.Fatal(got)
			}
		default:
			if got != s && !(s == "" && got == "") {
				t.Fatal(got)
			}
		}
	}
	if _, err := NormalizeCLIBackend("openai"); err == nil {
		t.Fatal("expected error")
	}
}

func TestTurnInputsBoundByCurrentRun(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bot, err := st.InsertBot(BotDraft{Name: "Ada", CLIBackend: "grok"}, "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddMessage(Message{
		BotID: bot.ID, Thread: "user", Role: "user", Content: "one",
		CreatedAt: "2020-01-01T00:00:00.000000000Z",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddMessage(Message{
		BotID: bot.ID, Thread: "user", Role: "system", Content: "Notice: ignore",
		CreatedAt: "2020-01-01T00:00:01.000000000Z",
	}); err != nil {
		t.Fatal(err)
	}
	run, err := st.CreateRun(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddMessage(Message{
		BotID: bot.ID, Thread: "user", Role: "user", Content: "two",
		CreatedAt: "2999-01-01T00:00:00.000000000Z",
	}); err != nil {
		t.Fatal(err)
	}
	got, err := st.TurnInputs(bot.ID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Content != "one" {
		t.Fatalf("%#v", got)
	}
	if bot.CLIBackend != "grok" || bot.SessionID != "" {
		t.Fatalf("%#v", bot)
	}
	if err := st.SetBotSession(bot.ID, "sess-1"); err != nil {
		t.Fatal(err)
	}
	again, err := st.GetBot(bot.ID)
	if err != nil || again.SessionID != "sess-1" {
		t.Fatalf("%v %#v", err, again)
	}
}
