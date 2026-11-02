package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreLogInsertRedacts(t *testing.T) {
	tok := "ghp_" + strings.Repeat("A1b2", 9)
	notice := "notice " + tok
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	bot, err := st.CreateBot("Ada", "help", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddLog(bot.ID, "direct", map[string]any{"note": notice}); err != nil {
		t.Fatal(err)
	}
	run, err := st.CreateRun(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := st.FinishRun(run.ID, "error", notice)
	if err != nil || !ok {
		t.Fatalf("finish %v %v", ok, err)
	}

	events, err := st.ListLog(bot.ID, "", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	var sawDirect, sawFinished bool
	for _, ev := range events {
		body := string(ev.Detail)
		if strings.Contains(body, tok) {
			t.Fatalf("kind %s leaked %s", ev.Kind, body)
		}
		switch ev.Kind {
		case "direct":
			sawDirect = true
			if !strings.Contains(body, "notice [redacted]") {
				t.Fatalf("direct %s", body)
			}
		case "run_finished":
			sawFinished = true
			if !strings.Contains(body, "notice [redacted]") {
				t.Fatalf("run_finished %s", body)
			}
		}
	}
	if !sawDirect || !sawFinished {
		t.Fatalf("rows direct=%v finished=%v (%d events)", sawDirect, sawFinished, len(events))
	}
}
