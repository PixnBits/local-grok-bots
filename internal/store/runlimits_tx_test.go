package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

const abortLimitLog = `CREATE TRIGGER abort_limit_log BEFORE INSERT ON log_events
WHEN NEW.kind = 'bot_limits_changed'
BEGIN
  SELECT RAISE(ABORT, 'disk full');
END`

func TestLimitLogAbortRollsBackBotWrite(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.db.Exec(abortLimitLog); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertBot(BotDraft{Name: "Ada", Description: "stay", RunTimeout: time.Minute}, "user"); err == nil {
		t.Fatal("insert succeeded")
	} else {
		var se *StorageError
		if !errors.As(err, &se) {
			t.Fatalf("insert err %T %v", err, err)
		}
	}
	bots, err := st.ListBots()
	if err != nil || len(bots) != 0 {
		t.Fatalf("bots %#v %v", bots, err)
	}
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM log_events`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("log rows %d %v", n, err)
	}
	if _, err := st.db.Exec(`DROP TRIGGER abort_limit_log`); err != nil {
		t.Fatal(err)
	}
	bot, err := st.InsertBot(BotDraft{
		Name: "Ada", Label: "one", Description: "stay", RunTimeout: time.Minute,
	}, "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(abortLimitLog); err != nil {
		t.Fatal(err)
	}
	label := "two"
	if _, _, err := st.UpdateBot(bot.ID, BotPatch{
		Label: &label, RunTimeoutSet: true, RunTimeout: 2 * time.Minute, By: "user",
	}); err == nil {
		t.Fatal("update succeeded")
	} else {
		var se *StorageError
		if !errors.As(err, &se) {
			t.Fatalf("update err %T %v", err, err)
		}
	}
	got, err := st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "one" || got.RunTimeout.Duration() != time.Minute {
		t.Fatalf("row changed %#v", got)
	}
	events, err := st.ListLog(bot.ID, "bot_limits_changed", "", 20)
	if err != nil || len(events) != 1 {
		t.Fatalf("limit rows %d %v", len(events), err)
	}
	updated, err := st.ListLog(bot.ID, "bot_updated", "", 20)
	if err != nil || len(updated) != 0 {
		t.Fatalf("updated rows %#v %v", updated, err)
	}
}
