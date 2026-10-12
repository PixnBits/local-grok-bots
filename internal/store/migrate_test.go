package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestMigrateInstructionsColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE bots (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  name_lower TEXT NOT NULL UNIQUE,
  instructions TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'idle',
  model TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE timers (
  id TEXT PRIMARY KEY,
  bot_id TEXT NOT NULL,
  schedule TEXT NOT NULL,
  prompt TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  next_fire_at TEXT NOT NULL,
  last_fire_at TEXT
);
INSERT INTO bots(id, name, name_lower, instructions, status, created_at, updated_at)
VALUES('b1', 'Ada', 'ada', 'keep', 'idle', 't', 't');
INSERT INTO timers(id, bot_id, schedule, prompt, enabled, next_fire_at)
VALUES('t1', 'b1', '1h', 'do it', 1, '2999-01-01T00:00:00.000000000Z');
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bot, err := st.GetBot("b1")
	if err != nil {
		t.Fatal(err)
	}
	if bot.Description != "keep" || bot.Label != "" || bot.Mark.Shape != "circle" {
		t.Fatalf("migrated bot %#v", bot)
	}
	if len(bot.Grants) != 0 || len(bot.NetAllow) != 0 || len(bot.SSHAllow) != 0 {
		t.Fatalf("migrated grants %#v", bot)
	}
	timers, err := st.ListTimers("b1")
	if err != nil {
		t.Fatal(err)
	}
	if len(timers) != 1 || timers[0].Name != "" || timers[0].Prompt != "do it" || timers[0].Source != "user" {
		t.Fatalf("migrated timers %#v", timers)
	}
}
