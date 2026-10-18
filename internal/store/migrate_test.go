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
	if len(bot.Grants) != 0 || len(bot.NetAllow) != 0 || len(bot.SSHAllow) != 0 || bot.ServerTools != nil {
		t.Fatalf("migrated grants %#v", bot)
	}
	timers, err := st.ListTimers("b1")
	if err != nil {
		t.Fatal(err)
	}
	if len(timers) != 1 || timers[0].Name != "" || timers[0].Prompt != "do it" {
		t.Fatalf("migrated timers %#v", timers)
	}
	for _, col := range []string{"cli_pid", "cli_pgid", "cli_start", "cli_exe", "cli_marker", "server_tools"} {
		ok, err := st.hasColumn("bots", col)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("migrate did not add %s", col)
		}
	}
}

func TestCLIProcKeptUntilCleared(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bot, err := st.CreateBot("Ada", "local", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	want := CLIProc{PID: 4242, PGID: 4242, Start: "999", Exe: "/usr/bin/claude", Marker: "run-1"}
	if err := st.SetCLIProc(bot.ID, want); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		got, err := st.ReconcileOnBoot("0.1.0", true)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].BotID != bot.ID || got[0].PID != want.PID || got[0].PGID != want.PGID || got[0].Start != want.Start || got[0].Exe != want.Exe || got[0].Marker != want.Marker {
			t.Fatalf("reconcile %d %+v", i, got)
		}
	}
	bare := CLIProc{PID: 4321}
	if err := st.SetCLIProc(bot.ID, bare); err != nil {
		t.Fatal(err)
	}
	got, err := st.ReconcileOnBoot("0.1.0", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].PID != bare.PID || got[0].Start != "" || got[0].Exe != "" {
		t.Fatalf("bare pid was dropped or filled %+v", got)
	}
	if err := st.ClearCLIProc(bot.ID); err != nil {
		t.Fatal(err)
	}
	got, err = st.ReconcileOnBoot("0.1.0", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("cleared identity returned %+v", got)
	}
	cleared, err := st.GetCLIProc(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cleared.PID != 0 || cleared.PGID != 0 || cleared.Start != "" || cleared.Exe != "" || cleared.Marker != "" {
		t.Fatalf("clear left %+v", cleared)
	}
}
