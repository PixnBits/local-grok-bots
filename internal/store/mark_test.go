package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestDefaultMark(t *testing.T) {
	got := DefaultMark()
	if got.Shape != "circle" || got.Color != "#787B8A" {
		t.Fatalf("default %#v", got)
	}
}

func TestNormalizeMarkColor(t *testing.T) {
	def := DefaultMark()
	accept := []struct{ in, want string }{
		{"#abc", "#abc"},
		{"#ABC", "#abc"},
		{"#a1b2c3", "#a1b2c3"},
		{"#A1B2C3", "#a1b2c3"},
	}
	for _, tc := range accept {
		got, err := NormalizeMark(Mark{Color: tc.in})
		if err != nil || got.Color != tc.want || got.Shape != def.Shape {
			t.Fatalf("%s -> %#v %v", tc.in, got, err)
		}
		if tc.in == "#abc" || tc.in == "#ABC" {
			if got.Color != "#abc" || len(got.Color) != 4 {
				t.Fatalf("expanded %q", got.Color)
			}
		}
	}
	for _, bad := range []string{"abc", "#ab", "#abcd", "#abcde", "#abcdefg", "#ggg", "#12345g", "# abc"} {
		if _, err := NormalizeMark(Mark{Color: bad}); err == nil || err.Error() != "mark color must be #rgb or #rrggbb" {
			t.Fatalf("%q err %v", bad, err)
		}
	}
	for _, empty := range []string{"", "   "} {
		got, err := NormalizeMark(Mark{Color: empty})
		if err != nil || got.Color != def.Color || got.Color != "#787B8A" {
			t.Fatalf("%q -> %#v %v", empty, got, err)
		}
	}
}

func TestCreateBotDefaultMark(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bot, err := st.CreateBot("Ada", "local", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	if bot.Mark != DefaultMark() || bot.Mark.Color != "#787B8A" {
		t.Fatalf("created %#v", bot.Mark)
	}
	got, err := st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mark.Color != "#787B8A" || got.Mark.Shape != "circle" {
		t.Fatalf("read %#v", got.Mark)
	}
}

func TestStoredMarkColorUnchanged(t *testing.T) {
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
  mark_shape TEXT NOT NULL DEFAULT 'circle',
  mark_color TEXT NOT NULL DEFAULT '#1b654c',
  status TEXT NOT NULL DEFAULT 'idle',
  model TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
INSERT INTO bots(id, name, name_lower, instructions, mark_shape, mark_color, status, created_at, updated_at)
VALUES('b1', 'Ada', 'ada', 'keep', 'diamond', '#1b654c', 'idle', 't', 't');
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
	if bot.Mark.Color != "#1b654c" || bot.Mark.Shape != "diamond" {
		t.Fatalf("stored mark %#v", bot.Mark)
	}
}

func TestMarkColorColumnDefault(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var dflt string
	if err := st.db.QueryRow(`SELECT dflt_value FROM pragma_table_info('bots') WHERE name='mark_color'`).Scan(&dflt); err != nil {
		t.Fatal(err)
	}
	if dflt != "'#787B8A'" {
		t.Fatalf("column default %q", dflt)
	}
}

func TestAddedMarkColorDefault(t *testing.T) {
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
INSERT INTO bots(id, name, name_lower, instructions, status, created_at, updated_at)
VALUES('b1', 'Ada', 'ada', 'keep', 'idle', 't', 't');
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
	if bot.Mark.Color != "#787B8A" || bot.Mark.Shape != "circle" {
		t.Fatalf("added mark %#v", bot.Mark)
	}
}
