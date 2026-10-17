package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/id"
	_ "modernc.org/sqlite"
)

const timeLayout = "2006-01-02T15:04:05.000000000Z"

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a bot name collides case-insensitively.
var ErrConflict = errors.New("name already exists")

var (
	clockMu sync.Mutex
	lastNS  int64
)

// Now returns a strictly increasing UTC timestamp so lexicographic order
// matches creation order.
func Now() time.Time {
	clockMu.Lock()
	defer clockMu.Unlock()
	n := time.Now().UTC().UnixNano()
	if n <= lastNS {
		n = lastNS + 1
	}
	lastNS = n
	return time.Unix(0, n).UTC()
}

func FormatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

// Mark is the roster glyph. It does not change behavior.
type Mark struct {
	Shape string `json:"shape"`
	Color string `json:"color"`
}

// DefaultMark is used when a bot is created without one.
func DefaultMark() Mark { return Mark{Shape: "circle", Color: "#1b654c"} }

// NormalizeMark accepts a shape and a #rrggbb color. Empty fields use the default.
func NormalizeMark(m Mark) (Mark, error) {
	shape := strings.ToLower(strings.TrimSpace(m.Shape))
	color := strings.ToLower(strings.TrimSpace(m.Color))
	if shape == "" {
		shape = "circle"
	}
	if color == "" {
		color = "#1b654c"
	}
	switch shape {
	case "circle", "square", "diamond", "triangle", "hex":
	default:
		return Mark{}, errors.New("unknown mark shape")
	}
	if len(color) != 7 || color[0] != '#' {
		return Mark{}, errors.New("mark color must be #rrggbb")
	}
	for _, c := range color[1:] {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return Mark{}, errors.New("mark color must be #rrggbb")
		}
	}
	return Mark{Shape: shape, Color: color}, nil
}

// NormalizeGrants keeps net, git, ssh, and build. Anything else is an error.
// The browser grant is not settable yet.
func NormalizeGrants(in []string) ([]string, error) {
	seen := map[string]bool{}
	for _, g := range in {
		g = strings.ToLower(strings.TrimSpace(g))
		if g == "" {
			continue
		}
		switch g {
		case "net", "git", "ssh", "build":
			seen[g] = true
		default:
			return nil, fmt.Errorf("unknown grant %q", g)
		}
	}
	out := []string{}
	for _, g := range []string{"net", "git", "ssh", "build"} {
		if seen[g] {
			out = append(out, g)
		}
	}
	return out, nil
}

// NormalizeAllow keeps explicit hostnames. An empty list allows nothing.
func NormalizeAllow(in []string) ([]string, error) {
	if len(in) > 64 {
		return nil, errors.New("allowlist too long")
	}
	seen := map[string]bool{}
	out := []string{}
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(h, ".")))
		if h == "" {
			continue
		}
		if len(h) > 253 || strings.Contains(h, "..") {
			return nil, fmt.Errorf("invalid allowlist host %q", h)
		}
		for _, c := range h {
			if c > 127 || !(c == '.' || c == '-' || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
				return nil, fmt.Errorf("invalid allowlist host %q", h)
			}
		}
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out, nil
}

func encodeList(v []string) string {
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func decodeList(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return []string{}, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

type Bot struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Label       string  `json:"label"`
	Description string  `json:"description,omitempty"`
	Mark        Mark    `json:"mark"`
	Pinned      bool    `json:"pinned"`
	Hidden      bool    `json:"hidden"`
	Archived    bool    `json:"archived"`
	ArchivedAt  *string `json:"archived_at,omitempty"`
	// Warnings are advisory notes the daemon computes on read; not stored.
	Warnings []string `json:"warnings,omitempty"`
	Grants   []string `json:"grants"`
	NetAllow []string `json:"net_allow"`
	SSHAllow []string `json:"ssh_allow"`
	Status   string   `json:"status"`
	Model    *string  `json:"model"`
	// SessionID is the CLI session. It is not part of the web API.
	SessionID     string  `json:"-"`
	CreatedAt     string  `json:"created_at,omitempty"`
	UpdatedAt     string  `json:"updated_at,omitempty"`
	ActiveRunID   *string `json:"active_run_id,omitempty"`
	LastRunStatus string  `json:"last_run_status,omitempty"`
	LastRunError  string  `json:"last_run_error,omitempty"`
	// ContinueRunID is not a column. The daemon fills it from the in-memory offer.
	ContinueRunID string `json:"continue_run_id,omitempty"`
	// PendingPermissions is not a column: open permission or question
	// requests for this bot, from the daemon's broker.
	PendingPermissions int `json:"pending_permissions,omitempty"`
}

type Memory struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	UpdatedAt string `json:"updated_at"`
}

type Message struct {
	ID        string  `json:"id"`
	BotID     string  `json:"bot_id"`
	Thread    string  `json:"thread"`
	Role      string  `json:"role"`
	Content   string  `json:"content"`
	RunID     *string `json:"run_id"`
	CreatedAt string  `json:"created_at"`
}

type Timer struct {
	ID         string  `json:"id"`
	BotID      string  `json:"bot_id"`
	Name       string  `json:"name"`
	Schedule   string  `json:"schedule"`
	Prompt     string  `json:"prompt"`
	Enabled    bool    `json:"enabled"`
	NextFireAt string  `json:"next_fire_at"`
	LastFireAt *string `json:"last_fire_at"`
	// Source is "user" or "bot". Only user timers keep a live CLI past idle.
	Source string `json:"source,omitempty"`
}

type Run struct {
	ID         string  `json:"id"`
	BotID      string  `json:"bot_id"`
	Status     string  `json:"status"`
	StartedAt  string  `json:"started_at"`
	FinishedAt *string `json:"finished_at"`
	Error      *string `json:"error"`
}

type LogEvent struct {
	ID     int64           `json:"id"`
	TS     string          `json:"ts"`
	BotID  *string         `json:"bot_id"`
	Kind   string          `json:"kind"`
	Detail json.RawMessage `json:"detail"`
}

// ToolRecord is one tool call a run made, kept so the page can show what a
// reply did after a reload. Arguments are redacted and the result is clipped.
type ToolRecord struct {
	// Kind is "call" for a tool call, or "text" for what the model wrote in
	// the same response before its calls. Text records have no name or
	// arguments; Result holds the text.
	Kind      string          `json:"kind"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	OK        bool            `json:"ok"`
	Result    string          `json:"result_or_error"`
	CreatedAt string          `json:"created_at"`
}

type DMPeer struct {
	BotID  string `json:"bot_id"`
	Name   string `json:"name"`
	LastAt string `json:"last_at"`
}

// Store is the SQLite source of truth. All methods are safe for concurrent use.
type Store struct {
	db *sql.DB
	mu sync.Mutex
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS bots (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  name_lower TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  mark_shape TEXT NOT NULL DEFAULT 'circle',
  mark_color TEXT NOT NULL DEFAULT '#1b654c',
  pinned INTEGER NOT NULL DEFAULT 0,
  hidden INTEGER NOT NULL DEFAULT 0,
  grants TEXT NOT NULL DEFAULT '[]',
  net_allow TEXT NOT NULL DEFAULT '[]',
  ssh_allow TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'idle',
  model TEXT,
  session_id TEXT NOT NULL DEFAULT '',
  cli_pid INTEGER NOT NULL DEFAULT 0,
  cli_pgid INTEGER NOT NULL DEFAULT 0,
  cli_start TEXT NOT NULL DEFAULT '',
  cli_exe TEXT NOT NULL DEFAULT '',
  cli_marker TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memory (
  bot_id TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (bot_id, key)
);
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  bot_id TEXT NOT NULL,
  thread TEXT NOT NULL,
  role TEXT NOT NULL,
  content TEXT NOT NULL,
  run_id TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(bot_id, thread, created_at, id);
CREATE TABLE IF NOT EXISTS timers (
  id TEXT PRIMARY KEY,
  bot_id TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  schedule TEXT NOT NULL,
  prompt TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  next_fire_at TEXT NOT NULL,
  last_fire_at TEXT,
  source TEXT NOT NULL DEFAULT 'user'
);
CREATE INDEX IF NOT EXISTS idx_timers_due ON timers(enabled, next_fire_at);
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  bot_id TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_bot ON runs(bot_id, started_at);
CREATE TABLE IF NOT EXISTS run_tools (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  bot_id TEXT NOT NULL,
  name TEXT NOT NULL,
  arguments TEXT NOT NULL,
  ok INTEGER NOT NULL,
  result TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_run_tools_run ON run_tools(run_id, id);
CREATE TABLE IF NOT EXISTS log_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  bot_id TEXT,
  kind TEXT NOT NULL,
  detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_log_bot ON log_events(bot_id, id);
CREATE INDEX IF NOT EXISTS idx_log_kind ON log_events(kind, id);
CREATE TABLE IF NOT EXISTS coi_cap (
  bot_id TEXT NOT NULL,
  cli TEXT NOT NULL,
  ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_coi_cap ON coi_cap(bot_id, cli, ts);
CREATE TABLE IF NOT EXISTS user_perm_rules (
  id TEXT PRIMARY KEY,
  bot_id TEXT NOT NULL,
  effect TEXT NOT NULL,
  pattern TEXT NOT NULL,
  classification TEXT NOT NULL DEFAULT '',
  sensitivity TEXT NOT NULL DEFAULT '',
  risk TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_user_perm_rules_bot ON user_perm_rules(bot_id, created_at);
CREATE TABLE IF NOT EXISTS perm_suggestions (
  id TEXT PRIMARY KEY,
  bot_id TEXT NOT NULL,
  pattern TEXT NOT NULL,
  effect TEXT NOT NULL,
  classification TEXT NOT NULL DEFAULT '',
  sensitivity TEXT NOT NULL DEFAULT '',
  risk TEXT NOT NULL DEFAULT '',
  count INTEGER NOT NULL DEFAULT 0,
  examples TEXT NOT NULL DEFAULT '[]',
  summary TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL,
  decided_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_perm_suggestions_bot ON perm_suggestions(bot_id, status, created_at);
`)
	if err != nil {
		return err
	}
	return s.evolve()
}

func (s *Store) evolve() error {
	hasInstr, err := s.hasColumn("bots", "instructions")
	if err != nil {
		return err
	}
	hasDesc, err := s.hasColumn("bots", "description")
	if err != nil {
		return err
	}
	if hasInstr && !hasDesc {
		if _, err := s.db.Exec(`ALTER TABLE bots RENAME COLUMN instructions TO description`); err != nil {
			return err
		}
	}
	adds := []struct{ table, col, decl string }{
		{"bots", "description", "TEXT NOT NULL DEFAULT ''"},
		{"bots", "label", "TEXT NOT NULL DEFAULT ''"},
		{"bots", "mark_shape", "TEXT NOT NULL DEFAULT 'circle'"},
		{"bots", "mark_color", "TEXT NOT NULL DEFAULT '#1b654c'"},
		{"bots", "pinned", "INTEGER NOT NULL DEFAULT 0"},
		{"bots", "hidden", "INTEGER NOT NULL DEFAULT 0"},
		{"bots", "grants", "TEXT NOT NULL DEFAULT '[]'"},
		{"bots", "net_allow", "TEXT NOT NULL DEFAULT '[]'"},
		{"bots", "ssh_allow", "TEXT NOT NULL DEFAULT '[]'"},
		{"bots", "session_id", "TEXT NOT NULL DEFAULT ''"},
		{"bots", "cli_pid", "INTEGER NOT NULL DEFAULT 0"},
		{"bots", "cli_pgid", "INTEGER NOT NULL DEFAULT 0"},
		{"bots", "cli_start", "TEXT NOT NULL DEFAULT ''"},
		{"bots", "cli_exe", "TEXT NOT NULL DEFAULT ''"},
		{"bots", "cli_marker", "TEXT NOT NULL DEFAULT ''"},
		{"timers", "name", "TEXT NOT NULL DEFAULT ''"},
		{"timers", "source", "TEXT NOT NULL DEFAULT 'user'"},
		{"timers", "archive_paused", "INTEGER NOT NULL DEFAULT 0"},
		{"runs", "input_through", "TEXT"},
		{"run_tools", "kind", "TEXT NOT NULL DEFAULT 'call'"},
		{"bots", "archived_at", "TEXT"},
		{"timers", "archive_paused", "INTEGER NOT NULL DEFAULT 0"},
		{"bots", "tool_hash", "TEXT"},
		{"bots", "tool_snapshot", "TEXT"},
	}
	for _, a := range adds {
		ok, err := s.hasColumn(a.table, a.col)
		if err != nil {
			return err
		}
		if ok {
			continue
		}
		if _, err := s.db.Exec(`ALTER TABLE ` + a.table + ` ADD COLUMN ` + a.col + ` ` + a.decl); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) hasColumn(table, col string) (bool, error) {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == col {
			return true, nil
		}
	}
	return false, rows.Err()
}

// ReconcileOnBoot marks leftover running runs failed, idles those bots,
// and records missed timers without running them. It writes daemon_start.
// cliRuns marks those runs interrupted and keeps session_id so the next CLI
// turn can --resume. Otherwise the Ollama reason daemon_restart is unchanged.
// Orphan CLI identities are returned and left stored. The caller signals
// each one, then ClearCLIProc. Clearing here would drop the identity
// before that signal attempt.
func (s *Store) ReconcileOnBoot(version string, cliRuns bool) ([]CLIProc, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := FormatTime(Now())
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	prows, err := tx.Query(`SELECT id, cli_pid, cli_pgid, cli_start, cli_exe, cli_marker FROM bots WHERE cli_pid > 0`)
	if err != nil {
		return nil, err
	}
	var procs []CLIProc
	for prows.Next() {
		var p CLIProc
		if err := prows.Scan(&p.BotID, &p.PID, &p.PGID, &p.Start, &p.Exe, &p.Marker); err != nil {
			prows.Close()
			return nil, err
		}
		procs = append(procs, p)
	}
	prows.Close()
	if err := prows.Err(); err != nil {
		return nil, err
	}

	reason := "daemon_restart"
	if cliRuns {
		reason = "interrupted"
	}
	rows, err := tx.Query(`SELECT id, bot_id FROM runs WHERE status='running'`)
	if err != nil {
		return nil, err
	}
	type pair struct{ runID, botID string }
	var running []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.runID, &p.botID); err != nil {
			rows.Close()
			return nil, err
		}
		running = append(running, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, p := range running {
		if _, err := tx.Exec(`UPDATE runs SET status='error', error=?, finished_at=? WHERE id=? AND status='running'`, reason, now, p.runID); err != nil {
			return nil, err
		}
		if err := s.addLogTx(tx, p.botID, "run_finished", map[string]any{
			"run_id": p.runID, "status": "error", "error": reason,
		}); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(`UPDATE bots SET status='idle', updated_at=? WHERE status='running'`, now); err != nil {
		return nil, err
	}

	trows, err := tx.Query(`SELECT id, bot_id, schedule, next_fire_at FROM timers WHERE enabled=1 AND next_fire_at < ?`, now)
	if err != nil {
		return nil, err
	}
	type missed struct{ id, botID, schedule, when string }
	var late []missed
	for trows.Next() {
		var m missed
		if err := trows.Scan(&m.id, &m.botID, &m.schedule, &m.when); err != nil {
			trows.Close()
			return nil, err
		}
		late = append(late, m)
	}
	trows.Close()
	if err := trows.Err(); err != nil {
		return nil, err
	}
	for _, m := range late {
		next, err := nextAfter(Now(), m.schedule)
		if err != nil {
			if _, err := tx.Exec(`UPDATE timers SET enabled=0 WHERE id=?`, m.id); err != nil {
				return nil, err
			}
		} else {
			if _, err := tx.Exec(`UPDATE timers SET next_fire_at=? WHERE id=?`, FormatTime(next), m.id); err != nil {
				return nil, err
			}
		}
		if err := s.addLogTx(tx, m.botID, "timer_missed", map[string]any{
			"timer_id": m.id, "scheduled_for": m.when,
		}); err != nil {
			return nil, err
		}
	}
	if err := s.addLogTx(tx, "", "daemon_start", map[string]any{"version": version}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return procs, nil
}

func nextAfter(from time.Time, schedule string) (time.Time, error) {
	d, err := ParseInterval(schedule)
	if err != nil {
		return time.Time{}, err
	}
	return from.Add(d), nil
}

// ParseInterval accepts Go durations (30s, 5m, 2h) and day counts (1d),
// optionally prefixed with "every ".
func ParseInterval(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "every ")
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("schedule must be an interval like 30s, 5m, 2h, or 1d")
	}
	if strings.HasSuffix(s, "d") && !strings.ContainsAny(s, "hms") {
		n, err := parsePositiveInt(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, errors.New("schedule must be an interval like 30s, 5m, 2h, or 1d")
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < time.Second {
		return 0, errors.New("schedule must be an interval like 30s, 5m, 2h, or 1d")
	}
	return d, nil
}

func parsePositiveInt(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not int")
		}
		n = n*10 + int(c-'0')
	}
	if n <= 0 {
		return 0, errors.New("not positive")
	}
	return n, nil
}

func (s *Store) addLogTx(tx *sql.Tx, botID, kind string, detail any) error {
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	var bot any
	if botID != "" {
		bot = botID
	}
	_, err = tx.Exec(`INSERT INTO log_events(ts, bot_id, kind, detail) VALUES(?,?,?,?)`,
		FormatTime(Now()), bot, kind, string(b))
	return err
}

func (s *Store) AddLog(botID, kind string, detail any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.addLogTx(tx, botID, kind, detail); err != nil {
		return err
	}
	return tx.Commit()
}

// BotDraft is the input for creating a bot. Empty mark fields use DefaultMark.
type BotDraft struct {
	Name        string
	Label       string
	Description string
	Mark        Mark
	Model       *string
	Grants      []string
	NetAllow    []string
	SSHAllow    []string
}

// CreateBot inserts a bot with a default mark and no label.
func (s *Store) CreateBot(name, description string, model *string, by string) (Bot, error) {
	return s.InsertBot(BotDraft{Name: name, Description: description, Model: model}, by)
}

// InsertBot inserts a bot. Description is the standing prompt.
func (s *Store) InsertBot(d BotDraft, by string) (Bot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mark, err := NormalizeMark(d.Mark)
	if err != nil {
		return Bot{}, err
	}
	grants, err := NormalizeGrants(d.Grants)
	if err != nil {
		return Bot{}, err
	}
	netAllow, err := NormalizeAllow(d.NetAllow)
	if err != nil {
		return Bot{}, err
	}
	sshAllow, err := NormalizeAllow(d.SSHAllow)
	if err != nil {
		return Bot{}, err
	}
	now := FormatTime(Now())
	b := Bot{
		ID: id.New(), Name: d.Name, Label: d.Label, Description: d.Description,
		Mark: mark, Grants: grants, NetAllow: netAllow, SSHAllow: sshAllow,
		Status: "idle", Model: d.Model, CreatedAt: now, UpdatedAt: now,
	}
	_, err = s.db.Exec(`INSERT INTO bots(id, name, name_lower, label, description, mark_shape, mark_color, pinned, hidden, grants, net_allow, ssh_allow, status, model, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		b.ID, b.Name, strings.ToLower(b.Name), b.Label, b.Description, b.Mark.Shape, b.Mark.Color, 0, 0, encodeList(grants), encodeList(netAllow), encodeList(sshAllow), b.Status, nullStr(d.Model), b.CreatedAt, b.UpdatedAt)
	if err != nil {
		if isUnique(err) {
			return Bot{}, ErrConflict
		}
		return Bot{}, err
	}
	fields := []string{"name", "description"}
	if d.Label != "" {
		fields = append(fields, "label")
	}
	if d.Model != nil {
		fields = append(fields, "model")
	}
	if err := s.logUnlocked(b.ID, "bot_created", map[string]any{
		"fields": fields, "by": by, "bot_id": b.ID, "name": b.Name,
	}); err != nil {
		return Bot{}, err
	}
	return b, nil
}

func (s *Store) logUnlocked(botID, kind string, detail any) error {
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	var bot any
	if botID != "" {
		bot = botID
	}
	_, err = s.db.Exec(`INSERT INTO log_events(ts, bot_id, kind, detail) VALUES(?,?,?,?)`,
		FormatTime(Now()), bot, kind, string(b))
	return err
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE")
}

func nullStr(p *string) any {
	if p == nil || *p == "" {
		return nil
	}
	return *p
}

func (s *Store) GetBot(id string) (Bot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getBot(id, true)
}

func (s *Store) getBot(id string, withRun bool) (Bot, error) {
	row := s.db.QueryRow(botSelect+` WHERE id=?`, id)
	b, err := scanBot(row, true)
	if err != nil {
		return Bot{}, err
	}
	if withRun {
		s.attachRun(&b)
	}
	return b, nil
}

func (s *Store) attachRun(b *Bot) {
	var runID, status string
	var errText sql.NullString
	err := s.db.QueryRow(`SELECT id, status, error FROM runs WHERE bot_id=? ORDER BY started_at DESC LIMIT 1`, b.ID).Scan(&runID, &status, &errText)
	if err == sql.ErrNoRows {
		return
	}
	if err != nil {
		return
	}
	b.LastRunStatus = status
	if errText.Valid {
		b.LastRunError = errText.String
	}
	if status == "running" {
		b.ActiveRunID = &runID
	}
}

const botSelect = `SELECT id, name, label, description, mark_shape, mark_color, pinned, hidden, grants, net_allow, ssh_allow, status, model, session_id, created_at, updated_at, archived_at FROM bots`

func scanBot(row interface{ Scan(dest ...any) error }, full bool) (Bot, error) {
	var b Bot
	var model sql.NullString
	var shape, color, grants, netAllow, sshAllow string
	var pinned, hidden int
	var archived sql.NullString
	err := row.Scan(&b.ID, &b.Name, &b.Label, &b.Description, &shape, &color, &pinned, &hidden, &grants, &netAllow, &sshAllow, &b.Status, &model, &b.SessionID, &b.CreatedAt, &b.UpdatedAt, &archived)
	if errors.Is(err, sql.ErrNoRows) {
		return Bot{}, ErrNotFound
	}
	if err != nil {
		return Bot{}, err
	}
	b.Mark = Mark{Shape: shape, Color: color}
	if b.Mark.Shape == "" || b.Mark.Color == "" {
		b.Mark = DefaultMark()
	}
	b.Pinned = pinned != 0
	b.Hidden = hidden != 0
	if archived.Valid && archived.String != "" {
		a := archived.String
		b.ArchivedAt = &a
		b.Archived = true
	}
	b.Grants, err = decodeList(grants)
	if err != nil {
		return Bot{}, err
	}
	b.NetAllow, err = decodeList(netAllow)
	if err != nil {
		return Bot{}, err
	}
	b.SSHAllow, err = decodeList(sshAllow)
	if err != nil {
		return Bot{}, err
	}
	if model.Valid && model.String != "" {
		s := model.String
		b.Model = &s
	}
	if !full {
		b.Description = ""
	}
	return b, nil
}

func (s *Store) ListBots() ([]Bot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(botSelect + ` ORDER BY pinned DESC, name_lower`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Bot
	for rows.Next() {
		b, err := scanBot(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	for i := range out {
		s.attachRun(&out[i])
		out[i].Description = ""
		out[i].CreatedAt = ""
		out[i].UpdatedAt = ""
	}
	if out == nil {
		out = []Bot{}
	}
	return out, nil
}

type BotPatch struct {
	Name        *string
	Label       *string
	Description *string
	Mark        *Mark
	Model       *string
	ModelSet    bool
	Status      *string
	Pinned      *bool
	Hidden      *bool
	GrantsSet   bool
	Grants      []string
	NetSet      bool
	NetAllow    []string
	SSHSet      bool
	SSHAllow    []string
	By          string
}

func (s *Store) UpdateBot(id string, p BotPatch) (Bot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.getBot(id, false)
	if err != nil {
		return Bot{}, err
	}
	fields := []string{}
	if p.Name != nil && *p.Name != b.Name {
		b.Name = *p.Name
		fields = append(fields, "name")
	}
	if p.Label != nil && *p.Label != b.Label {
		b.Label = *p.Label
		fields = append(fields, "label")
	}
	if p.Description != nil && *p.Description != b.Description {
		b.Description = *p.Description
		fields = append(fields, "description")
	}
	if p.Mark != nil {
		mark, err := NormalizeMark(*p.Mark)
		if err != nil {
			return Bot{}, err
		}
		if mark != b.Mark {
			b.Mark = mark
			fields = append(fields, "mark")
		}
	}
	if p.ModelSet {
		b.Model = p.Model
		fields = append(fields, "model")
	}
	if p.Status != nil && *p.Status != b.Status {
		b.Status = *p.Status
		fields = append(fields, "status")
	}
	if p.Pinned != nil && *p.Pinned != b.Pinned {
		b.Pinned = *p.Pinned
		fields = append(fields, "pinned")
	}
	if p.Hidden != nil && *p.Hidden != b.Hidden {
		b.Hidden = *p.Hidden
		fields = append(fields, "hidden")
	}
	if p.GrantsSet {
		g, err := NormalizeGrants(p.Grants)
		if err != nil {
			return Bot{}, err
		}
		if !slices.Equal(g, b.Grants) {
			b.Grants = g
			fields = append(fields, "grants")
		}
	}
	if p.NetSet {
		hosts, err := NormalizeAllow(p.NetAllow)
		if err != nil {
			return Bot{}, err
		}
		if !slices.Equal(hosts, b.NetAllow) {
			b.NetAllow = hosts
			fields = append(fields, "net_allow")
		}
	}
	if p.SSHSet {
		hosts, err := NormalizeAllow(p.SSHAllow)
		if err != nil {
			return Bot{}, err
		}
		if !slices.Equal(hosts, b.SSHAllow) {
			b.SSHAllow = hosts
			fields = append(fields, "ssh_allow")
		}
	}
	if len(fields) == 0 {
		s.attachRun(&b)
		return b, nil
	}
	b.UpdatedAt = FormatTime(Now())
	pin, hide := 0, 0
	if b.Pinned {
		pin = 1
	}
	if b.Hidden {
		hide = 1
	}
	_, err = s.db.Exec(`UPDATE bots SET name=?, name_lower=?, label=?, description=?, mark_shape=?, mark_color=?, pinned=?, hidden=?, grants=?, net_allow=?, ssh_allow=?, model=?, status=?, updated_at=? WHERE id=?`,
		b.Name, strings.ToLower(b.Name), b.Label, b.Description, b.Mark.Shape, b.Mark.Color, pin, hide, encodeList(b.Grants), encodeList(b.NetAllow), encodeList(b.SSHAllow), nullStr(b.Model), b.Status, b.UpdatedAt, b.ID)
	if err != nil {
		if isUnique(err) {
			return Bot{}, ErrConflict
		}
		return Bot{}, err
	}
	if err := s.logUnlocked(b.ID, "bot_updated", map[string]any{"fields": fields, "by": p.By, "bot_id": b.ID, "name": b.Name}); err != nil {
		return Bot{}, err
	}
	s.attachRun(&b)
	return b, nil
}

// CLIProc is the CLI process identity stored for one bot.
// A later boot may signal it only when the live process still matches.
type CLIProc struct {
	BotID  string
	PID    int
	PGID   int
	Start  string
	Exe    string
	Marker string
}

// SetCLIProc records the identity captured at spawn.
// A crash leaves the row so the next boot can try to signal that process.
func (s *Store) SetCLIProc(id string, p CLIProc) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.PID < 0 {
		p.PID = 0
	}
	if p.PGID < 0 {
		p.PGID = 0
	}
	res, err := s.db.Exec(`UPDATE bots SET cli_pid=?, cli_pgid=?, cli_start=?, cli_exe=?, cli_marker=? WHERE id=?`,
		p.PID, p.PGID, p.Start, p.Exe, p.Marker, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetCLIProc reads the stored CLI identity. A cleared row has PID 0.
func (s *Store) GetCLIProc(id string) (CLIProc, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var p CLIProc
	p.BotID = id
	err := s.db.QueryRow(`SELECT cli_pid, cli_pgid, cli_start, cli_exe, cli_marker FROM bots WHERE id=?`, id).
		Scan(&p.PID, &p.PGID, &p.Start, &p.Exe, &p.Marker)
	if errors.Is(err, sql.ErrNoRows) {
		return CLIProc{}, ErrNotFound
	}
	return p, err
}

// ClearCLIProc drops the stored CLI identity.
// Call it after a boot signal attempt, including when that attempt refuses.
func (s *Store) ClearCLIProc(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`UPDATE bots SET cli_pid=0, cli_pgid=0, cli_start='', cli_exe='', cli_marker='' WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetBotSession records the CLI session id. It does not write a log row.
// An idle kill or a restart keeps this value so the next turn can --resume.
func (s *Store) SetBotSession(id, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`UPDATE bots SET session_id=? WHERE id=?`, sessionID, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetStatus(id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`UPDATE bots SET status=?, updated_at=? WHERE id=?`, status, FormatTime(Now()), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteBot(id, by string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var name string
	err := s.db.QueryRow(`SELECT name FROM bots WHERE id=?`, id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM memory WHERE bot_id=?`,
		`DELETE FROM messages WHERE bot_id=?`,
		`DELETE FROM timers WHERE bot_id=?`,
		`DELETE FROM run_tools WHERE bot_id=?`,
		`DELETE FROM runs WHERE bot_id=?`,
		`DELETE FROM bots WHERE id=?`,
	} {
		if _, err := tx.Exec(q, id); err != nil {
			return err
		}
	}
	if err := s.addLogTx(tx, id, "bot_deleted", map[string]any{"fields": []string{"deleted"}, "by": by, "bot_id": id, "name": name}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) FindBot(nameOrID string) (Bot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(botSelect+` WHERE id=?`, nameOrID)
	b, err := scanBot(row, true)
	if err == nil {
		return b, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Bot{}, err
	}
	row = s.db.QueryRow(botSelect+` WHERE name_lower=?`, strings.ToLower(strings.TrimSpace(nameOrID)))
	return scanBot(row, true)
}

func (s *Store) ListMemory(botID string) ([]Memory, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT key, value, updated_at FROM memory WHERE bot_id=? ORDER BY key`, botID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Memory{}
	for rows.Next() {
		var m Memory
		if err := rows.Scan(&m.Key, &m.Value, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) UpsertMemory(botID, key, value string) (Memory, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := FormatTime(Now())
	_, err := s.db.Exec(`INSERT INTO memory(bot_id, key, value, updated_at) VALUES(?,?,?,?)
		ON CONFLICT(bot_id, key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		botID, key, value, now)
	if err != nil {
		return Memory{}, err
	}
	return Memory{Key: key, Value: value, UpdatedAt: now}, nil
}

func (s *Store) DeleteMemory(botID, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM memory WHERE bot_id=? AND key=?`, botID, key)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) AddMessage(m Message) (Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addMessage(m)
}

func (s *Store) addMessage(m Message) (Message, error) {
	if m.ID == "" {
		m.ID = id.New()
	}
	if m.CreatedAt == "" {
		m.CreatedAt = FormatTime(Now())
	}
	_, err := s.db.Exec(`INSERT INTO messages(id, bot_id, thread, role, content, run_id, created_at) VALUES(?,?,?,?,?,?,?)`,
		m.ID, m.BotID, m.Thread, m.Role, m.Content, nullStr(m.RunID), m.CreatedAt)
	if err != nil {
		return Message{}, err
	}
	return m, nil
}

// AddDMPair stores both sides of a direct message in one transaction.
func (s *Store) AddDMPair(fromID, toID, content, runID string) (sent Message, received Message, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return Message{}, Message{}, err
	}
	defer tx.Rollback()
	var run any
	if runID != "" {
		run = runID
	}
	sent = Message{ID: id.New(), BotID: fromID, Thread: "dm:" + toID, Role: "bot", Content: content, CreatedAt: FormatTime(Now())}
	if runID != "" {
		sent.RunID = &runID
	}
	received = Message{ID: id.New(), BotID: toID, Thread: "dm:" + fromID, Role: "user", Content: content, CreatedAt: FormatTime(Now())}
	var fromName string
	if err := tx.QueryRow(`SELECT name FROM bots WHERE id=?`, fromID).Scan(&fromName); err != nil {
		return Message{}, Message{}, err
	}
	notice := Message{ID: id.New(), BotID: toID, Thread: "user", Role: "system", Content: "Message from " + fromName, CreatedAt: FormatTime(Now())}
	if _, err := tx.Exec(`INSERT INTO messages(id, bot_id, thread, role, content, run_id, created_at) VALUES(?,?,?,?,?,?,?)`,
		sent.ID, sent.BotID, sent.Thread, sent.Role, sent.Content, run, sent.CreatedAt); err != nil {
		return Message{}, Message{}, err
	}
	if _, err := tx.Exec(`INSERT INTO messages(id, bot_id, thread, role, content, run_id, created_at) VALUES(?,?,?,?,?,?,?)`,
		received.ID, received.BotID, received.Thread, received.Role, received.Content, nil, received.CreatedAt); err != nil {
		return Message{}, Message{}, err
	}
	if _, err := tx.Exec(`INSERT INTO messages(id, bot_id, thread, role, content, run_id, created_at) VALUES(?,?,?,?,?,?,?)`,
		notice.ID, notice.BotID, notice.Thread, notice.Role, notice.Content, nil, notice.CreatedAt); err != nil {
		return Message{}, Message{}, err
	}
	if err := s.addLogTx(tx, fromID, "dm_sent", map[string]any{"message_id": sent.ID, "other_bot_id": toID}); err != nil {
		return Message{}, Message{}, err
	}
	if err := s.addLogTx(tx, toID, "dm_received", map[string]any{"message_id": received.ID, "other_bot_id": fromID}); err != nil {
		return Message{}, Message{}, err
	}
	if err := tx.Commit(); err != nil {
		return Message{}, Message{}, err
	}
	return sent, received, nil
}

func (s *Store) ListMessages(botID, thread, before string, limit int) ([]Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = 50
	}
	q := `SELECT id, bot_id, thread, role, content, run_id, created_at FROM messages WHERE bot_id=? AND thread=?`
	args := []any{botID, thread}
	if before != "" {
		q += ` AND (created_at < (SELECT created_at FROM messages WHERE id=?) OR (created_at = (SELECT created_at FROM messages WHERE id=?) AND id < ?))`
		args = append(args, before, before, before)
	}
	q += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rev []Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		rev = append(rev, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Message, len(rev))
	for i := range rev {
		out[len(rev)-1-i] = rev[i]
	}
	if out == nil {
		out = []Message{}
	}
	return out, nil
}

func scanMessage(sc interface{ Scan(...any) error }) (Message, error) {
	var m Message
	var run sql.NullString
	if err := sc.Scan(&m.ID, &m.BotID, &m.Thread, &m.Role, &m.Content, &run, &m.CreatedAt); err != nil {
		return Message{}, err
	}
	if run.Valid {
		s := run.String
		m.RunID = &s
	}
	return m, nil
}

// RecentContext returns the newest messages for a bot across the user thread
// and DM threads, oldest first, capped at limit.
func (s *Store) RecentContext(botID string, limit int) ([]Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = 40
	}
	rows, err := s.db.Query(`SELECT id, bot_id, thread, role, content, run_id, created_at FROM (
		SELECT id, bot_id, thread, role, content, run_id, created_at FROM messages WHERE bot_id=?
		ORDER BY created_at DESC, id DESC LIMIT ?
	) ORDER BY created_at ASC, id ASC`, botID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Message{}
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) NeedsRun(botID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var started sql.NullString
	// A run has consumed every message up to input_through when it folded
	// messages in mid-run, and up to started_at otherwise.
	err := s.db.QueryRow(`SELECT COALESCE(input_through, started_at) FROM runs WHERE bot_id=? ORDER BY started_at DESC LIMIT 1`, botID).Scan(&started)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	var pending sql.NullString
	// Notice lines are visible on the thread. They do not queue another turn.
	err = s.db.QueryRow(`SELECT MAX(created_at) FROM messages WHERE bot_id=? AND `+turnInput, botID).Scan(&pending)
	if err != nil {
		return false, err
	}
	if !pending.Valid || pending.String == "" {
		return false, nil
	}
	if !started.Valid || started.String == "" {
		return true, nil
	}
	return pending.String > started.String, nil
}

// turnInput matches the messages that queue a turn. NeedsRun, TurnInputs,
// and TurnInputSince share it.
const turnInput = `(
		(thread='user' AND role='user')
		OR (thread='user' AND role='system' AND content NOT LIKE 'Notice: %')
		OR (thread LIKE 'dm:%' AND role='user')
	)`

// TurnInputs returns the messages for this CLI turn: user text, scheduled
// prompts, and inbound DMs created after the previous run started and before
// this run started. Notices are excluded. The daemon store is the source of
// truth; CLI transcripts are not read.
func (s *Store) TurnInputs(botID, currentRunID string) ([]Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var current string
	err := s.db.QueryRow(`SELECT started_at FROM runs WHERE id=?`, currentRunID).Scan(&current)
	if err != nil {
		return nil, err
	}
	var prev sql.NullString
	err = s.db.QueryRow(`SELECT started_at FROM runs WHERE bot_id=? AND id!=? ORDER BY started_at DESC LIMIT 1`, botID, currentRunID).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	q := `SELECT id, bot_id, thread, role, content, run_id, created_at FROM messages WHERE bot_id=? AND created_at<? AND ` + turnInput
	args := []any{botID, current}
	if prev.Valid && prev.String != "" {
		q += ` AND created_at>?`
		args = append(args, prev.String)
	}
	q += ` ORDER BY created_at ASC, id ASC`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Message{}
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// TurnInputSince returns turn-queuing messages created after since, oldest first.
func (s *Store) TurnInputSince(botID, since string) ([]Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, bot_id, thread, role, content, run_id, created_at FROM messages
		WHERE bot_id=? AND created_at > ? AND `+turnInput+` ORDER BY created_at ASC, id ASC`, botID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Message{}
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// MarkRunInput records that a live run has read turn input through ts.
// It only moves forward.
func (s *Store) MarkRunInput(runID, ts string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE runs SET input_through=? WHERE id=? AND (input_through IS NULL OR input_through < ?)`, ts, runID, ts)
	return err
}

func (s *Store) CreateRun(botID string) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := Run{ID: id.New(), BotID: botID, Status: "running", StartedAt: FormatTime(Now())}
	_, err := s.db.Exec(`INSERT INTO runs(id, bot_id, status, started_at) VALUES(?,?,?,?)`, r.ID, r.BotID, r.Status, r.StartedAt)
	if err != nil {
		return Run{}, err
	}
	if err := s.logUnlocked(botID, "run_started", map[string]any{"run_id": r.ID}); err != nil {
		return Run{}, err
	}
	return r, nil
}

// FinishRun moves a running run to a terminal status. False means it was already finished.
func (s *Store) FinishRun(id, status, errText string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var botID string
	err := s.db.QueryRow(`SELECT bot_id FROM runs WHERE id=? AND status='running'`, id).Scan(&botID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	now := FormatTime(Now())
	var e any
	if errText != "" {
		e = errText
	}
	if _, err := s.db.Exec(`UPDATE runs SET status=?, finished_at=?, error=? WHERE id=? AND status='running'`, status, now, e, id); err != nil {
		return false, err
	}
	detail := map[string]any{"run_id": id, "status": status}
	if errText != "" {
		detail["error"] = errText
	}
	if err := s.logUnlocked(botID, "run_finished", detail); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) GetRun(id string) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var r Run
	var fin, errText sql.NullString
	err := s.db.QueryRow(`SELECT id, bot_id, status, started_at, finished_at, error FROM runs WHERE id=?`, id).
		Scan(&r.ID, &r.BotID, &r.Status, &r.StartedAt, &fin, &errText)
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	if err != nil {
		return Run{}, err
	}
	if fin.Valid {
		r.FinishedAt = &fin.String
	}
	if errText.Valid {
		r.Error = &errText.String
	}
	return r, nil
}

// OnceSchedule marks a one-shot timer. It fires at next_fire_at, then turns
// itself off; the row stays for history.
const OnceSchedule = "once"

// CreateTimerAt stores a one-shot timer that fires at at.
// source is "user" or "bot". Only a user timer keeps a live CLI past idle.
func (s *Store) CreateTimerAt(botID, name, prompt string, at time.Time, source string) (Timer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	src, err := timerSource(source)
	if err != nil {
		return Timer{}, err
	}
	t := Timer{
		ID: id.New(), BotID: botID, Name: strings.TrimSpace(name), Schedule: OnceSchedule, Prompt: prompt,
		Enabled: true, NextFireAt: FormatTime(at), Source: src,
	}
	_, err = s.db.Exec(`INSERT INTO timers(id, bot_id, name, schedule, prompt, enabled, next_fire_at, source) VALUES(?,?,?,?,?,?,?,?)`,
		t.ID, t.BotID, t.Name, t.Schedule, t.Prompt, 1, t.NextFireAt, t.Source)
	return t, err
}

func (s *Store) CreateTimer(botID, name, schedule, prompt string, enabled bool, source string) (Timer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	source, err := timerSource(source)
	if err != nil {
		return Timer{}, err
	}
	d, err := ParseInterval(schedule)
	if err != nil {
		return Timer{}, err
	}
	en := 0
	if enabled {
		en = 1
	}
	t := Timer{
		ID: id.New(), BotID: botID, Name: strings.TrimSpace(name), Schedule: strings.TrimSpace(schedule), Prompt: prompt,
		Enabled: enabled, NextFireAt: FormatTime(Now().Add(d)), Source: source,
	}
	_, err = s.db.Exec(`INSERT INTO timers(id, bot_id, name, schedule, prompt, enabled, next_fire_at, source) VALUES(?,?,?,?,?,?,?,?)`,
		t.ID, t.BotID, t.Name, t.Schedule, t.Prompt, en, t.NextFireAt, t.Source)
	return t, err
}

func timerSource(source string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "user":
		return "user", nil
	case "bot":
		return "bot", nil
	default:
		return "", fmt.Errorf("timer source must be user or bot")
	}
}

func (s *Store) ListTimers(botID string) ([]Timer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(timerSelect+` WHERE bot_id=? ORDER BY next_fire_at`, botID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTimers(rows)
}

func (s *Store) GetTimer(id string) (Timer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(timerSelect+` WHERE id=?`, id)
	t, err := scanTimer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Timer{}, ErrNotFound
	}
	return t, err
}

type TimerPatch struct {
	Name     *string
	Schedule *string
	Prompt   *string
	Enabled  *bool
}

func (s *Store) UpdateTimer(id string, p TimerPatch) (Timer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(timerSelect+` WHERE id=?`, id)
	t, err := scanTimer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Timer{}, ErrNotFound
	}
	if err != nil {
		return Timer{}, err
	}
	if p.Name != nil {
		t.Name = strings.TrimSpace(*p.Name)
	}
	if p.Schedule != nil {
		if _, err := ParseInterval(*p.Schedule); err != nil {
			return Timer{}, err
		}
		t.Schedule = strings.TrimSpace(*p.Schedule)
		d, _ := ParseInterval(t.Schedule)
		t.NextFireAt = FormatTime(Now().Add(d))
	}
	if p.Prompt != nil {
		t.Prompt = *p.Prompt
	}
	if p.Enabled != nil {
		t.Enabled = *p.Enabled
		if t.Enabled {
			next, err := time.Parse(timeLayout, t.NextFireAt)
			if err != nil || !next.After(time.Now().UTC()) {
				d, _ := ParseInterval(t.Schedule)
				t.NextFireAt = FormatTime(Now().Add(d))
			}
		}
	}
	en := 0
	if t.Enabled {
		en = 1
	}
	_, err = s.db.Exec(`UPDATE timers SET name=?, schedule=?, prompt=?, enabled=?, next_fire_at=? WHERE id=?`,
		t.Name, t.Schedule, t.Prompt, en, t.NextFireAt, t.ID)
	return t, err
}

func (s *Store) DeleteTimer(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM timers WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ClaimDueTimers returns timers whose next_fire_at has passed and pushes each
// next fire forward. The caller runs them.
func (s *Store) ClaimDueTimers(now time.Time) ([]Timer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stamp := FormatTime(now)
	rows, err := s.db.Query(timerSelect+` WHERE enabled=1 AND next_fire_at <= ?`, stamp)
	if err != nil {
		return nil, err
	}
	due, err := scanTimers(rows)
	rows.Close()
	if err != nil {
		return nil, err
	}
	var claimed []Timer
	for _, t := range due {
		fired := FormatTime(Now())
		var res sql.Result
		if t.Schedule == OnceSchedule {
			res, err = s.db.Exec(`UPDATE timers SET enabled=0, last_fire_at=? WHERE id=? AND next_fire_at=? AND enabled=1`,
				fired, t.ID, t.NextFireAt)
		} else {
			d, perr := ParseInterval(t.Schedule)
			if perr != nil {
				continue
			}
			next := FormatTime(Now().Add(d))
			res, err = s.db.Exec(`UPDATE timers SET next_fire_at=?, last_fire_at=? WHERE id=? AND next_fire_at=?`,
				next, fired, t.ID, t.NextFireAt)
		}
		if err != nil {
			return nil, err
		}
		n, _ := res.RowsAffected()
		if n == 1 {
			claimed = append(claimed, t)
		}
	}
	return claimed, nil
}

func scanTimers(rows *sql.Rows) ([]Timer, error) {
	out := []Timer{}
	for rows.Next() {
		t, err := scanTimer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

const timerSelect = `SELECT id, bot_id, name, schedule, prompt, enabled, next_fire_at, last_fire_at, source FROM timers`

func scanTimer(sc interface{ Scan(...any) error }) (Timer, error) {
	var t Timer
	var en int
	var last sql.NullString
	err := sc.Scan(&t.ID, &t.BotID, &t.Name, &t.Schedule, &t.Prompt, &en, &t.NextFireAt, &last, &t.Source)
	if err != nil {
		return Timer{}, err
	}
	t.Enabled = en == 1
	if last.Valid {
		t.LastFireAt = &last.String
	}
	if t.Source == "" {
		t.Source = "user"
	}
	return t, nil
}

func (s *Store) ListDMs(botID string) ([]DMPeer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
		SELECT substr(m.thread, 4) AS other_id, b.name, MAX(m.created_at)
		FROM messages m
		JOIN bots b ON b.id = substr(m.thread, 4)
		WHERE m.bot_id=? AND m.thread LIKE 'dm:%'
		GROUP BY other_id
		ORDER BY MAX(m.created_at) DESC`, botID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DMPeer{}
	for rows.Next() {
		var d DMPeer
		if err := rows.Scan(&d.BotID, &d.Name, &d.LastAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) ListLog(botID, kind, before string, limit int) ([]LogEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	q := `SELECT id, ts, bot_id, kind, detail FROM log_events WHERE 1=1`
	args := []any{}
	if botID != "" {
		q += ` AND bot_id=?`
		args = append(args, botID)
	}
	if kind != "" {
		q += ` AND kind=?`
		args = append(args, kind)
	}
	if before != "" {
		q += ` AND id < ?`
		args = append(args, before)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LogEvent{}
	for rows.Next() {
		var e LogEvent
		var bot sql.NullString
		var detail string
		if err := rows.Scan(&e.ID, &e.TS, &bot, &e.Kind, &detail); err != nil {
			return nil, err
		}
		if bot.Valid {
			s := bot.String
			e.BotID = &s
		}
		e.Detail = json.RawMessage(detail)
		if !json.Valid(e.Detail) {
			e.Detail = json.RawMessage(`{}`)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// InsertRunningRun is for crash-restart tests.
func (s *Store) InsertRunningRun(botID string) (Run, error) {
	return s.CreateRun(botID)
}

func (s *Store) BotNames() (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, name FROM bots`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = name
	}
	return out, rows.Err()
}

// BackdateTimer moves next_fire_at into the past. Test helper.
func (s *Store) BackdateTimer(id string, when time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`UPDATE timers SET next_fire_at=? WHERE id=?`, FormatTime(when), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) LogCount(kind string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM log_events WHERE kind=?`, kind).Scan(&n)
	return n, err
}

// TakeCOICap records one brokered CLI call unless the last hour is already full.
// A limit of zero or less denies the call and does not record it. A store
// error is returned so the caller can fail closed.
func (s *Store) TakeCOICap(botID, cli string, limit int) (bool, error) {
	if s == nil {
		return false, errors.New("store is not available")
	}
	if limit <= 0 {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := Now()
	cut := FormatTime(now.Add(-time.Hour))
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM coi_cap WHERE bot_id=? AND cli=? AND ts<=?`, botID, cli, cut); err != nil {
		return false, err
	}
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM coi_cap WHERE bot_id=? AND cli=? AND ts>?`, botID, cli, cut).Scan(&n); err != nil {
		return false, err
	}
	if n >= limit {
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return false, nil
	}
	if _, err := tx.Exec(`INSERT INTO coi_cap(bot_id, cli, ts) VALUES(?,?,?)`, botID, cli, FormatTime(now)); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// CountLogSince counts one bot's log events of kind at or after since.
func (s *Store) CountLogSince(botID, kind string, since time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM log_events WHERE bot_id=? AND kind=? AND ts>=?`,
		botID, kind, FormatTime(since),
	).Scan(&n)
	return n, err
}

// FailRunning marks any run still in progress as error. Used on clean shutdown.
func (s *Store) FailRunning(reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, bot_id FROM runs WHERE status='running'`)
	if err != nil {
		return err
	}
	type pair struct{ runID, botID string }
	var running []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.runID, &p.botID); err != nil {
			rows.Close()
			return err
		}
		running = append(running, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	now := FormatTime(Now())
	for _, p := range running {
		res, err := s.db.Exec(`UPDATE runs SET status='error', error=?, finished_at=? WHERE id=? AND status='running'`, reason, now, p.runID)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			continue
		}
		if err := s.logUnlocked(p.botID, "run_finished", map[string]any{
			"run_id": p.runID, "status": "error", "error": reason,
		}); err != nil {
			return err
		}
	}
	_, err = s.db.Exec(`UPDATE bots SET status='idle', updated_at=? WHERE status='running'`, now)
	return err
}

// AddRunTool records one tool call made by a run.
func (s *Store) AddRunTool(runID, botID string, rec ToolRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(rec.Arguments) == 0 {
		rec.Arguments = json.RawMessage(`{}`)
	}
	ok := 0
	if rec.OK {
		ok = 1
	}
	if rec.Kind == "" {
		rec.Kind = "call"
	}
	_, err := s.db.Exec(`INSERT INTO run_tools(run_id, bot_id, kind, name, arguments, ok, result, created_at) VALUES(?,?,?,?,?,?,?,?)`,
		runID, botID, rec.Kind, rec.Name, string(rec.Arguments), ok, rec.Result, FormatTime(Now()))
	return err
}

// RunTools returns the tool calls for each listed run, in call order.
// Runs with no calls are absent from the map.
func (s *Store) RunTools(runIDs []string) (map[string][]ToolRecord, error) {
	out := map[string][]ToolRecord{}
	if len(runIDs) == 0 {
		return out, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	q := `SELECT run_id, kind, name, arguments, ok, result, created_at FROM run_tools WHERE run_id IN (?` + strings.Repeat(",?", len(runIDs)-1) + `) ORDER BY id`
	args := make([]any, len(runIDs))
	for i, r := range runIDs {
		args[i] = r
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var runID, argText string
		var ok int
		var rec ToolRecord
		if err := rows.Scan(&runID, &rec.Kind, &rec.Name, &argText, &ok, &rec.Result, &rec.CreatedAt); err != nil {
			return nil, err
		}
		rec.Arguments = json.RawMessage(argText)
		rec.OK = ok == 1
		out[runID] = append(out[runID], rec)
	}
	return out, rows.Err()
}

// SetArchived archives or restores a bot. Archiving keeps every row, stamps
// archived_at, and pauses the bot's enabled timers, marking them so restore
// turns back on only those. Restore schedules them from now, so a timer that
// came due while archived does not fire at once. Unchanged state is a no-op.
func (s *Store) SetArchived(id string, archived bool, by string) (Bot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.getBot(id, false)
	if err != nil {
		return Bot{}, err
	}
	if b.Archived == archived {
		s.attachRun(&b)
		return b, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Bot{}, err
	}
	defer tx.Rollback()
	now := FormatTime(Now())
	if archived {
		if _, err := tx.Exec(`UPDATE bots SET archived_at=?, updated_at=? WHERE id=?`, now, now, id); err != nil {
			return Bot{}, err
		}
		if _, err := tx.Exec(`UPDATE timers SET enabled=0, archive_paused=1 WHERE bot_id=? AND enabled=1`, id); err != nil {
			return Bot{}, err
		}
	} else {
		if _, err := tx.Exec(`UPDATE bots SET archived_at=NULL, updated_at=? WHERE id=?`, now, id); err != nil {
			return Bot{}, err
		}
		rows, err := tx.Query(`SELECT id, schedule FROM timers WHERE bot_id=? AND archive_paused=1`, id)
		if err != nil {
			return Bot{}, err
		}
		type tm struct{ id, schedule string }
		var paused []tm
		for rows.Next() {
			var t tm
			if err := rows.Scan(&t.id, &t.schedule); err != nil {
				rows.Close()
				return Bot{}, err
			}
			paused = append(paused, t)
		}
		rows.Close()
		for _, t := range paused {
			var next time.Time
			if t.schedule == OnceSchedule {
				// A one-shot keeps its time, or fires now if that passed.
				var at string
				if err := tx.QueryRow(`SELECT next_fire_at FROM timers WHERE id=?`, t.id).Scan(&at); err != nil {
					return Bot{}, err
				}
				next = Now()
				if when, err := time.Parse(timeLayout, at); err == nil && when.After(next) {
					next = when
				}
			} else {
				n, err := nextAfter(Now(), t.schedule)
				if err != nil {
					return Bot{}, err
				}
				next = n
			}
			if _, err := tx.Exec(`UPDATE timers SET enabled=1, archive_paused=0, next_fire_at=? WHERE id=?`, FormatTime(next), t.id); err != nil {
				return Bot{}, err
			}
		}
	}
	field := "archived"
	if !archived {
		field = "unarchived"
	}
	if err := s.addLogTx(tx, id, "bot_updated", map[string]any{"fields": []string{field}, "by": by, "bot_id": id, "name": b.Name}); err != nil {
		return Bot{}, err
	}
	if err := tx.Commit(); err != nil {
		return Bot{}, err
	}
	b, err = s.getBot(id, true)
	return b, err
}

// ToolSnapshot returns the hash and JSON snapshot of the tool list the bot
// last saw. Both are empty when the bot has never had one recorded.
func (s *Store) ToolSnapshot(botID string) (hash, snapshot string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var h, sn sql.NullString
	err = s.db.QueryRow(`SELECT tool_hash, tool_snapshot FROM bots WHERE id=?`, botID).Scan(&h, &sn)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return h.String, sn.String, err
}

// SetToolSnapshot records the tool list the bot has now been told about.
func (s *Store) SetToolSnapshot(botID, hash, snapshot string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE bots SET tool_hash=?, tool_snapshot=? WHERE id=?`, hash, snapshot, botID)
	return err
}

// RecentRuns returns the bot's latest runs, newest first.
func (s *Store) RecentRuns(botID string, limit int) ([]Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, bot_id, status, started_at, finished_at, error FROM runs WHERE bot_id=? ORDER BY started_at DESC LIMIT ?`, botID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		var r Run
		var fin, errText sql.NullString
		if err := rows.Scan(&r.ID, &r.BotID, &r.Status, &r.StartedAt, &fin, &errText); err != nil {
			return nil, err
		}
		if fin.Valid {
			r.FinishedAt = &fin.String
		}
		if errText.Valid {
			r.Error = &errText.String
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LastToolNotice returns the newest "Notice: Tools …" line on the bot's
// thread, or nil.
func (s *Store) LastToolNotice(botID string) (*Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(`SELECT id, bot_id, thread, role, content, run_id, created_at FROM messages
		WHERE bot_id=? AND role='system' AND content LIKE 'Notice: Tools %' ORDER BY created_at DESC, id DESC LIMIT 1`, botID)
	m, err := scanMessage(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}
