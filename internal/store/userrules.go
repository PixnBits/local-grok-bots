package store

import (
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/id"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

// UserPermRule is one durable allow, ask, or deny pattern for a bot.
type UserPermRule struct {
	ID             string `json:"id"`
	BotID          string `json:"bot_id"`
	Effect         string `json:"effect"`
	Pattern        string `json:"pattern"`
	Classification string `json:"classification"`
	Sensitivity    string `json:"sensitivity"`
	Risk           string `json:"risk"`
	Reason         string `json:"reason"`
	CreatedAt      string `json:"created_at"`
}

// PermSuggestion is a candidate rule that is not applied until accepted.
type PermSuggestion struct {
	ID             string   `json:"id"`
	BotID          string   `json:"bot_id"`
	Pattern        string   `json:"pattern"`
	Effect         string   `json:"effect"`
	Classification string   `json:"classification"`
	Sensitivity    string   `json:"sensitivity"`
	Risk           string   `json:"risk"`
	Count          int      `json:"count"`
	Examples       []string `json:"examples"`
	Summary        string   `json:"summary"`
	Status         string   `json:"status"`
	CreatedAt      string   `json:"created_at"`
	DecidedAt      string   `json:"decided_at,omitempty"`
}

// PermSample is one stored permission decision used by the analyser.
type PermSample struct {
	Tool      string
	Arguments json.RawMessage
	CreatedAt string
}

// InsertUserPermRule stores an active rule. A live duplicate for the same
// bot, effect, and pattern returns ErrConflict.
func (s *Store) InsertUserPermRule(rule UserPermRule) (UserPermRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rule.Pattern = canonicalPattern(rule.Pattern)
	taken, err := rulePatternTaken(s.db, rule.BotID, rule.Effect, rule.Pattern)
	if err != nil {
		return UserPermRule{}, err
	}
	if taken {
		return UserPermRule{}, ErrConflict
	}
	if rule.ID == "" {
		rule.ID = id.New()
	}
	rule.CreatedAt = FormatTime(Now())
	_, err = s.db.Exec(`INSERT INTO user_perm_rules(id, bot_id, effect, pattern, classification, sensitivity, risk, reason, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		rule.ID, rule.BotID, rule.Effect, rule.Pattern, rule.Classification, rule.Sensitivity, rule.Risk, rule.Reason, rule.CreatedAt)
	if err != nil {
		return UserPermRule{}, err
	}
	return rule, nil
}

// ListUserPermRules returns active rules, oldest first.
func (s *Store) ListUserPermRules(botID string) ([]UserPermRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return listUserPermRules(s.db, botID)
}

type ruleQuery interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
	Exec(query string, args ...any) (sql.Result, error)
}

func canonicalPattern(pattern string) string {
	if c, err := policy.CanonicalRule(pattern); err == nil {
		return c
	}
	return strings.TrimSpace(pattern)
}

func sameCanonicalPattern(a, b string) bool {
	return canonicalPattern(a) == canonicalPattern(b)
}

// rulePatternTaken reports a live rule with the same bot, effect, and
// canonical pattern. Whitespace-only differences are the same rule.
func rulePatternTaken(q ruleQuery, botID, effect, pattern string) (bool, error) {
	rows, err := listUserPermRules(q, botID)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if !strings.EqualFold(row.Effect, effect) {
			continue
		}
		if sameCanonicalPattern(row.Pattern, pattern) {
			return true, nil
		}
	}
	return false, nil
}

func findSuggestion(q ruleQuery, botID, pattern string) (id, status string, err error) {
	rows, err := q.Query(`SELECT id, pattern, status FROM perm_suggestions WHERE bot_id=? ORDER BY created_at DESC, id`, botID)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()
	for rows.Next() {
		var rowID, rowPattern, rowStatus string
		if err := rows.Scan(&rowID, &rowPattern, &rowStatus); err != nil {
			return "", "", err
		}
		if sameCanonicalPattern(rowPattern, pattern) {
			return rowID, rowStatus, nil
		}
	}
	if err := rows.Err(); err != nil {
		return "", "", err
	}
	return "", "", sql.ErrNoRows
}

func listUserPermRules(q ruleQuery, botID string) ([]UserPermRule, error) {
	rows, err := q.Query(`SELECT id, bot_id, effect, pattern, classification, sensitivity, risk, reason, created_at FROM user_perm_rules WHERE bot_id=? AND revoked_at IS NULL ORDER BY created_at, id`, botID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserPermRule{}
	for rows.Next() {
		var r UserPermRule
		if err := rows.Scan(&r.ID, &r.BotID, &r.Effect, &r.Pattern, &r.Classification, &r.Sensitivity, &r.Risk, &r.Reason, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AcceptUserPermRule inserts the rule and audit row, then runs write before
// commit. A write error rolls the database back.
func (s *Store) AcceptUserPermRule(rule UserPermRule, audit any, write func([]UserPermRule) error) (UserPermRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return UserPermRule{}, err
	}
	defer tx.Rollback()
	rule.Pattern = canonicalPattern(rule.Pattern)
	taken, err := rulePatternTaken(tx, rule.BotID, rule.Effect, rule.Pattern)
	if err != nil {
		return UserPermRule{}, err
	}
	if taken {
		return UserPermRule{}, ErrConflict
	}
	if rule.ID == "" {
		rule.ID = id.New()
	}
	if m, ok := audit.(map[string]any); ok && m != nil {
		if _, exists := m["id"]; !exists {
			m["id"] = rule.ID
		}
		if _, exists := m["action"]; !exists {
			m["action"] = "accept"
		}
	}
	rule.CreatedAt = FormatTime(Now())
	_, err = tx.Exec(`INSERT INTO user_perm_rules(id, bot_id, effect, pattern, classification, sensitivity, risk, reason, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		rule.ID, rule.BotID, rule.Effect, rule.Pattern, rule.Classification, rule.Sensitivity, rule.Risk, rule.Reason, rule.CreatedAt)
	if err != nil {
		return UserPermRule{}, err
	}
	if err := s.addLogTx(tx, rule.BotID, "user_perm_rule", audit); err != nil {
		return UserPermRule{}, err
	}
	rows, err := listUserPermRules(tx, rule.BotID)
	if err != nil {
		return UserPermRule{}, err
	}
	if write != nil {
		if err := write(rows); err != nil {
			return UserPermRule{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return UserPermRule{}, err
	}
	return rule, nil
}

// RevokeUserPermRuleApply marks the rule revoked and writes the audit row,
// then runs write before commit. A write error rolls the database back.
func (s *Store) RevokeUserPermRuleApply(botID, id string, audit any, write func([]UserPermRule) error) (UserPermRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return UserPermRule{}, err
	}
	defer tx.Rollback()
	var r UserPermRule
	err = tx.QueryRow(`SELECT id, bot_id, effect, pattern, classification, sensitivity, risk, reason, created_at FROM user_perm_rules WHERE id=? AND bot_id=? AND revoked_at IS NULL`, id, botID).
		Scan(&r.ID, &r.BotID, &r.Effect, &r.Pattern, &r.Classification, &r.Sensitivity, &r.Risk, &r.Reason, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return UserPermRule{}, ErrNotFound
	}
	if err != nil {
		return UserPermRule{}, err
	}
	now := FormatTime(Now())
	if _, err := tx.Exec(`UPDATE user_perm_rules SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, now, id); err != nil {
		return UserPermRule{}, err
	}
	if audit == nil {
		audit = map[string]any{"action": "revoke", "id": r.ID, "effect": r.Effect, "pattern": r.Pattern, "risk": r.Risk}
	}
	if err := s.addLogTx(tx, botID, "user_perm_rule", audit); err != nil {
		return UserPermRule{}, err
	}
	rows, err := listUserPermRules(tx, botID)
	if err != nil {
		return UserPermRule{}, err
	}
	if write != nil {
		if err := write(rows); err != nil {
			return UserPermRule{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return UserPermRule{}, err
	}
	return r, nil
}

// RevokeUserPermRule marks a rule revoked. A missing or already revoked row
// is ErrNotFound.
func (s *Store) RevokeUserPermRule(botID, id string) (UserPermRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var r UserPermRule
	err := s.db.QueryRow(`SELECT id, bot_id, effect, pattern, classification, sensitivity, risk, reason, created_at FROM user_perm_rules WHERE id=? AND bot_id=? AND revoked_at IS NULL`, id, botID).
		Scan(&r.ID, &r.BotID, &r.Effect, &r.Pattern, &r.Classification, &r.Sensitivity, &r.Risk, &r.Reason, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return UserPermRule{}, ErrNotFound
	}
	if err != nil {
		return UserPermRule{}, err
	}
	now := FormatTime(Now())
	if _, err := s.db.Exec(`UPDATE user_perm_rules SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, now, id); err != nil {
		return UserPermRule{}, err
	}
	return r, nil
}

// ListPermSamples returns recent permission decisions for a bot, newest first.
func (s *Store) ListPermSamples(botID string, limit int) ([]PermSample, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT name, arguments, created_at FROM run_tools WHERE bot_id=? AND kind='permission' ORDER BY id DESC LIMIT ?`, botID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PermSample{}
	for rows.Next() {
		var sample PermSample
		var args string
		if err := rows.Scan(&sample.Tool, &args, &sample.CreatedAt); err != nil {
			return nil, err
		}
		sample.Arguments = json.RawMessage(args)
		out = append(out, sample)
	}
	return out, rows.Err()
}

// SaveSuggestion inserts or updates a pending or refused card.
// A dismissed or accepted suggestion for the same pattern is left alone.
func (s *Store) SaveSuggestion(sug PermSuggestion) (PermSuggestion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	examples, err := json.Marshal(sug.Examples)
	if err != nil {
		return PermSuggestion{}, err
	}
	if sug.Status == "" {
		sug.Status = "pending"
	}
	sug.Pattern = canonicalPattern(sug.Pattern)
	existingID, status, err := findSuggestion(s.db, sug.BotID, sug.Pattern)
	if err == nil {
		if status == "dismissed" || status == "accepted" {
			sug.ID = existingID
			sug.Status = status
			return sug, nil
		}
		_, err = s.db.Exec(`UPDATE perm_suggestions SET pattern=?, effect=?, classification=?, sensitivity=?, risk=?, count=?, examples=?, summary=?, status=? WHERE id=?`,
			sug.Pattern, sug.Effect, sug.Classification, sug.Sensitivity, sug.Risk, sug.Count, string(examples), sug.Summary, sug.Status, existingID)
		if err != nil {
			return PermSuggestion{}, err
		}
		sug.ID = existingID
		return sug, nil
	}
	if err != sql.ErrNoRows {
		return PermSuggestion{}, err
	}
	sug.ID = id.New()
	sug.CreatedAt = FormatTime(Now())
	_, err = s.db.Exec(`INSERT INTO perm_suggestions(id, bot_id, pattern, effect, classification, sensitivity, risk, count, examples, summary, status, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		sug.ID, sug.BotID, sug.Pattern, sug.Effect, sug.Classification, sug.Sensitivity, sug.Risk, sug.Count, string(examples), sug.Summary, sug.Status, sug.CreatedAt)
	if err != nil {
		return PermSuggestion{}, err
	}
	return sug, nil
}

// ListPermSuggestions returns pending and refused cards, newest first.
func (s *Store) ListPermSuggestions(botID string) ([]PermSuggestion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, bot_id, pattern, effect, classification, sensitivity, risk, count, examples, summary, status, created_at, decided_at FROM perm_suggestions WHERE bot_id=? AND status IN ('pending','refused') ORDER BY created_at DESC, id`, botID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSuggestions(rows)
}

// GetPermSuggestion returns one card for the bot.
func (s *Store) GetPermSuggestion(botID, id string) (PermSuggestion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(`SELECT id, bot_id, pattern, effect, classification, sensitivity, risk, count, examples, summary, status, created_at, decided_at FROM perm_suggestions WHERE bot_id=? AND id=?`, botID, id)
	return scanSuggestion(row)
}

// DecidePermSuggestion sets status to accepted or dismissed.
func (s *Store) DecidePermSuggestion(botID, id, status string) (PermSuggestion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := FormatTime(Now())
	res, err := s.db.Exec(`UPDATE perm_suggestions SET status=?, decided_at=? WHERE bot_id=? AND id=? AND status IN ('pending','refused')`, status, now, botID, id)
	if err != nil {
		return PermSuggestion{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return PermSuggestion{}, ErrNotFound
	}
	row := s.db.QueryRow(`SELECT id, bot_id, pattern, effect, classification, sensitivity, risk, count, examples, summary, status, created_at, decided_at FROM perm_suggestions WHERE id=?`, id)
	return scanSuggestion(row)
}

func scanSuggestions(rows *sql.Rows) ([]PermSuggestion, error) {
	out := []PermSuggestion{}
	for rows.Next() {
		sug, err := scanSuggestion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sug)
	}
	return out, rows.Err()
}

type suggestionScanner interface {
	Scan(...any) error
}

func scanSuggestion(sc suggestionScanner) (PermSuggestion, error) {
	var sug PermSuggestion
	var examples string
	var decided sql.NullString
	if err := sc.Scan(&sug.ID, &sug.BotID, &sug.Pattern, &sug.Effect, &sug.Classification, &sug.Sensitivity, &sug.Risk, &sug.Count, &examples, &sug.Summary, &sug.Status, &sug.CreatedAt, &decided); err != nil {
		if err == sql.ErrNoRows {
			return PermSuggestion{}, ErrNotFound
		}
		return PermSuggestion{}, err
	}
	if decided.Valid {
		sug.DecidedAt = decided.String
	}
	if err := json.Unmarshal([]byte(examples), &sug.Examples); err != nil || sug.Examples == nil {
		sug.Examples = []string{}
	}
	return sug, nil
}
