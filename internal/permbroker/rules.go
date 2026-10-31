package permbroker

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const (
	EffectAllow = "allow"
	EffectAsk   = "ask"
	EffectDeny  = "deny"

	ScopeOnce   = "once"
	ScopeTask   = "task"
	ScopeBot    = "bot"
	ScopeGlobal = "global"

	ToolShell = "shell"
)

// Rule is an exact argv match, a pattern, or a migrated legacy record.
// Scope is bot or global. Once and task are grants, not rules.
// Kind is exact, pattern, or legacy. Empty means exact.
type Rule struct {
	ID           string    `json:"id"`
	Effect       string    `json:"effect"`
	Argv         []string  `json:"argv,omitempty"`
	Tool         string    `json:"tool"`
	Scope        string    `json:"scope"`
	BotID        string    `json:"bot_id,omitempty"`
	CreatedFrom  string    `json:"created_from,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	LastUsedAt   time.Time `json:"last_used_at,omitempty"`
	Uses         int       `json:"uses"`
	Kind         string    `json:"kind,omitempty"`
	Pattern      string    `json:"pattern,omitempty"`
	Text         string    `json:"text,omitempty"`
	Source       string    `json:"source,omitempty"`
	Readonly     bool      `json:"readonly,omitempty"`
	Active       *bool     `json:"active,omitempty"`
	NeedsConfirm bool      `json:"needs_confirm,omitempty"`
}

type rulesFile struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}

func loadRules(path string) (rulesFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return rulesFile{}, nil
		}
		return rulesFile{}, err
	}
	if len(bytesTrim(b)) == 0 {
		return rulesFile{}, nil
	}
	var doc rulesFile
	if err := json.Unmarshal(b, &doc); err != nil {
		return rulesFile{}, err
	}
	if doc.Rules == nil {
		doc.Rules = []Rule{}
	}
	return doc, nil
}

func saveRules(path string, doc rulesFile) error {
	if doc.Rules == nil {
		doc.Rules = []Rule{}
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "rules-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return os.Chmod(path, 0o600)
}

func bytesTrim(b []byte) []byte {
	i := 0
	j := len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\t' || b[i] == '\r') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\t' || b[j-1] == '\r') {
		j--
	}
	return b[i:j]
}

// scopeAllowed is the ladder for saving an approval.
// Critical is once only. A compound, a non-eligible command, or a
// command a task grant must not cover is once only when hard is set,
// otherwise once or task. High and unclassified stop at the bot.
// Low and medium may be global. A compound is never a bot or global rule.
func scopeAllowed(level Level, eligible, compound, hard, literal bool, scope string) bool {
	if scope != ScopeOnce && !literal {
		return false
	}
	switch scope {
	case ScopeOnce:
		return true
	case ScopeTask:
		return level != LevelCritical && !hard
	case ScopeBot:
		return eligible && !compound && !hard && level != LevelCritical
	case ScopeGlobal:
		return eligible && !compound && !hard && (level == LevelLow || level == LevelMedium)
	default:
		return false
	}
}

var errBadAudit = errors.New("permission broker audit is unreadable")
