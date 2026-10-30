package permbroker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// AuditRow is one daemon decision. The hook does not write this file.
// Argv and Input are redacted before they are stored.
type AuditRow struct {
	Time           time.Time `json:"time"`
	BotID          string    `json:"bot_id"`
	SessionID      string    `json:"session_id"`
	RunID          string    `json:"run_id"`
	TaskID         string    `json:"task_id"`
	Tool           string    `json:"tool"`
	Argv           []string  `json:"argv,omitempty"`
	Input          string    `json:"input,omitempty"`
	InputHash      string    `json:"input_hash"`
	Cwd            string    `json:"cwd"`
	Decision       string    `json:"decision"`
	PendingID      string    `json:"pending_id,omitempty"`
	Actor          string    `json:"actor"`
	RuleID         string    `json:"rule_id,omitempty"`
	Level          Level     `json:"level"`
	TableVersion   string    `json:"table_version"`
	RulesetVersion int       `json:"ruleset_version"`
	Classifier     string    `json:"classifier"`
	PeerUID        int       `json:"peer_uid,omitempty"`
	PeerPID        int       `json:"peer_pid,omitempty"`
	PrevHash       string    `json:"prev_hash"`
	Hash           string    `json:"hash"`
}

// Auditor receives a copy of each row after it is appended. The daemon
// uses it to mirror a short record into the shared audit log.
type Auditor interface {
	Record(AuditRow)
}

type fileAudit struct {
	mu   sync.Mutex
	f    *os.File
	prev string
}

func openAudit(path string) (*fileAudit, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	prev, err := lastAuditHash(path)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &fileAudit{f: f, prev: prev}, nil
}

func lastAuditHash(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var row AuditRow
		if err := json.Unmarshal([]byte(line), &row); err != nil || row.Hash == "" {
			return "", errBadAudit
		}
		return row.Hash, nil
	}
	return "", nil
}

func (a *fileAudit) append(row AuditRow) AuditRow {
	if a == nil || a.f == nil {
		row.TableVersion = TableVersion
		return row
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	row.PrevHash = a.prev
	row.Hash = ""
	body, err := json.Marshal(row)
	if err != nil {
		return row
	}
	sum := sha256.Sum256(append([]byte(a.prev), body...))
	row.Hash = hex.EncodeToString(sum[:])
	body, err = json.Marshal(row)
	if err != nil {
		return row
	}
	_, _ = a.f.Write(append(body, '\n'))
	a.prev = row.Hash
	return row
}

func (a *fileAudit) close() {
	if a == nil || a.f == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.f.Close()
	a.f = nil
}

var redactRes = []*regexp.Regexp{
	regexp.MustCompile(`ghp_[A-Za-z0-9]+`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]+`),
	regexp.MustCompile(`gho_[A-Za-z0-9]+`),
	regexp.MustCompile(`(?i)authorization:\s*\S+`),
	regexp.MustCompile(`(?i)bearer\s+\S+`),
	regexp.MustCompile(`sk-[A-Za-z0-9_\-]+`),
	regexp.MustCompile(`xai-[A-Za-z0-9_\-]+`),
	regexp.MustCompile(`lgbr_[A-Za-z0-9_\-]+`),
	regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`),
}

// Redact hides credentials in text the audit file would otherwise keep.
// password= and --token= keep the key and replace the value.
func Redact(s string) string {
	if s == "" {
		return s
	}
	s = passwordRE.ReplaceAllString(s, "${1}[redacted]")
	s = tokenFlagRE.ReplaceAllString(s, "${1}[redacted]")
	s = tokenWordRE.ReplaceAllString(s, "${1}[redacted]")
	for _, re := range redactRes {
		s = re.ReplaceAllString(s, "[redacted]")
	}
	return s
}

var (
	passwordRE  = regexp.MustCompile(`(?i)(password=)[^\s]+`)
	tokenFlagRE = regexp.MustCompile(`(?i)(--token=)\S+`)
	tokenWordRE = regexp.MustCompile(`(?i)(--token\s+)\S+`)
)

func redactArgv(argv []string) []string {
	if len(argv) == 0 {
		return nil
	}
	out := make([]string, len(argv))
	for i, a := range argv {
		out[i] = Redact(a)
	}
	return out
}
