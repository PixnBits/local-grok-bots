// Package audit writes one JSON object per line for CLI start and stop.
// An empty destination writes nothing. Secrets in string fields are redacted.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Logger is the optional audit sink. A nil Logger and a disabled Logger
// both drop events.
type Logger struct {
	mu    sync.Mutex
	w     io.Writer
	close func() error
}

var (
	userinfo    = regexp.MustCompile(`://[^/\s:]+:[^/\s@]+@`)
	secretKV    = regexp.MustCompile(`(?i)\b(XAI_API_KEY|ANTHROPIC_API_KEY|SSH_AUTH_SOCK|AUTHORIZATION|PROXY_AUTHORIZATION)=([^\s]+)`)
	secretKeyRe = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_-]?key|authorization|credential|bearer)`)
	secretValRe = regexp.MustCompile(`(?i)\b(?:sk-[a-z0-9]{8,}|ghp_[a-zA-Z0-9]{8,}|github_pat_[a-zA-Z0-9_]{8,}|bearer\s+[a-z0-9\-._~+/]+=*)`)
)

// Open selects the sink. dest is empty, "stderr", "syslog", or an absolute path.
func Open(dest string) (*Logger, error) {
	switch strings.TrimSpace(dest) {
	case "":
		return &Logger{}, nil
	case "stderr":
		return &Logger{w: os.Stderr}, nil
	case "syslog":
		w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "local-grok-bots")
		if err != nil {
			return nil, fmt.Errorf("audit log: %w", err)
		}
		return &Logger{w: w, close: w.Close}, nil
	default:
		if !filepath.IsAbs(dest) || strings.ContainsAny(dest, "\r\n\x00") {
			return nil, fmt.Errorf("audit log must be stderr, syslog, or an absolute path")
		}
		f, err := os.OpenFile(dest, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("audit log: %w", err)
		}
		return &Logger{w: f, close: f.Close}, nil
	}
}

// Enabled reports whether events are written anywhere.
func (l *Logger) Enabled() bool {
	return l != nil && l.w != nil
}

// Write emits one JSON line. String values are redacted.
func (l *Logger) Write(fields map[string]any) {
	if l == nil || l.w == nil {
		return
	}
	out := make(map[string]any, len(fields)+1)
	for k, v := range fields {
		if s, ok := v.(string); ok {
			v = Redact(s)
		}
		out[k] = v
	}
	if _, ok := out["ts"]; !ok {
		out["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	enc := json.NewEncoder(l.w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(out)
}

// Close closes a file or syslog sink. Stderr is left open.
func (l *Logger) Close() error {
	if l == nil || l.close == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fn := l.close
	l.close = nil
	if fn == nil {
		return nil
	}
	return fn()
}

// Redact hides proxy passwords and known secret assignments.
func Redact(s string) string {
	s = userinfo.ReplaceAllString(s, "://redacted@")
	return secretKV.ReplaceAllString(s, "$1=redacted")
}

// RedactText hides proxy passwords, known assignments, and token-shaped values.
func RedactText(s string) string {
	return secretValRe.ReplaceAllString(Redact(s), "[redacted]")
}

// RedactValue walks a JSON-like value and redacts secret keys and token-shaped
// strings. String leaves are clipped.
func RedactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if secretKeyRe.MatchString(k) {
				out[k] = "[redacted]"
				continue
			}
			out[k] = RedactValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = RedactValue(t[i])
		}
		return out
	case string:
		return clipText(RedactText(t), 500)
	default:
		return clipText(fmt.Sprint(t), 500)
	}
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…(truncated)"
}
