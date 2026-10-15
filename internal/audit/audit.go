// Package audit writes one JSON object per line for CLI start and stop.
// An empty destination writes nothing. Secrets in nested values are redacted.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"path/filepath"
	"reflect"
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
	// sk-ant- allows hyphen and underscore segments (api03, admin01, oat01).
	// lgbr_ is the per-run token (prefix plus 32 bytes of hex). A bare 64-hex
	// word is the generated admin token and the MCP permission token.
	// Exact-length tokens keep a trailing boundary so a longer hex run is left alone.
	secretValRe = regexp.MustCompile(`(?i)\b(?:` +
		`sk-ant-[a-z0-9_-]{8,}` +
		`|sk-[a-z0-9]{8,}` +
		`|xai-[a-z0-9]{20,}` +
		`|ghp_[a-z0-9]{8,}` +
		`|github_pat_[a-z0-9_]{8,}` +
		`|lgbr_[a-f0-9]{64}\b` +
		`|bearer\s+[a-z0-9\-._~+/]+=*` +
		`|[a-f0-9]{64}\b` +
		`)`)
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

// Write emits one JSON line. Nested maps, slices, and error strings are redacted.
// Booleans, numbers, and null are left as themselves.
func (l *Logger) Write(fields map[string]any) {
	if l == nil || l.w == nil {
		return
	}
	out, _ := redactWalk(fields, false).(map[string]any)
	if out == nil {
		out = map[string]any{}
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
// strings. String leaves are clipped. Booleans, numbers, and null stay their
// own types. error values are redacted as their Error string.
func RedactValue(v any) any {
	return redactWalk(v, true)
}

func redactWalk(v any, clip bool) any {
	if v == nil {
		return nil
	}
	switch t := v.(type) {
	case json.Number:
		return t
	case error:
		if isNilPtr(t) {
			return nil
		}
		return finishString(t.Error(), clip)
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String:
		return finishString(rv.String(), clip)
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		return v
	case reflect.Map:
		if rv.IsNil() {
			return map[string]any{}
		}
		out := make(map[string]any, rv.Len())
		for _, key := range rv.MapKeys() {
			ks := fmt.Sprint(key.Interface())
			if secretKeyRe.MatchString(ks) {
				out[ks] = "[redacted]"
				continue
			}
			out[ks] = redactWalk(rv.MapIndex(key).Interface(), clip)
		}
		return out
	case reflect.Slice, reflect.Array:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			return v
		}
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return []any{}
		}
		out := make([]any, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out[i] = redactWalk(rv.Index(i).Interface(), clip)
		}
		return out
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		return redactWalk(rv.Elem().Interface(), clip)
	default:
		return v
	}
}

func finishString(s string, clip bool) string {
	s = RedactText(s)
	if !clip {
		return s
	}
	return clipText(s, 500)
}

func isNilPtr(v any) bool {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map, reflect.Func, reflect.Chan:
		return rv.IsNil()
	default:
		return false
	}
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…(truncated)"
}
