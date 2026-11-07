// Package audit writes one JSON object per line for CLI start and stop.
// An empty destination writes nothing. Secrets in nested values are redacted.
package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
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
// Booleans, numbers, and null are left as themselves. A write error is ignored.
// A nil or disabled logger drops the event.
func (l *Logger) Write(fields map[string]any) {
	_ = l.write(fields)
}

// WriteErr emits one JSON line and returns a write error.
// A nil or disabled logger is an error so a caller can fail closed.
// Close leaves the writer set, so a closed sink fails here.
func (l *Logger) WriteErr(fields map[string]any) error {
	if l == nil || l.w == nil {
		return errors.New("audit disabled")
	}
	return l.write(fields)
}

func (l *Logger) write(fields map[string]any) error {
	if l == nil || l.w == nil {
		return nil
	}
	out, _ := (&walker{}).walk(fields).(map[string]any)
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
	return enc.Encode(out)
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

// maxWalkDepth is the deepest value the walker will enter. Deeper values
// become "[depth]" so a hostile or accidental chain cannot overflow the stack.
const maxWalkDepth = 32

// walkOpts is the per-call redaction mode. clip is the RedactValue string
// limit. detail is the log-row path: no clip, redacted map keys, JSON struct
// conversion, and bool/number/nil values kept under secret-named keys.
type walkOpts struct {
	clip   bool
	detail bool
}

// visit is one map, slice, or pointer on the current walk path.
type visit struct {
	ptr uintptr
	typ reflect.Type
}

// walker is the reflection state for one RedactValue or RedactDetail call.
type walker struct {
	opts  walkOpts
	depth int
	seen  map[visit]struct{}
}

// RedactValue walks a JSON-like value and redacts secret keys and token-shaped
// strings. String leaves are clipped. Booleans, numbers, and null stay their
// own types. error values are redacted as their Error string. []byte is
// returned unchanged. A cycle becomes "[cycle]" and a value deeper than
// maxWalkDepth becomes "[depth]".
func RedactValue(v any) any {
	return (&walker{opts: walkOpts{clip: true}}).walk(v)
}

// RedactDetail copies v and redacts it for a log row. Strings are not clipped.
// Structs, pointers to structs, and other json.Marshaler values are walked
// through encoding/json so tags, omitempty, and MarshalJSON apply. Secret-named
// keys keep bool, number, and nil values. Map key text is redacted too. The
// caller's value is not modified. A cycle becomes "[cycle]" and a value deeper
// than maxWalkDepth becomes "[depth]".
func RedactDetail(v any) any {
	return (&walker{opts: walkOpts{detail: true}}).walk(v)
}

func (w *walker) walk(v any) any {
	if w.depth > maxWalkDepth {
		return "[depth]"
	}
	if v == nil {
		return nil
	}
	// json.Number is a string kind and implements both Marshaler and Stringer.
	// Keep the number type before either of those paths can rewrite it.
	if _, ok := v.(json.Number); ok {
		return v
	}
	if w.opts.detail {
		if raw, ok := v.(json.RawMessage); ok {
			return w.rawMessage(raw)
		}
		// Marshaler before error and Stringer so time.Time stays RFC3339.
		if _, ok := v.(json.Marshaler); ok {
			if isNilPtr(v) {
				return nil
			}
			return w.viaJSON(v)
		}
	}
	switch t := v.(type) {
	case error:
		if isNilPtr(t) {
			return nil
		}
		return finishString(t.Error(), w.opts.clip)
	}
	if w.opts.detail {
		if s, ok := v.(fmt.Stringer); ok && !isNilPtr(v) {
			return finishString(s.String(), false)
		}
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String:
		return finishString(rv.String(), w.opts.clip)
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		return v
	case reflect.Map:
		return w.walkMap(rv)
	case reflect.Slice, reflect.Array:
		return w.walkSeq(rv)
	case reflect.Pointer, reflect.Interface:
		return w.walkPtr(v, rv)
	case reflect.Struct:
		if w.opts.detail {
			return w.viaJSON(v)
		}
		return v
	default:
		return v
	}
}

func (w *walker) walkPtr(v any, rv reflect.Value) any {
	if rv.IsNil() {
		return nil
	}
	if rv.Kind() == reflect.Pointer && w.opts.detail && rv.Elem().Kind() == reflect.Struct {
		return w.viaJSON(v)
	}
	if rv.Kind() == reflect.Pointer {
		pop, cyc := w.push(rv)
		if cyc {
			return "[cycle]"
		}
		defer pop()
	}
	w.depth++
	defer func() { w.depth-- }()
	return w.walk(rv.Elem().Interface())
}

func (w *walker) walkMap(rv reflect.Value) any {
	if rv.IsNil() {
		return map[string]any{}
	}
	pop, cyc := w.push(rv)
	if cyc {
		return "[cycle]"
	}
	defer pop()

	type slot struct {
		orig string
		name string
		val  any
	}
	keys := rv.MapKeys()
	slots := make([]slot, 0, len(keys))
	for _, key := range keys {
		orig := fmt.Sprint(key.Interface())
		name := orig
		if w.opts.detail {
			name = RedactText(orig)
		}
		slots = append(slots, slot{orig: orig, name: name, val: rv.MapIndex(key).Interface()})
	}
	if w.opts.detail {
		sort.Slice(slots, func(i, j int) bool {
			if slots[i].orig != slots[j].orig {
				return slots[i].orig < slots[j].orig
			}
			return slots[i].name < slots[j].name
		})
		taken := make(map[string]struct{}, len(slots))
		for i := range slots {
			name := slots[i].name
			if _, ok := taken[name]; ok {
				for n := 2; ; n++ {
					candidate := slots[i].name + "#" + strconv.Itoa(n)
					if _, exists := taken[candidate]; !exists {
						name = candidate
						break
					}
				}
			}
			taken[name] = struct{}{}
			slots[i].name = name
		}
	}
	out := make(map[string]any, len(slots))
	w.depth++
	defer func() { w.depth-- }()
	for _, sl := range slots {
		out[sl.name] = w.field(sl.name, sl.val)
	}
	return out
}

// field redacts one map value. token_name is a label. Other secret-named keys
// become "[redacted]", except bool, number, and nil on the detail path.
func (w *walker) field(key string, val any) any {
	if key == "token_name" {
		if s, ok := val.(string); ok {
			return s
		}
	}
	// A body digest is 64 hex characters, which is also the shape of an
	// admin token. Keep that one field when the value is exactly that shape.
	if key == "body_sha256" {
		if s, ok := val.(string); ok && sha256Hex(s) {
			return s
		}
	}
	if secretKeyRe.MatchString(key) {
		if w.opts.detail && scalarSecretValue(val) {
			return val
		}
		return "[redacted]"
	}
	return w.walk(val)
}

func (w *walker) walkSeq(rv reflect.Value) any {
	if rv.Type().Elem().Kind() == reflect.Uint8 {
		if !w.opts.detail {
			return rv.Interface()
		}
		return redactBytes(rv)
	}
	if rv.Kind() == reflect.Slice && rv.IsNil() {
		return []any{}
	}
	if rv.Kind() == reflect.Slice {
		pop, cyc := w.push(rv)
		if cyc {
			return "[cycle]"
		}
		defer pop()
	}
	out := make([]any, rv.Len())
	w.depth++
	defer func() { w.depth-- }()
	for i := 0; i < rv.Len(); i++ {
		out[i] = w.walk(rv.Index(i).Interface())
	}
	return out
}

func (w *walker) viaJSON(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return "[unencodable]"
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var parsed any
	if err := dec.Decode(&parsed); err != nil {
		return "[unencodable]"
	}
	return w.walk(parsed)
}

func (w *walker) rawMessage(raw json.RawMessage) any {
	if !json.Valid(raw) {
		return RedactText(string(raw))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var parsed any
	if err := dec.Decode(&parsed); err != nil {
		return RedactText(string(raw))
	}
	walked := w.walk(parsed)
	b, err := json.Marshal(walked)
	if err != nil {
		return "[unencodable]"
	}
	return json.RawMessage(b)
}

// push records a map, slice, or pointer on the current path. A repeat is a
// cycle. Empty slices are not recorded: they share no elements, and distinct
// empty slices can have the same data pointer.
func (w *walker) push(rv reflect.Value) (func(), bool) {
	if rv.Kind() == reflect.Slice && rv.Len() == 0 {
		return func() {}, false
	}
	id := visit{ptr: rv.Pointer(), typ: rv.Type()}
	if _, ok := w.seen[id]; ok {
		return func() {}, true
	}
	if w.seen == nil {
		w.seen = make(map[visit]struct{})
	}
	w.seen[id] = struct{}{}
	return func() { delete(w.seen, id) }, false
}

func redactBytes(rv reflect.Value) any {
	if rv.Kind() == reflect.Slice {
		if rv.IsNil() {
			return []byte(nil)
		}
		return []byte(RedactText(string(rv.Bytes())))
	}
	b := make([]byte, rv.Len())
	for i := range b {
		b[i] = byte(rv.Index(i).Uint())
	}
	return []byte(RedactText(string(b)))
}

// scalarSecretValue reports values the detail path may keep under a
// secret-named key. A token count is a number; the key text is not the secret.
func scalarSecretValue(v any) bool {
	if v == nil {
		return true
	}
	if _, ok := v.(json.Number); ok {
		return true
	}
	switch reflect.ValueOf(v).Kind() {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		return true
	default:
		return false
	}
}

func sha256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
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
