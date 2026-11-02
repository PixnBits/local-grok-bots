package daemon

import "github.com/PixnBits/local-grok-bots/internal/audit"

func redactValue(v any) any {
	return audit.RedactValue(v)
}

// redactLogDetail copies JSON-like log detail and runs audit.RedactText on
// every string leaf. The caller's maps and slices stay as they were. Nil stays
// nil so a missing detail still marshals as null. Keys are kept; only string
// values are rewritten.
func redactLogDetail(v any) any {
	switch t := v.(type) {
	case string:
		return audit.RedactText(t)
	case map[string]any:
		if t == nil {
			return map[string]any(nil)
		}
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = redactLogDetail(val)
		}
		return out
	case map[string]string:
		if t == nil {
			return map[string]string(nil)
		}
		out := make(map[string]string, len(t))
		for k, val := range t {
			out[k] = audit.RedactText(val)
		}
		return out
	case []any:
		if t == nil {
			return []any(nil)
		}
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redactLogDetail(val)
		}
		return out
	case []string:
		if t == nil {
			return []string(nil)
		}
		out := make([]string, len(t))
		for i, val := range t {
			out[i] = audit.RedactText(val)
		}
		return out
	default:
		return v
	}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…(truncated)"
}
