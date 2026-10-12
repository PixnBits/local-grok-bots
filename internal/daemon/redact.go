package daemon

import (
	"fmt"
	"regexp"
)

var secretKeyRe = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_-]?key|authorization|credential|bearer)`)
var secretValRe = regexp.MustCompile(`(?i)\b(?:sk-[a-z0-9]{8,}|ghp_[a-zA-Z0-9]{8,}|github_pat_[a-zA-Z0-9_]{8,}|bearer\s+[a-z0-9\-._~+/]+=*)`)
var secretAssignRe = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_-]?key|authorization|credential|bearer)\s*[:=]\s*\S+`)

// redactText hides token-shaped values and secret assignments in free text.
func redactText(s string) string {
	s = secretAssignRe.ReplaceAllString(s, "$1=[redacted]")
	return secretValRe.ReplaceAllString(s, "[redacted]")
}

func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if secretKeyRe.MatchString(k) {
				out[k] = "[redacted]"
				continue
			}
			out[k] = redactValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = redactValue(t[i])
		}
		return out
	case string:
		return clip(secretValRe.ReplaceAllString(t, "[redacted]"), 500)
	default:
		return clip(fmt.Sprint(t), 500)
	}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…(truncated)"
}
