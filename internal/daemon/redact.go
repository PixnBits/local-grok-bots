package daemon

import "github.com/PixnBits/local-grok-bots/internal/audit"

func redactValue(v any) any {
	return audit.RedactValue(v)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…(truncated)"
}
