package github

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxBodyLines is the most lines a write body may contain.
// The approval card shows about eight lines and a cue for the rest.
const MaxBodyLines = 400

// CleanText returns text with CRLF stored as LF, and a reason when it
// cannot be sent. An empty reason means the returned text is acceptable.
// kind is "title", "body", or "comment".
func CleanText(s, kind string) (string, string) {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return s, textIssue(s, kind)
}

// VisibleRunes copies s with refused characters written as ⟦U+XXXX⟧.
func VisibleRunes(s string) string {
	if s == "" || !needsVisible(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, "⟦U+%04X⟧", s[i])
			i++
			continue
		}
		if pullRuneIssue(r, true) != "" {
			fmt.Fprintf(&b, "⟦U+%04X⟧", r)
		} else {
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

func needsVisible(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if pullRuneIssue(r, true) != "" {
			return true
		}
	}
	return false
}

// LooksSecret reports whether s contains a secret-shaped token.
func LooksSecret(s string) bool {
	if strings.Contains(s, "ghp_") || strings.Contains(s, "github_pat_") || strings.Contains(s, "sk-ant-") {
		return true
	}
	return strings.Contains(strings.ToLower(s), "password=")
}

// ExternalLinks lists http(s) URLs in s whose host is not github.com.
// At most eight links are returned, each at most 200 bytes.
func ExternalLinks(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		rest := s[i:]
		httpAt := strings.Index(rest, "http://")
		httpsAt := strings.Index(rest, "https://")
		rel := httpAt
		if httpsAt >= 0 && (rel < 0 || httpsAt < rel) {
			rel = httpsAt
		}
		if rel < 0 {
			break
		}
		start := i + rel
		end := start
		for end < len(s) {
			c := s[end]
			if c <= ' ' || c == ')' || c == ']' || c == '>' || c == '"' || c == '\'' {
				break
			}
			end++
		}
		if end > start {
			raw := s[start:end]
			if len(raw) > 200 {
				raw = raw[:200]
			}
			if externalHost(raw) && !linkSeen(out, raw) && len(out) < 8 {
				out = append(out, raw)
			}
		}
		if end <= i {
			i++
		} else {
			i = end
		}
	}
	return out
}

func linkSeen(out []string, raw string) bool {
	for _, s := range out {
		if s == raw {
			return true
		}
	}
	return false
}

func externalHost(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host != "github.com" && host != "www.github.com"
}

func textIssue(s, kind string) string {
	max := 1 << 16
	allowNL := true
	switch kind {
	case "title":
		max = 256
		allowNL = false
		if strings.TrimSpace(s) == "" {
			return "arguments"
		}
	case "comment":
		if strings.TrimSpace(s) == "" {
			return "arguments"
		}
	}
	if len(s) > max || strings.ContainsRune(s, 0) || !utf8.ValidString(s) {
		return "arguments"
	}
	lines := 0
	if s != "" {
		lines = 1
	}
	for _, r := range s {
		if r == '\n' {
			lines++
		}
		if reason := pullRuneIssue(r, allowNL); reason != "" {
			return reason
		}
	}
	if allowNL && lines > MaxBodyLines {
		return "lines"
	}
	return ""
}

func pullRuneIssue(r rune, allowNL bool) string {
	if r == 0 || r == 0x7f {
		return "arguments"
	}
	if r < 0x20 {
		if allowNL && (r == '\n' || r == '\t') {
			return ""
		}
		return "arguments"
	}
	if isC1Rune(r) || isBidiRune(r) || isZeroWidthRune(r) || isTagRune(r) || isVariationRune(r) || isOtherFormat(r) {
		return "text"
	}
	return ""
}

func isC1Rune(r rune) bool {
	return r >= 0x80 && r <= 0x9f
}

func isBidiRune(r rune) bool {
	if r >= 0x202A && r <= 0x202E {
		return true
	}
	if r >= 0x2066 && r <= 0x2069 {
		return true
	}
	return r == 0x200E || r == 0x200F || r == 0x061C
}

func isZeroWidthRune(r rune) bool {
	if r >= 0x200B && r <= 0x200D {
		return true
	}
	return r == 0x2060 || r == 0xFEFF
}

func isTagRune(r rune) bool {
	return r >= 0xE0000 && r <= 0xE007F
}

func isVariationRune(r rune) bool {
	if r >= 0xFE00 && r <= 0xFE0F {
		return true
	}
	return r >= 0xE0100 && r <= 0xE01EF
}

// isOtherFormat is the format-character backstop. The classes above are
// listed again so this function does not decide them.
func isOtherFormat(r rune) bool {
	if r >= 0x202A && r <= 0x202E || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C {
		return false
	}
	if (r >= 0x200B && r <= 0x200D) || r == 0x2060 || r == 0xFEFF {
		return false
	}
	if r >= 0xE0000 && r <= 0xE007F {
		return false
	}
	return unicode.Is(unicode.Cf, r)
}
