package github

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxBodyLines is the most lines a write body may contain.
// The approval card shows about eight lines and a cue for the rest.
const MaxBodyLines = 400

// CardCueLines is the number of body lines that fit in the card box.
const CardCueLines = 8

// CardCueBytes is a body length that wraps past the card box.
const CardCueBytes = 480

var (
	secretAWS    = regexp.MustCompile(`(?i)(?:^|[^A-Z0-9])A[KS]IA[0-9A-Z]{16}`)
	secretSlack  = regexp.MustCompile(`(?i)xox[abpr]-`)
	secretPEM    = regexp.MustCompile(`(?i)-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----`)
	secretBearer = regexp.MustCompile(`(?i)bearer\s+\S{8,}`)
	secretAssign = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token)\s*[:=]`)
	secretSK     = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])sk-[a-z0-9]`)
)

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

// CountLines counts newline, line separator, and paragraph separator.
func CountLines(s string) int {
	if s == "" {
		return 0
	}
	n := 1
	for _, r := range s {
		if r == '\n' || isLineSepRune(r) {
			n++
		}
	}
	return n
}

// CardNeedsCue reports whether the approval card should show a scroll cue.
func CardNeedsCue(s string) bool {
	return CountLines(s) > CardCueLines || len(s) > CardCueBytes
}

// LooksSecret reports whether s contains a secret-shaped token.
func LooksSecret(s string) bool {
	if s == "" {
		return false
	}
	lower := strings.ToLower(s)
	for _, p := range []string{"ghp_", "gho_", "ghs_", "ghu_", "ghr_", "github_pat_"} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	if secretSK.FindString(s) != "" || secretAWS.FindString(s) != "" || secretSlack.FindString(s) != "" {
		return true
	}
	if secretPEM.FindString(s) != "" || secretBearer.FindString(s) != "" || secretAssign.FindString(s) != "" {
		return true
	}
	return false
}

// ExternalLinks lists URLs in s whose host is not github.com.
// At most eight links are returned, each at most 200 bytes. Additional
// matches are summarized as "+N more".
func ExternalLinks(s string) []string {
	var out []string
	extra := 0
	for i := 0; i < len(s); {
		start, end := nextLink(s, i)
		if start < 0 {
			break
		}
		raw := s[start:end]
		if len(raw) > 200 {
			raw = raw[:200]
		}
		if externalHost(raw) && !linkSeen(out, raw) {
			if len(out) < 8 {
				out = append(out, raw)
			} else {
				extra++
			}
		}
		if end <= i {
			i++
		} else {
			i = end
		}
	}
	if extra > 0 {
		out = append(out, fmt.Sprintf("+%d more", extra))
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

func nextLink(s string, from int) (int, int) {
	rest := s[from:]
	lower := strings.ToLower(rest)
	rel := -1
	kind := ""
	consider := func(at int, k string) {
		if at < 0 {
			return
		}
		if rel < 0 || at < rel {
			rel = at
			kind = k
		}
	}
	consider(strings.Index(lower, "https://"), "https")
	consider(strings.Index(lower, "http://"), "http")
	consider(indexProtocolRelative(lower), "rel")
	consider(indexWWW(lower), "www")
	if rel < 0 {
		return -1, -1
	}
	start := from + rel
	end := start
	for end < len(s) {
		c := s[end]
		if c <= ' ' || c == ')' || c == ']' || c == '>' || c == '"' || c == '\'' {
			break
		}
		end++
	}
	if kind == "www" && end == start {
		return -1, -1
	}
	if end <= start {
		return start, start + 1
	}
	return start, end
}

func indexProtocolRelative(lower string) int {
	from := 0
	for from < len(lower) {
		at := strings.Index(lower[from:], "//")
		if at < 0 {
			return -1
		}
		at += from
		if at == 0 || lower[at-1] != ':' {
			return at
		}
		from = at + 2
	}
	return -1
}

func indexWWW(lower string) int {
	from := 0
	for from < len(lower) {
		at := strings.Index(lower[from:], "www.")
		if at < 0 {
			return -1
		}
		at += from
		if at == 0 || isWWWBoundary(lower[at-1]) {
			return at
		}
		from = at + 4
	}
	return -1
}

func isWWWBoundary(c byte) bool {
	return c <= ' ' || c == '(' || c == '[' || c == '<' || c == '"' || c == '\''
}

func externalHost(raw string) bool {
	if strings.Contains(raw, `\`) {
		return true
	}
	host := linkHost(raw)
	if host == "" {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host != "github.com" && host != "www.github.com"
}

func linkHost(raw string) string {
	if strings.HasPrefix(strings.ToLower(raw), "www.") {
		raw = "http://" + raw
	} else if strings.HasPrefix(raw, "//") {
		raw = "http:" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
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
	if allowNL && CountLines(s) > MaxBodyLines {
		return "lines"
	}
	for _, r := range s {
		if reason := pullRuneIssue(r, allowNL); reason != "" {
			return reason
		}
	}
	return ""
}

func pullRuneIssue(r rune, allowNL bool) string {
	if r == '\n' || r == '\t' {
		if allowNL {
			return ""
		}
		return "arguments"
	}
	if !refusedRune(r) {
		return ""
	}
	if r < 0x20 || r == 0x7f {
		return "arguments"
	}
	return "text"
}

// refusedRune is the shared check for characters that must not appear in
// bot-supplied GitHub text and must be escaped in fetched titles.
func refusedRune(r rune) bool {
	if r == '\n' || r == '\t' {
		return false
	}
	if r < 0x20 || r == 0x7f || isC1Rune(r) {
		return true
	}
	if isDefaultIgnorable(r) {
		return true
	}
	if isPrivateUseBMP(r) || isPrivateUsePlane(r) {
		return true
	}
	return isLineSepRune(r) || isBrailleBlank(r)
}

func isC1Rune(r rune) bool {
	return r >= 0x80 && r <= 0x9f
}

func isDefaultIgnorable(r rune) bool {
	if unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) {
		return true
	}
	if unicode.Is(unicode.Cf, r) {
		return true
	}
	return unicode.Is(unicode.Variation_Selector, r)
}

func isPrivateUseBMP(r rune) bool {
	return r >= 0xE000 && r <= 0xF8FF
}

func isPrivateUsePlane(r rune) bool {
	return r >= 0xF0000 && r <= 0x10FFFF
}

func isLineSepRune(r rune) bool {
	return r == 0x2028 || r == 0x2029
}

func isBrailleBlank(r rune) bool {
	return r == 0x2800
}
