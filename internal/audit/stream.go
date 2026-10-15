package audit

import "strings"

// Stream withholds a trailing partial secret so a value split across chunks
// is redacted as one piece. Flush releases whatever is still held.
// Push and Flush together match RedactText of the concatenated input.
type Stream struct {
	hold string
}

// Push appends delta and returns text that can no longer grow into a secret.
func (s *Stream) Push(delta string) string {
	if s == nil {
		return RedactText(delta)
	}
	emit, hold := splitHold(s.hold + delta)
	s.hold = hold
	if emit == "" {
		return ""
	}
	return RedactText(emit)
}

// Flush redacts the withheld tail. The stream is empty afterwards.
func (s *Stream) Flush() string {
	if s == nil {
		return ""
	}
	out := RedactText(s.hold)
	s.hold = ""
	return out
}

// A pattern head, and how its body may continue. max < 0 means unbounded.
// An exact max still withholds a full body at the end of the buffer, because
// the next character decides whether the trailing word boundary holds.
type secretPat struct {
	head string
	max  int
	body func(byte) bool
	bear bool
}

var secretPats = []secretPat{
	{"sk-ant-", -1, isAntBody, false},
	{"github_pat_", -1, isGitHubBody, false},
	{"lgbr_", 64, isHexByte, false},
	{"xai-", -1, isAlnumByte, false},
	{"ghp_", -1, isAlnumByte, false},
	{"sk-", -1, isAlnumByte, false},
	{"bearer", -1, nil, true},
}

func splitHold(s string) (emit, hold string) {
	best := 0
	for i := range secretPats {
		p := &secretPats[i]
		if n := properSuffixPrefix(s, p.head); n > best {
			best = n
		}
		from := 0
		for {
			at := indexFold(s, p.head, from)
			if at < 0 {
				break
			}
			if suffixOpen(s[at:]) {
				if n := len(s) - at; n > best {
					best = n
				}
			}
			from = at + 1
		}
	}
	if n := hexSuffixHold(s); n > best {
		best = n
	}
	if best <= 0 || best > len(s) {
		return s, ""
	}
	if best == len(s) {
		return "", s
	}
	return s[:len(s)-best], s[len(s)-best:]
}

func suffixOpen(s string) bool {
	for i := range secretPats {
		p := &secretPats[i]
		if len(s) < len(p.head) && hasPrefixFold(p.head, s) {
			return true
		}
		if !hasPrefixFold(s, p.head) {
			continue
		}
		rest := s[len(p.head):]
		if p.bear {
			if openBearer(rest) {
				return true
			}
			continue
		}
		if openBody(rest, p.body, p.max) {
			return true
		}
	}
	return false
}

// openBody reports whether rest can still grow into a secret of this pattern.
// A character outside the body class before the end closes it. A body longer
// than max cannot be an exact-length token.
func openBody(rest string, class func(byte) bool, max int) bool {
	n := 0
	for n < len(rest) {
		if !class(rest[n]) {
			return false
		}
		n++
		if max >= 0 && n > max {
			return false
		}
	}
	return true
}

func openBearer(rest string) bool {
	if rest == "" {
		return true
	}
	if !isRegexSpace(rest[0]) {
		return false
	}
	i := 0
	for i < len(rest) && isRegexSpace(rest[i]) {
		i++
	}
	if i == len(rest) {
		return true
	}
	saw := false
	for i < len(rest) && isBearerByte(rest[i]) {
		saw = true
		i++
	}
	if i == len(rest) {
		return true
	}
	if !saw || rest[i] != '=' {
		return false
	}
	for i < len(rest) && rest[i] == '=' {
		i++
	}
	return i == len(rest)
}

func properSuffixPrefix(s, head string) int {
	max := len(head) - 1
	if max > len(s) {
		max = len(s)
	}
	best := 0
	for n := 1; n <= max; n++ {
		if strings.EqualFold(s[len(s)-n:], head[:n]) {
			best = n
		}
	}
	return best
}

func indexFold(s, needle string, from int) int {
	if needle == "" || from > len(s) {
		return -1
	}
	if from < 0 {
		from = 0
	}
	for i := from; i+len(needle) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(needle)], needle) {
			return i
		}
	}
	return -1
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// hexSuffixHold withholds a trailing 1..64 hex run that could be an admin token.
// A longer run has no 64-hex word boundary, so it is not a token.
func hexSuffixHold(s string) int {
	i := len(s)
	for i > 0 && isHexByte(s[i-1]) {
		i--
	}
	run := len(s) - i
	if run == 0 || run > 64 {
		return 0
	}
	if i > 0 && isWordByte(s[i-1]) {
		return 0
	}
	return run
}

func isAlnumByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isWordByte(c byte) bool {
	return isAlnumByte(c) || c == '_'
}

func isAntBody(c byte) bool {
	return isAlnumByte(c) || c == '_' || c == '-'
}

func isGitHubBody(c byte) bool {
	return isAlnumByte(c) || c == '_'
}

func isBearerByte(c byte) bool {
	switch c {
	case '-', '.', '_', '~', '+', '/':
		return true
	default:
		return isAlnumByte(c)
	}
}

func isRegexSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\f', '\r':
		return true
	default:
		return false
	}
}
