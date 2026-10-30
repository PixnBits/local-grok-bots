package permbroker

import (
	"path/filepath"
	"strings"
)

// Pattern error reasons. A future rules page can show Reason.
const (
	ReasonTrailingWildcard = "trailing_wildcard"
	ReasonWrapperCommand   = "wrapper_command"
	ReasonFlagPosition     = "flag_position"
	ReasonStarInWord       = "star_in_word"
	ReasonStarFirst        = "star_first"
	ReasonOperator         = "operator"
)

// PatternError is one syntax failure. Reason is a stable token.
type PatternError struct {
	Reason string
}

func (e *PatternError) Error() string {
	if e == nil || e.Reason == "" {
		return "pattern"
	}
	return "pattern: " + e.Reason
}

// patternWitnesses are the argv tokens used to prove a pattern is a
// subset of the original glob. A slash or a flag is included so a
// matcher that accepts either of those cannot convert when the glob
// does not.
var patternWitnesses = []string{
	"x", "HEAD", "aa", "a b", "file.txt", ".", "..",
	"-n", "--flag", "a/b", `a\b`, "", "*",
}

// ValidatePattern is the one syntax check for migration and for a
// future rules page. A star is one whole argv token. It is not a flag,
// not first, and not last. The first token is a literal command and
// is not a wrapper or interpreter.
func ValidatePattern(pattern string) error {
	if strings.TrimSpace(pattern) == "" || patternHasOperator(pattern) {
		return &PatternError{Reason: ReasonOperator}
	}
	words := strings.Fields(pattern)
	if len(words) == 0 {
		return &PatternError{Reason: ReasonOperator}
	}
	if strings.Contains(words[0], "*") {
		return &PatternError{Reason: ReasonStarFirst}
	}
	for _, w := range words {
		if strings.HasPrefix(w, "-") && strings.Contains(w, "*") {
			return &PatternError{Reason: ReasonFlagPosition}
		}
	}
	last := words[len(words)-1]
	if last == "*" || last == "**" {
		return &PatternError{Reason: ReasonTrailingWildcard}
	}
	for _, w := range words {
		if strings.Contains(w, "*") && w != "*" {
			return &PatternError{Reason: ReasonStarInWord}
		}
	}
	if wrapperArgv(patternProbe(words)) {
		return &PatternError{Reason: ReasonWrapperCommand}
	}
	return nil
}

func patternHasOperator(pattern string) bool {
	if strings.ContainsAny(pattern, ";|&<>`$()?[]\n\r") {
		return true
	}
	return strings.Contains(pattern, "$(")
}

func patternProbe(words []string) []string {
	out := make([]string, len(words))
	for i, w := range words {
		if w == "*" {
			out[i] = "x"
			continue
		}
		out[i] = w
	}
	return out
}

// patternMatch is token-for-token. A star matches one argv token that
// is not a flag and does not contain a path separator. The first token
// is compared as written. An invalid pattern does not match.
func patternMatch(pat string, argv []string) bool {
	if ValidatePattern(pat) != nil {
		return false
	}
	words := strings.Fields(pat)
	if len(words) != len(argv) {
		return false
	}
	for i, w := range words {
		if w == "*" {
			if !starTokenOK(argv[i]) {
				return false
			}
			continue
		}
		if argv[i] != w {
			return false
		}
	}
	return true
}

func starTokenOK(tok string) bool {
	if tok == "" || strings.HasPrefix(tok, "-") {
		return false
	}
	return !strings.ContainsAny(tok, `/\`)
}

// patternNarrows reports that every argv the pattern matches, among the
// witness tokens, also matches the original glob. Anything else stays
// legacy. The check is a subset proof, not a widening.
func patternNarrows(glob string, words []string) bool {
	if ValidatePattern(strings.Join(words, " ")) != nil {
		return false
	}
	stars := 0
	for _, w := range words {
		if w == "*" {
			stars++
		}
	}
	if stars > 3 {
		return false
	}
	accepted := 0
	argv := make([]string, 0, len(words))
	var walk func(int) bool
	walk = func(i int) bool {
		if i == len(words) {
			if !patternMatch(strings.Join(words, " "), argv) {
				return true
			}
			accepted++
			ok, err := filepath.Match(glob, strings.Join(argv, " "))
			return err == nil && ok
		}
		if words[i] == "*" {
			for _, w := range patternWitnesses {
				argv = append(argv, w)
				if !walk(i + 1) {
					return false
				}
				argv = argv[:len(argv)-1]
			}
			return true
		}
		argv = append(argv, words[i])
		ok := walk(i + 1)
		argv = argv[:len(argv)-1]
		return ok
	}
	if !walk(0) {
		return false
	}
	return accepted > 0
}
