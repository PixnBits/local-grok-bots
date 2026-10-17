package permission

import (
	"regexp"
	"strings"
)

func matchRules(rules []string, tool, text string) string {
	for _, rule := range rules {
		if ruleMatches(rule, tool, text) {
			return rule
		}
	}
	return ""
}

func ruleMatches(rule, tool, text string) bool {
	name, pattern, scoped := splitRule(rule)
	if !nameMatches(name, tool) {
		return false
	}
	if !scoped {
		return true
	}
	if strings.TrimSpace(text) == "" {
		return false
	}
	// Check the raw text. Trim would drop a trailing newline before the
	// prefix suffix is inspected.
	if prefixSuffixBlocked(pattern, text) {
		return false
	}
	return globMatch(pattern, strings.TrimSpace(text))
}

func splitRule(rule string) (name, pattern string, scoped bool) {
	rule = strings.TrimSpace(rule)
	if !strings.HasSuffix(rule, ")") {
		return rule, "", false
	}
	i := strings.IndexByte(rule, '(')
	if i <= 0 {
		return rule, "", false
	}
	return strings.TrimSpace(rule[:i]), rule[i+1 : len(rule)-1], true
}

func nameMatches(pattern, name string) bool {
	if !strings.ContainsAny(pattern, "*?") {
		return strings.EqualFold(pattern, name)
	}
	return globMatchFold(pattern, name)
}

func argText(args map[string]any) string {
	if args == nil {
		return ""
	}
	for _, key := range []string{"command", "cmd", "file_path", "filePath", "path"} {
		if s, ok := args[key].(string); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func globMatch(pattern, value string) bool {
	if prefixSuffixBlocked(pattern, value) {
		return false
	}
	re, err := regexp.Compile(globExpr(pattern, false))
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

// prefixSuffixBlocked refuses a stored prefix rule when the text matched by
// the trailing glob contains a shell separator. A deny pattern with a glob
// in the middle still matches.
func prefixSuffixBlocked(pattern, value string) bool {
	i := strings.IndexAny(pattern, "*?")
	if i < 0 {
		return false
	}
	for _, r := range pattern[i:] {
		if r != '*' && r != '?' {
			return false
		}
	}
	prefix := pattern[:i]
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	suffix := value[len(prefix):]
	for i := 0; i < len(suffix); i++ {
		switch suffix[i] {
		case ';', '|', '&', '`', '$', '(', ')', '<', '>', '\n':
			return true
		}
	}
	return false
}

func globMatchFold(pattern, value string) bool {
	re, err := regexp.Compile(globExpr(pattern, true))
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

func globExpr(pattern string, fold bool) string {
	var b strings.Builder
	if fold {
		b.WriteString("(?i)")
	}
	b.WriteByte('^')
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteByte('$')
	return b.String()
}

func matchUser(rules []UserRule, effect, tool, text string) (pattern, id string) {
	effect = strings.ToLower(effect)
	for _, rule := range rules {
		if strings.ToLower(strings.TrimSpace(rule.Effect)) != effect {
			continue
		}
		if ruleMatches(rule.Pattern, tool, text) {
			pat := rule.Pattern
			if pat == "" {
				pat = rule.ID
			}
			return pat, rule.ID
		}
	}
	return "", ""
}

func stampUser(req Request, id string, class Class) Request {
	req.RuleID = id
	req.Classification = class.Kind
	req.Sensitivity = class.Sensitivity
	req.Risk = class.Risk
	return req
}
