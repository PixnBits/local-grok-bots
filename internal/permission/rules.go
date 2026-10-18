package permission

import (
	"regexp"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func matchRules(rules []string, req Request, text string) string {
	for _, rule := range rules {
		if ruleMatchesCall(rule, req, text) {
			return rule
		}
	}
	return ""
}

func ruleMatches(rule, tool, text string) bool {
	return ruleMatchesCall(rule, Request{Tool: tool, Args: inferMatchArgs(tool, text)}, text)
}

func inferMatchArgs(tool, text string) map[string]any {
	if isPathTool(tool) {
		return map[string]any{"file_path": text, "path": text}
	}
	return map[string]any{"command": text}
}

func ruleMatchesCall(rule string, req Request, text string) bool {
	if canon, err := policy.CanonicalRule(rule); err == nil {
		rule = canon
	}
	name, pattern, scoped := splitRule(rule)
	if !nameMatches(name, req.Tool) {
		return false
	}
	if !scoped {
		return true
	}
	values := matchValues(req, text)
	if len(values) == 0 {
		return false
	}
	for _, v := range values {
		// Check the raw text. Trim would drop a trailing newline before the
		// prefix suffix is inspected.
		if prefixSuffixBlocked(pattern, v) {
			continue
		}
		if globMatch(pattern, strings.TrimSpace(v)) {
			return true
		}
	}
	return false
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

func matchUser(rules []UserRule, effect string, req Request, text string) (pattern, id string) {
	effect = strings.ToLower(effect)
	for _, rule := range rules {
		if strings.ToLower(strings.TrimSpace(rule.Effect)) != effect {
			continue
		}
		if ruleMatchesCall(rule.Pattern, req, text) {
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
