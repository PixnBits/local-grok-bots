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
	re, err := regexp.Compile(globExpr(pattern, false))
	if err != nil {
		return false
	}
	return re.MatchString(value)
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
