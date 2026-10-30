package permbroker

import (
	"path/filepath"
	"strings"
	"time"
)

// LegacyRule is one profile rule that predates the broker file.
// Text is the original pattern, such as Bash(git status).
type LegacyRule struct {
	BotID  string
	Effect string
	Text   string
}

// MigrateLegacy copies profile rules into the broker file. An exact
// command becomes an exact rule. A single-word glob with a literal first
// word becomes a pattern. Anything else is kept as a legacy record and
// still applies, but an allow never covers a critical or compound command.
// The call is idempotent, bumps the ruleset once, and does not remove the
// caller's copy of the rules.
func (e *Engine) MigrateLegacy(in []LegacyRule) error {
	if e == nil || len(in) == 0 {
		return nil
	}
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	var add []Rule
	seen := map[string]bool{}
	now := e.now()
	for _, src := range in {
		text := strings.TrimSpace(src.Text)
		effect := strings.TrimSpace(src.Effect)
		bot := strings.TrimSpace(src.BotID)
		if text == "" || bot == "" {
			continue
		}
		switch effect {
		case EffectAllow, EffectAsk, EffectDeny:
		default:
			continue
		}
		key := bot + "\x00" + effect + "\x00" + text
		if seen[key] || e.migratedExists(bot, effect, text) {
			continue
		}
		seen[key] = true
		rule := legacyToRule(bot, effect, text, now)
		rule.ID = newID("r_")
		add = append(add, rule)
	}
	if len(add) == 0 {
		return nil
	}
	next := e.rules
	next.Version++
	next.Rules = append(append([]Rule(nil), e.rules.Rules...), add...)
	if err := saveRules(e.rulesPath, next); err != nil {
		return err
	}
	e.rules = next
	e.dirty = false
	e.invalidateLocked()
	for _, rule := range add {
		e.auditDecision(Request{BotID: rule.BotID}, inspected{
			Eligible: true, Argv: rule.Argv, Raw: rule.Text, ClassNote: "none",
		}, rule.Effect, "migrated", "", "migrated", rule.ID, rule.Scope)
	}
	return nil
}

func (e *Engine) migratedExists(bot, effect, text string) bool {
	for _, rule := range e.rules.Rules {
		if rule.Source == "migrated" && rule.BotID == bot && rule.Effect == effect && rule.Text == text {
			return true
		}
	}
	return false
}

func legacyToRule(bot, effect, text string, now time.Time) Rule {
	kind, tool, argv, pat := classifyLegacy(text)
	rule := Rule{
		Effect:    effect,
		Argv:      argv,
		Tool:      tool,
		Scope:     ScopeBot,
		BotID:     bot,
		CreatedAt: now,
		Kind:      kind,
		Pattern:   pat,
		Text:      text,
		Source:    "migrated",
		Readonly:  kind == "legacy",
	}
	if kind == "exact" {
		rule.Pattern = ""
	}
	return rule
}

func classifyLegacy(text string) (kind, tool string, argv []string, pattern string) {
	name, inner, scoped := splitLegacy(text)
	if !scoped {
		return "legacy", ToolShell, nil, strings.TrimSpace(text)
	}
	if !shellRuleName(name) {
		tool = strings.ToLower(strings.TrimSpace(name))
		if tool == "" {
			tool = ToolShell
		}
		return "legacy", tool, nil, inner
	}
	if legacySyntax(inner) {
		return "legacy", ToolShell, nil, inner
	}
	if !strings.ContainsAny(inner, "*?[") {
		fields := strings.Fields(inner)
		if len(fields) == 0 {
			return "legacy", ToolShell, nil, inner
		}
		return "exact", ToolShell, fields, ""
	}
	if patternSyntax(inner) {
		return "pattern", ToolShell, nil, inner
	}
	return "legacy", ToolShell, nil, inner
}

func splitLegacy(rule string) (name, pattern string, scoped bool) {
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

func shellRuleName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "bash", "shell", "run_shell":
		return true
	default:
		return false
	}
}

func legacySyntax(inner string) bool {
	if strings.ContainsAny(inner, ";|&<>`\n") || strings.Contains(inner, "$(") {
		return true
	}
	return false
}

func patternSyntax(inner string) bool {
	words := strings.Fields(inner)
	if len(words) == 0 {
		return false
	}
	if strings.ContainsAny(words[0], "*?[") {
		return false
	}
	for i, w := range words {
		if w == "**" {
			return i == len(words)-1
		}
		if w == "*" || w == "?" || strings.HasPrefix(w, "[") {
			return false
		}
		if strings.ContainsAny(w, "?[") {
			return false
		}
		if strings.Contains(w, "*") && strings.Trim(w, "*") == "" {
			return false
		}
	}
	return true
}

func patternMatch(pat string, argv []string) bool {
	words := strings.Fields(pat)
	if len(words) == 0 || len(argv) == 0 {
		return false
	}
	if argv[0] != words[0] && baseName(argv[0]) != words[0] {
		return false
	}
	ai := 1
	for wi := 1; wi < len(words); wi++ {
		w := words[wi]
		if w == "**" && wi == len(words)-1 {
			return true
		}
		if ai >= len(argv) {
			return false
		}
		if !wordMatch(w, argv[ai]) {
			return false
		}
		ai++
	}
	return ai == len(argv)
}

func wordMatch(pattern, value string) bool {
	if pattern == value {
		return true
	}
	ok, err := filepath.Match(pattern, value)
	if err == nil && ok {
		return true
	}
	ok, err = filepath.Match(pattern, baseName(value))
	return err == nil && ok
}

func legacyMatch(pat, raw string) bool {
	raw = strings.TrimSpace(raw)
	if pat == "" || raw == "" {
		return false
	}
	ok, err := filepath.Match(pat, raw)
	return err == nil && ok
}

func ruleHit(rule *Rule, in inspected, forDeny bool) bool {
	if rule == nil || normTool(rule.Tool) != ToolShell {
		return false
	}
	kind := rule.Kind
	if kind == "" {
		kind = "exact"
	}
	switch kind {
	case "exact":
		if !in.Eligible && !forDeny {
			return false
		}
		return argvEqual(rule.Argv, in.Argv)
	case "pattern":
		if rule.Effect == EffectAllow && !allowFlex(in) {
			return false
		}
		if patternMatch(rule.Pattern, in.Argv) {
			return true
		}
		if rule.Effect == EffectAllow {
			return false
		}
		for _, p := range in.Parts {
			if patternMatch(rule.Pattern, p.Argv) {
				return true
			}
		}
		return false
	case "legacy":
		if rule.Effect == EffectAllow && !allowFlex(in) {
			return false
		}
		if legacyMatch(rule.Pattern, in.Raw) {
			return true
		}
		if rule.Effect == EffectAllow {
			return false
		}
		for _, p := range in.Parts {
			if legacyMatch(rule.Pattern, p.Raw) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func allowFlex(in inspected) bool {
	return in.Eligible && !in.Compound && in.Level != LevelCritical && in.GitRisk == ""
}
