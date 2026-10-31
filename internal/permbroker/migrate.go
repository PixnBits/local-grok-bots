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
// command becomes an exact rule. A glob becomes a pattern only when the
// pattern syntax accepts it and every argv that pattern matches also
// matched the original glob. Anything else is kept as a legacy record.
// A legacy or pattern allow never covers a critical command, a compound,
// or a wrapper.
// A legacy or pattern allow is stored inactive until an admin confirms
// it. An exact command stays active. The call is idempotent, bumps the
// ruleset once, and does not remove the caller's copy of the rules.
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
	if effect == EffectAllow && (kind == "legacy" || kind == "pattern") {
		active := false
		rule.Active = &active
		rule.NeedsConfirm = true
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
	fields := strings.Fields(inner)
	if ValidatePattern(inner) == nil && patternNarrows(inner, fields) {
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

func legacyMatch(pat, raw string) bool {
	raw = strings.TrimSpace(raw)
	if pat == "" || raw == "" {
		return false
	}
	ok, err := filepath.Match(pat, raw)
	return err == nil && ok
}

func storedKind(rule *Rule) string {
	kind := rule.Kind
	if kind == "" {
		kind = "exact"
	}
	if kind == "pattern" && ValidatePattern(rule.Pattern) != nil {
		return "legacy"
	}
	return kind
}

func allowActive(rule *Rule) bool {
	if rule == nil || rule.NeedsConfirm {
		return false
	}
	return rule.Active == nil || *rule.Active
}

// legacySlashMatch is the matcher for a legacy deny or ask. Its star may
// cross a slash. A legacy allow keeps legacyMatch.
func legacySlashMatch(pat, raw string) bool {
	raw = strings.TrimSpace(raw)
	if pat == "" || raw == "" {
		return false
	}
	pat = strings.ReplaceAll(pat, "/", "\x00")
	raw = strings.ReplaceAll(raw, "/", "\x00")
	ok, err := filepath.Match(pat, raw)
	return err == nil && ok
}

func ruleHit(rule *Rule, in inspected, forDeny bool) bool {
	if rule == nil || normTool(rule.Tool) != ToolShell {
		return false
	}
	if rule.Effect == EffectAllow && !allowActive(rule) {
		return false
	}
	switch storedKind(rule) {
	case "exact":
		if !forDeny && (!in.Eligible || in.Compound) {
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
		if rule.Effect == EffectAllow {
			return legacyAllowMatch(rule.Pattern, in.Raw)
		}
		if legacySlashMatch(rule.Pattern, in.Raw) {
			return true
		}
		for _, p := range in.Parts {
			if legacySlashMatch(rule.Pattern, p.Raw) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// legacyAllowMatch keeps a legacy allow inside the original glob and
// refuses a longer argv than the glob's word count.
func legacyAllowMatch(pat, raw string) bool {
	if !legacyMatch(pat, raw) {
		return false
	}
	return len(strings.Fields(raw)) <= len(strings.Fields(pat))
}

func allowFlex(in inspected) bool {
	if !commandMayAllow(in) {
		return false
	}
	return !wrapperArgv(in.Argv)
}
