package permbroker

import (
	"strings"
	"time"
)

// InputError is a rules or pattern request the API rejects with a code.
type InputError struct {
	Code string
	Msg  string
}

func (e *InputError) Error() string {
	if e == nil {
		return "bad request"
	}
	if e.Msg != "" {
		return e.Msg
	}
	return e.Code
}

// RuleDraft is a rule the admin API wants to store or preview.
type RuleDraft struct {
	Kind    string
	Argv    []string
	Pattern string
	Scope   string
	BotID   string
	Effect  string
}

// TaskGrantView is one live task grant.
type TaskGrantView struct {
	BotID    string    `json:"bot_id"`
	Argv     []string  `json:"argv,omitempty"`
	Raw      string    `json:"raw,omitempty"`
	TaskText string    `json:"task_text,omitempty"`
	Expires  time.Time `json:"expires"`
}

// OutcomeView is one finished broker result, newest first.
type OutcomeView struct {
	Time    time.Time `json:"time"`
	BotID   string    `json:"bot_id"`
	Argv    []string  `json:"argv,omitempty"`
	Command string    `json:"command,omitempty"`
	Level   Level     `json:"level"`
	Kind    string    `json:"kind"`
	RuleID  string    `json:"rule_id,omitempty"`
	Parts   int       `json:"parts,omitempty"`
}

// PreviewHit is one recent request scored against a draft rule.
type PreviewHit struct {
	Argv     []string  `json:"argv"`
	Level    Level     `json:"level"`
	Compound bool      `json:"compound"`
	Time     time.Time `json:"time"`
	Outcome  string    `json:"outcome"`
	Reason   string    `json:"reason,omitempty"`
}

// Preview is the pattern preview response.
type Preview struct {
	Requests []PreviewHit   `json:"requests"`
	Summary  map[string]int `json:"summary"`
}

type approvalStamp struct {
	Bot  string
	Hash string
	At   time.Time
}

type ringReq struct {
	Argv     []string
	Level    Level
	Compound bool
	Eligible bool
	Literal  bool
	GitRisk  string
	Time     time.Time
}

// CreateRule stores an exact or pattern rule from the admin API.
// An exact rule refuses shell operators. A pattern uses ValidatePattern.
// An allow pattern still does not cover a critical or compound command
// when it is matched later.
func (e *Engine) CreateRule(d RuleDraft) (Rule, error) {
	if e == nil {
		return Rule{}, ErrScope
	}
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	effect := strings.TrimSpace(d.Effect)
	switch effect {
	case EffectAllow, EffectAsk, EffectDeny:
	default:
		return Rule{}, ErrScope
	}
	scope := strings.TrimSpace(d.Scope)
	if scope != ScopeBot && scope != ScopeGlobal {
		return Rule{}, ErrScope
	}
	bot := strings.TrimSpace(d.BotID)
	if scope == ScopeBot && bot == "" {
		return Rule{}, ErrScope
	}
	if scope == ScopeGlobal {
		bot = ""
	}
	kind := strings.TrimSpace(d.Kind)
	rule := Rule{
		Effect: effect, Tool: ToolShell, Scope: scope, BotID: bot, Source: "api",
	}
	switch kind {
	case "exact", "":
		argv := append([]string(nil), d.Argv...)
		if len(argv) == 0 {
			return Rule{}, ErrScope
		}
		if exactHasOperator(argv) {
			return Rule{}, &InputError{Code: "operators", Msg: "exact rule contains an operator"}
		}
		if hitsCritical(Request{ToolName: ToolShell}, inspected{Argv: argv, Raw: strings.Join(argv, " ")}, e.critical) {
			return Rule{}, ErrScope
		}
		cls := classifyArgv(argv, "", "", nil, e.resolver)
		lvl := maxLevel(e.table.level(ToolShell, argv), cls.Level)
		if cls.Hard || !cls.Eligible || lvl == LevelCritical || cls.Level == LevelCritical {
			return Rule{}, ErrScope
		}
		if !scopeAllowed(lvl, true, false, false, scope) {
			return Rule{}, ErrScope
		}
		rule.Kind = "exact"
		rule.Argv = argv
		return e.commitRule(rule, lvl)
	case "pattern":
		ok, code, msg := PatternStatus(d.Pattern)
		if !ok {
			return Rule{}, &InputError{Code: code, Msg: msg}
		}
		rule.Kind = "pattern"
		rule.Pattern = strings.TrimSpace(d.Pattern)
		return e.commitRule(rule, LevelUnclassified)
	default:
		return Rule{}, ErrScope
	}
}

func exactHasOperator(argv []string) bool {
	for _, a := range argv {
		if strings.ContainsAny(a, ";|&`\n()") || strings.Contains(a, "$(") {
			return true
		}
	}
	return false
}

// ListTaskGrants returns task grants that have not expired.
func (e *Engine) ListTaskGrants() []TaskGrantView {
	if e == nil {
		return []TaskGrantView{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	out := make([]TaskGrantView, 0)
	for _, g := range e.grants {
		if !now.Before(g.Expires) {
			continue
		}
		out = append(out, TaskGrantView{
			BotID: g.BotID, Argv: redactArgv(g.Argv), Raw: Redact(g.Raw),
			TaskText: g.TaskText, Expires: g.Expires,
		})
	}
	return out
}

// Recent returns the newest finished outcomes, up to 50.
func (e *Engine) Recent() []OutcomeView {
	if e == nil {
		return []OutcomeView{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.outcomes) == 0 {
		return []OutcomeView{}
	}
	out := append([]OutcomeView(nil), e.outcomes...)
	return out
}

// Preview scores the recent requests in scope against a draft rule.
func (e *Engine) Preview(d RuleDraft) (Preview, error) {
	if e == nil {
		return Preview{}, ErrScope
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	effect := strings.TrimSpace(d.Effect)
	switch effect {
	case EffectAllow, EffectAsk, EffectDeny:
	default:
		return Preview{}, ErrScope
	}
	kind := strings.TrimSpace(d.Kind)
	if kind == "" {
		kind = "exact"
	}
	if kind != "exact" && kind != "pattern" {
		return Preview{}, ErrScope
	}
	if kind == "pattern" {
		if ok, code, msg := PatternStatus(d.Pattern); !ok {
			return Preview{}, &InputError{Code: code, Msg: msg}
		}
	}
	rows := e.previewRows(strings.TrimSpace(d.Scope), strings.TrimSpace(d.BotID))
	hits := make([]PreviewHit, 0, len(rows))
	summary := map[string]int{
		"would_allow": 0, "would_ask": 0, "would_deny": 0,
		"still_asks_compound": 0, "still_asks_critical": 0, "no_match": 0,
	}
	for _, row := range rows {
		outcome, reason := previewScore(kind, effect, d.Pattern, d.Argv, row)
		summary[outcome]++
		hits = append(hits, PreviewHit{
			Argv: row.Argv, Level: row.Level, Compound: row.Compound,
			Time: row.Time, Outcome: outcome, Reason: reason,
		})
	}
	return Preview{Requests: hits, Summary: summary}, nil
}

func (e *Engine) previewRows(scope, bot string) []ringReq {
	var rows []ringReq
	if scope == ScopeGlobal {
		for _, list := range e.reqRing {
			rows = append(rows, list...)
		}
	} else {
		rows = append(rows, e.reqRing[bot]...)
	}
	// Newest first. The ring is already capped per bot; global is capped here.
	for i := 1; i < len(rows); i++ {
		j := i
		for j > 0 && rows[j].Time.After(rows[j-1].Time) {
			rows[j], rows[j-1] = rows[j-1], rows[j]
			j--
		}
	}
	if len(rows) > 50 {
		rows = rows[:50]
	}
	return rows
}

func previewScore(kind, effect, pattern string, argv []string, row ringReq) (string, string) {
	matched, reason := previewMatch(kind, pattern, argv, row.Argv)
	if !matched {
		return "no_match", reason
	}
	switch effect {
	case EffectDeny:
		return "would_deny", ""
	case EffectAsk:
		return "would_ask", ""
	default:
		if row.Level == LevelCritical {
			return "still_asks_critical", ""
		}
		if row.Compound {
			return "still_asks_compound", ""
		}
		if !row.Literal || !row.Eligible || row.GitRisk != "" {
			return "would_ask", ""
		}
		return "would_allow", ""
	}
}

func previewMatch(kind, pattern string, ruleArgv, argv []string) (bool, string) {
	if kind == "pattern" {
		return previewPattern(pattern, argv)
	}
	if len(argv) == len(ruleArgv) && argvEqual(ruleArgv, argv) {
		return true, ""
	}
	if len(argv) > len(ruleArgv) && len(ruleArgv) > 0 && argvEqual(ruleArgv, argv[:len(ruleArgv)]) {
		return false, "extra_word"
	}
	if len(argv) < len(ruleArgv) && len(argv) > 0 && argvEqual(argv, ruleArgv[:len(argv)]) {
		return false, "missing_word"
	}
	return false, ""
}

func previewPattern(pattern string, argv []string) (bool, string) {
	if patternMatch(pattern, argv) {
		return true, ""
	}
	words := strings.Fields(pattern)
	if len(words) == len(argv) && len(words) > 0 {
		starFlag := false
		aligned := true
		for i, w := range words {
			if w == "*" {
				if strings.HasPrefix(argv[i], "-") {
					starFlag = true
					continue
				}
				if !starTokenOK(argv[i]) {
					aligned = false
				}
				continue
			}
			if argv[i] != w {
				aligned = false
			}
		}
		if aligned && starFlag {
			return false, "flag_in_star"
		}
	}
	if len(argv) > len(words) && len(words) > 0 && patternCovers(words, argv[:len(words)]) {
		return false, "extra_word"
	}
	if len(argv) < len(words) && len(argv) > 0 && patternCovers(words[:len(argv)], argv) {
		return false, "missing_word"
	}
	return false, ""
}

func patternCovers(words, argv []string) bool {
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

func (e *Engine) noteRequest(req Request, in inspected) {
	bot := strings.TrimSpace(req.BotID)
	if bot == "" {
		return
	}
	if e.reqRing == nil {
		e.reqRing = map[string][]ringReq{}
	}
	argv := redactArgv(in.Argv)
	if len(argv) == 0 && in.Raw != "" {
		argv = redactArgv(strings.Fields(in.Raw))
	}
	row := ringReq{
		Argv: argv, Level: in.Level, Compound: in.Compound,
		Eligible: in.Eligible, Literal: in.Literal, GitRisk: in.GitRisk,
		Time: e.now(),
	}
	rows := append(e.reqRing[bot], row)
	if len(rows) > 50 {
		rows = rows[len(rows)-50:]
	}
	e.reqRing[bot] = rows
}

func (e *Engine) noteOutcome(req Request, in inspected, verdict, reason, pendingID, ruleID string) {
	if pendingID != "" || strings.HasPrefix(reason, "pending approval") {
		return
	}
	kind := ""
	parts := 0
	switch {
	case verdict == VerdictAllow && strings.HasPrefix(reason, "allowed by rule"):
		kind = "allowed_by_rule"
	case verdict == VerdictAllow && strings.Contains(reason, "task"):
		kind = "allowed_by_task_grant"
		parts = len(in.Parts)
		if parts == 0 {
			parts = 1
		}
	case verdict == VerdictDeny && strings.HasPrefix(reason, "denied by rule"):
		kind = "denied_by_rule"
	default:
		return
	}
	e.pushOutcome(outcomeFrom(req, in, kind, ruleID, parts))
}

func outcomeFrom(req Request, in inspected, kind, ruleID string, parts int) OutcomeView {
	return OutcomeView{
		Time: time.Time{}, BotID: req.BotID, Argv: redactArgv(in.Argv),
		Command: clip(Redact(in.Raw), 300), Level: in.Level, Kind: kind,
		RuleID: ruleID, Parts: parts,
	}
}

func itemOutcome(item *pendingItem, kind, ruleID string, parts int) OutcomeView {
	if item == nil {
		return OutcomeView{Kind: kind}
	}
	return OutcomeView{
		BotID: item.BotID, Argv: redactArgv(item.Argv),
		Command: clip(Redact(item.Raw), 300), Level: item.Level, Kind: kind,
		RuleID: ruleID, Parts: parts,
	}
}

func (e *Engine) pushOutcome(row OutcomeView) {
	if row.Time.IsZero() {
		row.Time = e.now()
	}
	e.outcomes = append([]OutcomeView{row}, e.outcomes...)
	if len(e.outcomes) > 50 {
		e.outcomes = e.outcomes[:50]
	}
}
