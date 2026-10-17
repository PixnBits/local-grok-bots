// Package permission is the host for CLI tool approvals.
// Pending requests live in memory. A restart drops them, and the call is denied.
package permission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/id"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

const (
	AllowOnce    = "allow_once"
	AllowSession = "allow_session"
	Deny         = "deny"
	Allow        = "allow"
)

var (
	ErrNotFound     = errors.New("unknown permission request")
	ErrMismatch     = errors.New("permission request does not belong to this run")
	ErrSessionGrant = errors.New("session grants are not permitted by policy")
	ErrDecision     = errors.New("decision must be allow_once, deny, or allow_session")
	// ErrDecided means the request was already answered or timed out.
	ErrDecided = errors.New("permission request already decided")
)

// Hook is consulted before policy rules. An empty Decision continues.
// Decision is allow, deny, or ask.
type Hook func(Request) HookResult

// HookResult is one hook's vote. Deny stops the check. Allow does not skip
// deny or ask rules.
type HookResult struct {
	Decision string
	Rule     string
}

// Request is one tool call that needs a decision.
type Request struct {
	ID        string
	RunID     string
	BotID     string
	SessionID string
	Tool      string
	Args      map[string]any
	ToolUseID string
	// Transport is mcp, stream_control, acp, or none. Empty omits the field.
	Transport string
	// Kind is "question" for an interactive question, empty otherwise.
	Kind string
	// Answered is how many questions the user answered. It is recorded
	// only when Kind is question.
	Answered int
	// AuditAnswers is the accepted answer map. Emit redacts it.
	AuditAnswers map[string]string
	// UserRules are durable allow/ask/deny patterns for this bot.
	// Empty leaves behavior unchanged.
	UserRules []UserRule
	// Workspace is the bot directory used to classify paths.
	Workspace string
	// RuleID, Classification, Sensitivity, and Risk are filled when a
	// durable user rule decided the call. Emit copies them onto the audit.
	RuleID         string
	Classification string
	Sensitivity    string
	Risk           string
}

// Outcome is the broker's decision. Behavior is allow or deny, which is the
// Claude permission-prompt-tool contract. Decision is the audit value.
type Outcome struct {
	ID       string
	Behavior string
	Decision string
	Source   string
	Rule     string
	Message  string
	// UpdatedInput replaces the tool input on allow. Nil keeps the original.
	UpdatedInput map[string]any
}

// PublishFunc emits a permission_request or permission_decision event.
type PublishFunc func(runID, event string, payload any)

// Options wires the broker to the daemon.
type Options struct {
	Publish   PublishFunc
	UIPresent func(runID string) bool
	Audit     func(map[string]any)
	Now       func() time.Time
	NewID     func() string
}

// Broker evaluates tool calls and holds UI prompts in memory.
type Broker struct {
	pub       PublishFunc
	uiPresent func(runID string) bool
	audit     func(map[string]any)
	now       func() time.Time
	newID     func() string

	mu      sync.Mutex
	hooks   []Hook
	pending map[string]*wait
	grants  map[string][]string
	// decided remembers answered request ids so a second answer is refused
	// rather than reported as unknown. Entries expire after decidedTTL.
	decided map[string]decidedEntry
}

type decidedEntry struct {
	botID, runID string
	at           time.Time
}

const decidedTTL = 30 * time.Minute

type wait struct {
	id        string
	botID     string
	runID     string
	sessionID string
	tool      string
	subject   string
	sessionOK bool
	kind      string
	questions []Question
	answers   map[string]string
	notes     map[string]map[string]any
	ch        chan string
	once      sync.Once
	// public is the permission_request payload, kept so a page that opens
	// after the request was published can list and answer it.
	public map[string]any
}

// New returns a broker. Nil options are safe.
func New(opts Options) *Broker {
	b := &Broker{
		pub:       opts.Publish,
		uiPresent: opts.UIPresent,
		audit:     opts.Audit,
		now:       opts.Now,
		newID:     opts.NewID,
		pending:   map[string]*wait{},
		decided:   map[string]decidedEntry{},
		grants:    map[string][]string{},
	}
	if b.now == nil {
		b.now = func() time.Time { return time.Now().UTC() }
	}
	if b.newID == nil {
		b.newID = id.New
	}
	return b
}

// AddHook appends a hook. Hooks run in registration order.
func (b *Broker) AddHook(h Hook) {
	if b == nil || h == nil {
		return
	}
	b.mu.Lock()
	b.hooks = append(b.hooks, h)
	b.mu.Unlock()
}

// UserRule is a durable allow, ask, or deny pattern accepted by the user.
// Effect is allow, ask, or deny. Pattern is the broker glob, such as
// Bash(cat *).
type UserRule struct {
	ID      string
	Effect  string
	Pattern string
}

// Evaluate decides a tool call. The order is hooks, managed deny, user deny,
// managed ask, user ask, then AskUserQuestion (always a UI question), then a
// hook allow, bypass mode, managed allow, a user allow that still classifies
// as low-risk read-only, a session grant, and canUseTool. Deny wins over a
// later allow. A user allow never overrides the hard floor.
func (b *Broker) Evaluate(ctx context.Context, pol policy.Permission, req Request) Outcome {
	if ctx == nil {
		ctx = context.Background()
	}
	if req.ID == "" {
		req.ID = b.newID()
	}
	req.Tool = strings.TrimSpace(req.Tool)
	text := argText(req.Args)

	var askRule string
	var allowHook HookResult
	sawAllow := false
	for _, h := range b.hookSnapshot() {
		res := h(req)
		switch strings.ToLower(strings.TrimSpace(res.Decision)) {
		case "deny":
			return b.complete(req, Deny, "hook", res.Rule)
		case "ask":
			if askRule == "" {
				askRule = res.Rule
				if askRule == "" {
					askRule = "hook"
				}
			}
		case "allow":
			if !sawAllow {
				sawAllow = true
				allowHook = res
			}
		}
	}
	if rule := matchRules(pol.Deny, req, text); rule != "" {
		return b.complete(req, Deny, "policy", rule)
	}
	if pattern, id := matchUser(req.UserRules, "deny", req, text); pattern != "" {
		return b.complete(stampUser(req, id, ClassifyCall(req.Tool, req.Args, req.Workspace)), Deny, "user", pattern)
	}
	if rule := matchRules(pol.Ask, req, text); rule != "" && askRule == "" {
		askRule = rule
	}
	if pattern, id := matchUser(req.UserRules, "ask", req, text); pattern != "" && askRule == "" {
		askRule = pattern
		req = stampUser(req, id, ClassifyCall(req.Tool, req.Args, req.Workspace))
	}
	if isInteractiveQuestion(req.Tool) {
		qs, err := parseQuestions(req.Args)
		if err != nil {
			req.Kind = "question"
			out := b.complete(req, Deny, "policy", "malformed")
			out.Message = "AskUserQuestion input is malformed"
			return out
		}
		return b.canUseTool(ctx, pol, req, askRule, qs)
	}
	if askRule != "" {
		return b.canUseTool(ctx, pol, req, askRule, nil)
	}
	if sawAllow {
		rule := allowHook.Rule
		if rule == "" {
			rule = "hook"
		}
		return b.complete(req, Allow, "hook", rule)
	}
	if policy.IsBypassMode(pol.Mode) {
		return b.complete(req, Allow, "policy", pol.Mode)
	}
	if rule := matchRules(pol.Allow, req, text); rule != "" {
		return b.complete(req, Allow, "policy", rule)
	}
	if allowText, ok := userAllowText(req, text); ok {
		if pattern, id := matchUser(req.UserRules, "allow", req, allowText); pattern != "" {
			class := ClassifyCall(req.Tool, req.Args, req.Workspace)
			if class.AutoAllow {
				return b.complete(stampUser(req, id, class), Allow, "user", pattern)
			}
		}
	}
	if b.granted(req) {
		return b.complete(req, Allow, "ui", "session")
	}
	return b.canUseTool(ctx, pol, req, "", nil)
}

// Pending returns copies of the open permission_request payloads for a bot,
// oldest deadline first. An empty botID lists every bot.
func (b *Broker) Pending(botID string) []map[string]any {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []map[string]any{}
	for _, w := range b.pending {
		if botID != "" && w.botID != botID {
			continue
		}
		cp := make(map[string]any, len(w.public))
		for k, v := range w.public {
			cp[k] = v
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		di, _ := out[i]["deadline"].(string)
		dj, _ := out[j]["deadline"].(string)
		if di != dj {
			return di < dj
		}
		ii, _ := out[i]["id"].(string)
		ij, _ := out[j]["id"].(string)
		return ii < ij
	})
	return out
}

// PendingCounts returns how many requests wait on each bot.
func (b *Broker) PendingCounts() map[string]int {
	out := map[string]int{}
	if b == nil {
		return out
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, w := range b.pending {
		out[w.botID]++
	}
	return out
}

// DecideFor records a UI answer. allow_session is refused when the request
// was opened without a managed session-grant policy. An unknown id, or an id
// that belongs to another bot or run, does not allow the tool.
func (b *Broker) DecideFor(botID, runID, reqID, decision string) error {
	if b == nil {
		return ErrNotFound
	}
	decision = strings.TrimSpace(decision)
	switch decision {
	case AllowOnce, Deny, AllowSession:
	default:
		return ErrDecision
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	w := b.pending[reqID]
	if w == nil {
		if d, ok := b.decided[reqID]; ok && d.botID == botID && d.runID == runID {
			return ErrDecided
		}
		return ErrNotFound
	}
	if w.botID != botID || w.runID != runID {
		return ErrMismatch
	}
	if w.kind == "question" && decision != Deny {
		return fmt.Errorf("%w: a question accepts answer or deny", ErrAnswer)
	}
	if decision == AllowSession && !w.sessionOK {
		return ErrSessionGrant
	}
	if !w.resolve(decision) {
		return ErrDecided
	}
	b.markDecidedLocked(w)
	if decision == AllowSession {
		b.rememberLocked(w)
	}
	return nil
}

// Answer records the user's choices for a question request.
// A non-question, a bad answer, or allow_once on a question leaves it pending.
func (b *Broker) Answer(botID, runID, reqID string, answers map[string]string, notes map[string]Note) error {
	if b == nil {
		return ErrNotFound
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	w := b.pending[reqID]
	if w == nil {
		if d, ok := b.decided[reqID]; ok && d.botID == botID && d.runID == runID {
			return ErrDecided
		}
		return ErrNotFound
	}
	if w.botID != botID || w.runID != runID {
		return ErrMismatch
	}
	if w.kind != "question" {
		return fmt.Errorf("%w: not a question", ErrAnswer)
	}
	canon, ann, err := validateAnswers(w.questions, answers, notes)
	if err != nil {
		return err
	}
	w.answers = canon
	w.notes = ann
	if !w.resolve(Answer) {
		return ErrDecided
	}
	b.markDecidedLocked(w)
	return nil
}

// Record emits a decision that was made outside Evaluate, such as a CLI
// permission_denied event. Source is stored as given.
func (b *Broker) Record(req Request, decision, source, rule string) {
	if b == nil {
		return
	}
	if req.ID == "" {
		req.ID = b.newID()
	}
	if decision == "" {
		decision = Deny
	}
	b.emit(req, decision, source, rule)
}

func (b *Broker) canUseTool(ctx context.Context, pol policy.Permission, req Request, rule string, qs []Question) Outcome {
	question := qs != nil
	if question {
		req.Kind = "question"
	}
	timeout := pol.PromptTimeout
	if timeout <= 0 {
		timeout = policy.DefaultPromptTimeout
	}
	// Only ui_prompts = false denies at once. Whether a page is attached
	// right now does not matter: the request stays pending until it is
	// answered, the run ends, or the timeout denies it (fail closed). A page
	// opened later lists it with Pending and answers it.
	if !pol.UIPrompts {
		return b.complete(req, Deny, "no_ui", rule)
	}
	sessionOK := pol.AllowSessionGrants && !question
	w := &wait{
		id:        req.ID,
		botID:     req.BotID,
		runID:     req.RunID,
		sessionID: req.SessionID,
		tool:      req.Tool,
		subject:   grantSubject(req),
		sessionOK: sessionOK,
		kind:      req.Kind,
		questions: qs,
		ch:        make(chan string, 1),
	}
	deadline := b.now().Add(timeout)
	fields := map[string]any{
		"id":              req.ID,
		"run_id":          req.RunID,
		"bot_id":          req.BotID,
		"tool":            req.Tool,
		"arguments":       audit.RedactValue(req.Args),
		"deadline":        deadline.UTC().Format(time.RFC3339Nano),
		"session_allowed": sessionOK,
	}
	if question {
		fields["kind"] = "question"
		fields["questions"] = publicQuestions(qs)
	}
	fields = withTransport(fields, req.Transport)
	w.public = fields
	b.mu.Lock()
	b.pending[req.ID] = w
	b.mu.Unlock()
	b.publish(req.RunID, "permission_request", fields)

	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				b.finishWait(w, "cancel")
			}
		case <-timer.C:
			b.finishWait(w, "timeout")
		}
	}()
	raw := <-w.ch
	decision, source := raw, "ui"
	switch raw {
	case "cancel":
		decision, source = Deny, "cancel"
	case "timeout":
		decision, source = Deny, "timeout"
	}
	if question && decision == Answer {
		req.Answered = len(w.answers)
		req.AuditAnswers = w.answers
	}
	out := b.complete(req, decision, source, rule)
	if decision == Answer {
		out.UpdatedInput = withAnswers(req.Args, w.answers, w.notes)
	}
	return out
}

func (b *Broker) finishWait(w *wait, kind string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !w.resolve(kind) {
		return
	}
	b.markDecidedLocked(w)
}

// markDecidedLocked moves a resolved wait out of pending. Callers hold b.mu.
func (b *Broker) markDecidedLocked(w *wait) {
	delete(b.pending, w.id)
	now := b.now()
	for id, d := range b.decided {
		if now.Sub(d.at) > decidedTTL {
			delete(b.decided, id)
		}
	}
	b.decided[w.id] = decidedEntry{botID: w.botID, runID: w.runID, at: now}
}

func (w *wait) resolve(decision string) bool {
	won := false
	w.once.Do(func() {
		won = true
		w.ch <- decision
	})
	return won
}

func (b *Broker) complete(req Request, decision, source, rule string) Outcome {
	behavior := Deny
	if decision == Allow || decision == AllowOnce || decision == AllowSession || decision == Answer {
		behavior = "allow"
	} else {
		decision = Deny
	}
	b.emit(req, decision, source, rule)
	return Outcome{
		ID:       req.ID,
		Behavior: behavior,
		Decision: decision,
		Source:   source,
		Rule:     rule,
		Message:  questionDenyMessage(req.Tool, behavior, source, rule),
	}
}

func (b *Broker) emit(req Request, decision, source, rule string) {
	when := b.now().UTC().Format(time.RFC3339Nano)
	redacted := audit.RedactValue(req.Args)
	payload := withTransport(map[string]any{
		"id":        req.ID,
		"run_id":    req.RunID,
		"bot_id":    req.BotID,
		"tool":      req.Tool,
		"arguments": redacted,
		"decision":  decision,
		"source":    source,
		"rule":      rule,
		"time":      when,
	}, req.Transport)
	if req.ToolUseID != "" {
		payload["tool_use_id"] = req.ToolUseID
	}
	if req.Kind == "question" {
		payload["kind"] = "question"
		payload["answered"] = req.Answered
	}
	if req.RuleID != "" {
		payload["rule_id"] = req.RuleID
	}
	if req.Classification != "" {
		payload["classification"] = req.Classification
	}
	if req.Sensitivity != "" {
		payload["sensitivity"] = req.Sensitivity
	}
	if req.Risk != "" {
		payload["risk"] = req.Risk
	}
	b.publish(req.RunID, "permission_decision", payload)
	if b.audit == nil {
		return
	}
	raw, err := json.Marshal(redacted)
	if err != nil {
		raw = []byte(`{}`)
	}
	rec := map[string]any{
		"event":      "permission_decision",
		"source":     source,
		"rule":       rule,
		"tool":       req.Tool,
		"arguments":  string(raw),
		"bot_id":     req.BotID,
		"run_id":     req.RunID,
		"time":       when,
		"decision":   decision,
		"request_id": req.ID,
	}
	if req.Kind == "question" {
		rec["kind"] = "question"
		rec["answered"] = req.Answered
		if req.AuditAnswers != nil {
			rec["answers"] = redactAnswers(req.AuditAnswers)
		}
	}
	if req.RuleID != "" {
		rec["rule_id"] = req.RuleID
	}
	if req.Classification != "" {
		rec["classification"] = req.Classification
	}
	if req.Sensitivity != "" {
		rec["sensitivity"] = req.Sensitivity
	}
	if req.Risk != "" {
		rec["risk"] = req.Risk
	}
	b.audit(withTransport(rec, req.Transport))
}

func withTransport(fields map[string]any, transport string) map[string]any {
	if transport != "" {
		fields["transport"] = transport
	}
	return fields
}

func (b *Broker) publish(runID, event string, payload any) {
	if b.pub != nil {
		b.pub(runID, event, payload)
	}
}

func (b *Broker) hookSnapshot() []Hook {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Hook, len(b.hooks))
	copy(out, b.hooks)
	return out
}

func (b *Broker) granted(req Request) bool {
	token := grantToken(req.Tool, grantSubject(req))
	if token == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, have := range b.grants[grantKey(req)] {
		if have == token {
			return true
		}
	}
	return false
}

func (b *Broker) rememberLocked(w *wait) {
	token := grantToken(w.tool, w.subject)
	if token == "" {
		return
	}
	key := grantKey(Request{BotID: w.botID, SessionID: w.sessionID, RunID: w.runID})
	for _, have := range b.grants[key] {
		if have == token {
			return
		}
	}
	b.grants[key] = append(b.grants[key], token)
}

// grantToken is the tool plus the command or path the user approved.
func grantToken(tool, subject string) string {
	tool = strings.ToLower(strings.TrimSpace(tool))
	if tool == "" {
		return ""
	}
	return tool + "\x00" + subject
}

// grantSubject is the trimmed command, the resolved path, url for WebFetch,
// or notebook_path for NotebookEdit. Other tools fall back to canonical JSON
// arguments. Glob and Grep also include the pattern so two patterns do not
// share a grant.
func grantSubject(req Request) string {
	name := strings.ToLower(strings.TrimSpace(req.Tool))
	if name == "bash" {
		return strings.TrimSpace(firstNonEmptyArg(req.Args, "command", "cmd"))
	}
	if name == "webfetch" {
		if u := firstNonEmptyArg(req.Args, "url"); u != "" {
			return strings.TrimSpace(u)
		}
	}
	if name == "notebookedit" {
		if p := firstNonEmptyArg(req.Args, "notebook_path"); p != "" {
			return resolvedGrantPath(p, req.Workspace)
		}
	}
	var parts []string
	if p := firstNonEmptyArg(req.Args, "file_path", "filePath", "path"); p != "" {
		parts = append(parts, resolvedGrantPath(p, req.Workspace))
	}
	if name == "glob" || name == "grep" {
		if pat := firstNonEmptyArg(req.Args, "pattern"); pat != "" {
			parts = append(parts, strings.TrimSpace(pat))
		}
	}
	if name == "grep" {
		if g := firstNonEmptyArg(req.Args, "glob"); g != "" {
			parts = append(parts, strings.TrimSpace(g))
		}
	}
	if len(parts) == 0 {
		if cmd := strings.TrimSpace(firstNonEmptyArg(req.Args, "command", "cmd")); cmd != "" {
			return cmd
		}
		return canonicalArgs(req.Args)
	}
	return strings.Join(parts, "\x00")
}

func canonicalArgs(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	b, err := json.Marshal(args)
	if err != nil {
		return ""
	}
	return string(b)
}

func firstNonEmptyArg(args map[string]any, keys ...string) string {
	for _, key := range keys {
		if s, ok := stringArg(args, key); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// userAllowText drops a Glob allow match when the path or pattern is refused.
func userAllowText(req Request, text string) (string, bool) {
	if strings.EqualFold(strings.TrimSpace(req.Tool), "glob") && !classifyGlobTool(req.Args, req.Workspace).AutoAllow {
		return "", false
	}
	return text, true
}

func grantKey(req Request) string {
	session := req.SessionID
	if session == "" {
		session = req.RunID
	}
	return req.BotID + "\x00" + session
}

func denyMessage(behavior, source, rule string) string {
	if behavior == "allow" {
		return ""
	}
	switch source {
	case "timeout":
		return "permission prompt timed out"
	case "no_ui":
		return "no UI is connected to approve this tool"
	case "cancel":
		return "permission prompt cancelled"
	case "hook":
		if rule != "" {
			return "denied by hook " + rule
		}
		return "denied by hook"
	case "ui":
		return "denied by user"
	case "user":
		if rule != "" {
			return "denied by user rule " + rule
		}
		return "denied by user rule"
	default:
		if rule != "" {
			return "denied by policy rule " + rule
		}
		return "denied by policy"
	}
}
