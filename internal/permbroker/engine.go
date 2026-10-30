package permbroker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	VerdictAllow = "allow"
	VerdictDeny  = "deny"

	// MaxRequest and MaxReply match the hook. One evaluate per connection.
	MaxRequest = 64 * 1024
	MaxReply   = 8 * 1024

	// TaskGrantCap is the longest a task approval stays valid.
	TaskGrantCap = 4 * time.Hour

	// JailSock is the path a future jail would see. Claude is not inside
	// the daemon jail, so the hook is given the host socket path instead.
	JailSock = "/lgb-perm.sock"
)

var (
	ErrStale       = errors.New("pending item is cancelled or stale")
	ErrNotFound    = errors.New("pending item not found")
	ErrScope       = errors.New("scope is not allowed for this command")
	ErrBadDecision = errors.New("decision must be approve or deny")
)

// Request is one tool call. The socket fills BotID, SessionID, RunID,
// and TaskID from the listener and the daemon's active turn. Callers
// inside the daemon pass those fields themselves. Cwd comes from the
// tool call and is part of the one-time token binding.
type Request struct {
	BotID     string
	SessionID string
	RunID     string
	TaskID    string
	Cwd       string
	ToolName  string
	ToolInput json.RawMessage
	ToolUseID string
	PeerUID   int
	PeerPID   int
}

// Decision is what the hook is allowed to see, plus the audit fields.
// Verdict is only allow or deny. An ask is a deny with PendingID set.
type Decision struct {
	Verdict   string
	Reason    string
	PendingID string
	Level     Level
	Actor     string
	RuleID    string
	InputHash string
	Eligible  bool
	Compound  bool
}

// ClassInput is what a classifier may see. It cannot return a verdict.
type ClassInput struct {
	Tool     string
	Argv     []string
	Raw      string
	Cwd      string
	Eligible bool
	Compound bool
	Level    Level
}

// Classifier may only raise a level. The engine ignores a lower level
// and has no method that lets a classifier allow a call.
type Classifier interface {
	Escalate(ctx context.Context, in ClassInput) (Level, string)
}

// NopClassifier is the default. It does not call a model.
type NopClassifier struct{}

func (NopClassifier) Escalate(context.Context, ClassInput) (Level, string) {
	return "", ""
}

// Turn is the daemon's current session for one bot.
type Turn struct {
	Session string
	Run     string
	Task    string
}

type pendingItem struct {
	ID         string
	BotID      string
	SessionID  string
	RunID      string
	TaskID     string
	Cwd        string
	Tool       string
	Argv       []string
	Raw        string
	InputHash  string
	Level      Level
	Eligible   bool
	Compound   bool
	CreatedAt  time.Time
	Ruleset    int
	Classifier string
}

// Pending is the redacted view returned to an admin.
type Pending struct {
	ID        string    `json:"id"`
	BotID     string    `json:"bot_id"`
	SessionID string    `json:"session_id"`
	RunID     string    `json:"run_id"`
	TaskID    string    `json:"task_id"`
	Tool      string    `json:"tool"`
	Argv      []string  `json:"argv,omitempty"`
	Command   string    `json:"command,omitempty"`
	Cwd       string    `json:"cwd"`
	Level     Level     `json:"level"`
	InputHash string    `json:"input_hash"`
	CreatedAt time.Time `json:"created_at"`
	Ruleset   int       `json:"ruleset"`
	Compound  bool      `json:"compound,omitempty"`
}

type token struct {
	BotID     string
	SessionID string
	Hash      string
	Cwd       string
}

type grant struct {
	BotID     string
	SessionID string
	TaskID    string
	Hash      string
	Cwd       string
	Expires   time.Time
}

// Engine decides tool calls and stores rules outside the jail.
type Engine struct {
	mu         sync.Mutex
	dir        string
	rulesPath  string
	rules      rulesFile
	table      table
	audit      *fileAudit
	auditor    Auditor
	classifier Classifier
	now        func() time.Time

	byID   map[string]*pendingItem
	byKey  map[string]string
	denied map[string]struct{}
	dead   map[string]struct{}
	tokens []token
	grants []grant
	active map[string]Turn
}

// Open loads rules and the audit chain from dir. risks are policy
// raises. A lowered shipped level returns ErrLevelLowered.
func Open(dir string, risks []RiskEntry, auditor Auditor) (*Engine, error) {
	if err := ValidateRisk(risks); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	doc, err := loadRules(filepath.Join(dir, "rules.json"))
	if err != nil {
		return nil, err
	}
	aud, err := openAudit(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		return nil, err
	}
	e := &Engine{
		dir:        dir,
		rulesPath:  filepath.Join(dir, "rules.json"),
		rules:      doc,
		table:      table{extra: append([]RiskEntry(nil), risks...)},
		audit:      aud,
		auditor:    auditor,
		classifier: NopClassifier{},
		now:        time.Now,
		byID:       map[string]*pendingItem{},
		byKey:      map[string]string{},
		denied:     map[string]struct{}{},
		dead:       map[string]struct{}{},
		active:     map[string]Turn{},
	}
	return e, nil
}

// Close closes the audit file and every listener the caller stopped
// separately. It does not delete rules.
func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	e.audit.close()
	return nil
}

// SetAuditor installs the daemon mirror. Nil clears it.
func (e *Engine) SetAuditor(a Auditor) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.auditor = a
	e.mu.Unlock()
}

// SetClassifier replaces the stub. A nil classifier restores the no-op.
func (e *Engine) SetClassifier(c Classifier) {
	if e == nil {
		return
	}
	if c == nil {
		c = NopClassifier{}
	}
	e.mu.Lock()
	e.classifier = c
	e.mu.Unlock()
}

// SetRisks replaces policy raises. A lower shipped level is refused and
// the previous table stays.
func (e *Engine) SetRisks(risks []RiskEntry) error {
	if err := ValidateRisk(risks); err != nil {
		return err
	}
	e.mu.Lock()
	e.table.extra = append([]RiskEntry(nil), risks...)
	e.mu.Unlock()
	return nil
}

// Ruleset is the current rules file version.
func (e *Engine) Ruleset() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rules.Version
}

// RuleCount is the number of stored rules.
func (e *Engine) RuleCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.rules.Rules)
}

// NoteTurn records the session the hook must use. A new task id ends
// grants and pending items for the previous task of this session.
func (e *Engine) NoteTurn(bot, session, run, task string) {
	if e == nil || bot == "" || session == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	prev := e.active[bot]
	e.active[bot] = Turn{Session: session, Run: run, Task: task}
	if prev.Session == session && task != "" && prev.Task != "" && prev.Task != task {
		e.dropTaskLocked(bot, session, task)
	}
}

// Active is the turn NoteTurn stored. The socket uses this and ignores
// session_id from the request.
func (e *Engine) Active(bot string) Turn {
	if e == nil {
		return Turn{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.active[bot]
}

// CancelSession drops pending items, tokens, and grants for one session.
func (e *Engine) CancelSession(bot, session string) {
	if e == nil || bot == "" || session == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cancelSessionLocked(bot, session)
	if e.active[bot].Session == session {
		delete(e.active, bot)
	}
}

// CancelBot drops every in-memory decision for the bot.
func (e *Engine) CancelBot(bot string) {
	if e == nil || bot == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cancelSessionLocked(bot, "")
	delete(e.active, bot)
}

func (e *Engine) cancelSessionLocked(bot, session string) {
	for id, item := range e.byID {
		if item.BotID != bot {
			continue
		}
		if session != "" && item.SessionID != session {
			continue
		}
		e.dead[id] = struct{}{}
		delete(e.byID, id)
		delete(e.byKey, collapseKey(item))
	}
	e.tokens = filterTokens(e.tokens, func(t token) bool {
		if t.BotID != bot {
			return true
		}
		return session != "" && t.SessionID != session
	})
	e.grants = filterGrants(e.grants, func(g grant) bool {
		if g.BotID != bot {
			return true
		}
		return session != "" && g.SessionID != session
	})
	for k := range e.denied {
		b, s, ok := splitKey(k)
		if ok && b == bot && (session == "" || s == session) {
			delete(e.denied, k)
		}
	}
}

func (e *Engine) dropTaskLocked(bot, session, keepTask string) {
	for id, item := range e.byID {
		if item.BotID == bot && item.SessionID == session && item.TaskID != "" && item.TaskID != keepTask {
			e.dead[id] = struct{}{}
			delete(e.byID, id)
			delete(e.byKey, collapseKey(item))
		}
	}
	e.grants = filterGrants(e.grants, func(g grant) bool {
		if g.BotID != bot || g.SessionID != session {
			return true
		}
		return g.TaskID == keepTask
	})
}

// Evaluate decides one call. It does not wait for a person.
func (e *Engine) Evaluate(ctx context.Context, req Request) Decision {
	if e == nil {
		return Decision{Verdict: VerdictDeny, Reason: "denied", Actor: "fail-closed"}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	in := e.inspect(ctx, req)
	if strings.TrimSpace(req.BotID) == "" || strings.TrimSpace(req.SessionID) == "" {
		return e.finish(req, in, VerdictDeny, "denied", "", "fail-closed", "")
	}
	if rule := e.match(req.BotID, in, EffectDeny); rule != nil {
		e.touch(rule)
		return e.finish(req, in, VerdictDeny, "denied by rule "+rule.ID, "", rule.ID, rule.ID)
	}
	if e.consumeToken(req, in.Hash) {
		return e.finish(req, in, VerdictAllow, "approved", "", "human", "")
	}
	if in.Level == LevelCritical || !in.Eligible {
		if in.Level != LevelCritical && e.grantCovers(req, in) {
			return e.finish(req, in, VerdictAllow, "allowed for this task", "", "policy", "")
		}
		return e.ask(req, in)
	}
	if rule := e.matchScoped(req.BotID, in, ScopeBot); rule != nil {
		return e.applyRule(req, in, rule)
	}
	if in.Level == LevelLow || in.Level == LevelMedium {
		if rule := e.matchScoped("", in, ScopeGlobal); rule != nil {
			return e.applyRule(req, in, rule)
		}
	}
	if e.grantCovers(req, in) {
		return e.finish(req, in, VerdictAllow, "allowed for this task", "", "policy", "")
	}
	return e.ask(req, in)
}

func (e *Engine) applyRule(req Request, in inspected, rule *Rule) Decision {
	e.touch(rule)
	if rule.Effect == EffectAsk {
		return e.ask(req, in)
	}
	if rule.Effect == EffectAllow {
		return e.finish(req, in, VerdictAllow, "allowed by rule "+rule.ID, "", rule.ID, rule.ID)
	}
	return e.finish(req, in, VerdictDeny, "denied by rule "+rule.ID, "", rule.ID, rule.ID)
}

func (e *Engine) ask(req Request, in inspected) Decision {
	key := collapseKeyReq(req, in)
	if _, ok := e.denied[key]; ok {
		return e.finish(req, in, VerdictDeny, "denied", "", "human", "")
	}
	if id, ok := e.byKey[key]; ok {
		return e.finish(req, in, VerdictDeny, pendingReason(id), id, "policy", "")
	}
	item := &pendingItem{
		ID:         newID("p_"),
		BotID:      req.BotID,
		SessionID:  req.SessionID,
		RunID:      req.RunID,
		TaskID:     req.TaskID,
		Cwd:        req.Cwd,
		Tool:       normTool(req.ToolName),
		Argv:       append([]string(nil), in.Argv...),
		Raw:        in.Raw,
		InputHash:  in.Hash,
		Level:      in.Level,
		Eligible:   in.Eligible,
		Compound:   in.Compound,
		CreatedAt:  e.now(),
		Ruleset:    e.rules.Version,
		Classifier: in.ClassNote,
	}
	e.byID[item.ID] = item
	e.byKey[key] = item.ID
	return e.finish(req, in, VerdictDeny, pendingReason(item.ID), item.ID, "policy", "")
}

func pendingReason(id string) string {
	return "pending approval " + id + "; retry the identical command after approval"
}

// ListPending returns redacted copies of the open items.
func (e *Engine) ListPending() []Pending {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Pending, 0, len(e.byID))
	for _, item := range e.byID {
		out = append(out, pendingView(item))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func pendingView(item *pendingItem) Pending {
	return Pending{
		ID:        item.ID,
		BotID:     item.BotID,
		SessionID: item.SessionID,
		RunID:     item.RunID,
		TaskID:    item.TaskID,
		Tool:      item.Tool,
		Argv:      redactArgv(item.Argv),
		Command:   Redact(item.Raw),
		Cwd:       item.Cwd,
		Level:     item.Level,
		InputHash: item.InputHash,
		CreatedAt: item.CreatedAt,
		Ruleset:   item.Ruleset,
		Compound:  item.Compound,
	}
}

// Decide approves or denies one pending item. Approve does not stop a
// run. Scope is required for approve and ignored for deny.
func (e *Engine) Decide(id, decision, scope string) error {
	if e == nil {
		return ErrNotFound
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, dead := e.dead[id]; dead {
		return ErrStale
	}
	item := e.byID[id]
	if item == nil {
		return ErrNotFound
	}
	if item.Ruleset != e.rules.Version {
		e.bury(item)
		return ErrStale
	}
	switch decision {
	case "deny":
		e.denied[collapseKey(item)] = struct{}{}
		e.bury(item)
		e.auditDecision(Request{BotID: item.BotID, SessionID: item.SessionID, RunID: item.RunID, TaskID: item.TaskID, Cwd: item.Cwd}, inspected{
			Hash: item.InputHash, Level: item.Level, Argv: item.Argv, Raw: item.Raw, ClassNote: item.Classifier,
		}, VerdictDeny, "denied", "", "human", "")
		return nil
	case "approve":
		if !scopeAllowed(item.Level, item.Eligible, item.Compound, scope) {
			return ErrScope
		}
		switch scope {
		case ScopeOnce:
			e.tokens = append(e.tokens, token{BotID: item.BotID, SessionID: item.SessionID, Hash: item.InputHash, Cwd: item.Cwd})
		case ScopeTask:
			e.grants = append(e.grants, grant{
				BotID: item.BotID, SessionID: item.SessionID, TaskID: item.TaskID,
				Hash: item.InputHash, Cwd: item.Cwd, Expires: e.now().Add(TaskGrantCap),
			})
		case ScopeBot, ScopeGlobal:
			if err := e.addRuleLocked(item, scope); err != nil {
				return err
			}
		default:
			return ErrScope
		}
		e.bury(item)
		return nil
	default:
		return ErrBadDecision
	}
}

// DenyAll denies the listed ids. A nil ids slice denies every current
// item. An id that is not current fails the call and changes nothing.
func (e *Engine) DenyAll(ids []string) error {
	if e == nil {
		return ErrNotFound
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var want []string
	if ids == nil {
		for id := range e.byID {
			want = append(want, id)
		}
	} else {
		for _, id := range ids {
			if _, dead := e.dead[id]; dead {
				return ErrStale
			}
			if e.byID[id] == nil {
				return ErrNotFound
			}
			want = append(want, id)
		}
	}
	for _, id := range want {
		item := e.byID[id]
		if item == nil {
			continue
		}
		e.denied[collapseKey(item)] = struct{}{}
		e.bury(item)
	}
	return nil
}

func (e *Engine) bury(item *pendingItem) {
	if item == nil {
		return
	}
	e.dead[item.ID] = struct{}{}
	delete(e.byID, item.ID)
	delete(e.byKey, collapseKey(item))
}

func (e *Engine) addRuleLocked(item *pendingItem, scope string) error {
	rule := Rule{
		ID:          newID("r_"),
		Effect:      EffectAllow,
		Argv:        append([]string(nil), item.Argv...),
		Tool:        ToolShell,
		Scope:       scope,
		CreatedFrom: item.ID,
		CreatedAt:   e.now(),
	}
	if scope == ScopeBot {
		rule.BotID = item.BotID
	}
	next := e.rules
	next.Version++
	next.Rules = append(append([]Rule(nil), e.rules.Rules...), rule)
	if err := saveRules(e.rulesPath, next); err != nil {
		return err
	}
	e.rules = next
	e.invalidateLocked()
	return nil
}

func (e *Engine) touch(rule *Rule) {
	rule.Uses++
	rule.LastUsedAt = e.now()
	_ = saveRules(e.rulesPath, e.rules)
}

func (e *Engine) invalidateLocked() {
	for id, item := range e.byID {
		e.dead[id] = struct{}{}
		delete(e.byID, id)
		delete(e.byKey, collapseKey(item))
	}
	e.tokens = nil
	e.grants = nil
	e.denied = map[string]struct{}{}
}

func (e *Engine) consumeToken(req Request, hash string) bool {
	for i, t := range e.tokens {
		if t.BotID == req.BotID && t.SessionID == req.SessionID && t.Hash == hash && t.Cwd == req.Cwd {
			e.tokens = append(e.tokens[:i], e.tokens[i+1:]...)
			return true
		}
	}
	return false
}

func (e *Engine) grantCovers(req Request, in inspected) bool {
	now := e.now()
	if len(in.Parts) > 0 {
		for _, part := range in.Parts {
			if !e.grantHas(req, part.Hash, now) {
				return false
			}
		}
		return true
	}
	return e.grantHas(req, in.Hash, now)
}

func (e *Engine) grantHas(req Request, hash string, now time.Time) bool {
	for _, g := range e.grants {
		if g.BotID == req.BotID && g.SessionID == req.SessionID && g.TaskID == req.TaskID && g.Hash == hash && g.Cwd == req.Cwd && now.Before(g.Expires) {
			return true
		}
	}
	return false
}

func (e *Engine) match(bot string, in inspected, effect string) *Rule {
	if !in.Eligible {
		return nil
	}
	var found *Rule
	for i := range e.rules.Rules {
		rule := &e.rules.Rules[i]
		if rule.Effect != effect || rule.Tool != ToolShell || !argvEqual(rule.Argv, in.Argv) {
			continue
		}
		if rule.Scope == ScopeGlobal || (rule.Scope == ScopeBot && rule.BotID == bot) {
			found = rule
		}
	}
	return found
}

func (e *Engine) matchScoped(bot string, in inspected, scope string) *Rule {
	if !in.Eligible {
		return nil
	}
	var ask, allow *Rule
	for i := range e.rules.Rules {
		rule := &e.rules.Rules[i]
		if rule.Scope != scope || rule.Tool != ToolShell || !argvEqual(rule.Argv, in.Argv) {
			continue
		}
		if scope == ScopeBot && rule.BotID != bot {
			continue
		}
		switch rule.Effect {
		case EffectAsk:
			ask = rule
		case EffectAllow:
			allow = rule
		}
	}
	if ask != nil {
		return ask
	}
	return allow
}

type inspected struct {
	Eligible  bool
	Compound  bool
	Argv      []string
	Raw       string
	Hash      string
	Level     Level
	Parts     []Part
	ClassNote string
}

func (e *Engine) inspect(ctx context.Context, req Request) inspected {
	in := inspected{}
	if isShellTool(req.ToolName) {
		raw, _ := commandOf(req.ToolInput)
		in.Raw = raw
		parsed := ParseCommand(raw)
		in.Eligible = parsed.Eligible
		in.Compound = parsed.Compound
		in.Argv = parsed.Argv
		in.Parts = parsed.Parts
		if parsed.Eligible {
			in.Hash = hashParts("shell", parsed.Argv)
			in.Level = e.table.level(ToolShell, parsed.Argv)
		} else {
			in.Hash = hashRaw(req.ToolName, raw)
			in.Level = LevelUnclassified
		}
	} else {
		canon, ok := canonicalJSON(req.ToolInput)
		if !ok {
			canon = string(req.ToolInput)
		}
		in.Raw = canon
		in.Hash = hashRaw(req.ToolName, canon)
		in.Level = LevelUnclassified
	}
	if e.classifier == nil {
		e.classifier = NopClassifier{}
	}
	raised, why := e.classifier.Escalate(ctx, ClassInput{
		Tool: req.ToolName, Argv: in.Argv, Raw: in.Raw, Cwd: req.Cwd,
		Eligible: in.Eligible, Compound: in.Compound, Level: in.Level,
	})
	if Rank(raised) > Rank(in.Level) {
		in.Level = raised
		if why == "" {
			why = "escalated"
		}
		in.ClassNote = why
	}
	if in.ClassNote == "" {
		in.ClassNote = "none"
	}
	return in
}

func (e *Engine) finish(req Request, in inspected, verdict, reason, pendingID, actor, ruleID string) Decision {
	if reason == "" {
		reason = "denied"
	}
	e.auditDecision(req, in, verdict, reason, pendingID, actor, ruleID)
	return Decision{
		Verdict: verdict, Reason: reason, PendingID: pendingID,
		Level: in.Level, Actor: actor, RuleID: ruleID, InputHash: in.Hash,
		Eligible: in.Eligible, Compound: in.Compound,
	}
}

func (e *Engine) auditDecision(req Request, in inspected, verdict, reason, pendingID, actor, ruleID string) {
	note := in.ClassNote
	if note == "" {
		note = "none"
	}
	row := AuditRow{
		Time: e.now(), BotID: req.BotID, SessionID: req.SessionID, RunID: req.RunID, TaskID: req.TaskID,
		Tool: normTool(req.ToolName), Argv: redactArgv(in.Argv), Input: clip(Redact(in.Raw), 500),
		InputHash: in.Hash, Cwd: req.Cwd, Decision: verdict, PendingID: pendingID,
		Actor: actor, RuleID: ruleID, Level: in.Level, TableVersion: TableVersion,
		RulesetVersion: e.rules.Version, Classifier: note, PeerUID: req.PeerUID, PeerPID: req.PeerPID,
	}
	row = e.audit.append(row)
	if e.auditor != nil {
		e.auditor.Record(row)
	}
	_ = reason
}

func commandOf(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "", false
	}
	s, _ := obj["command"].(string)
	return s, true
}

func canonicalJSON(raw json.RawMessage) (string, bool) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return "", false
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", false
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return "", false
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func hashParts(kind string, argv []string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, "v1\x00")
	_, _ = io.WriteString(h, kind)
	for _, a := range argv {
		_, _ = h.Write([]byte{0})
		_, _ = io.WriteString(h, a)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashRaw(tool, raw string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, "v1\x00raw\x00")
	_, _ = io.WriteString(h, tool)
	_, _ = h.Write([]byte{0})
	_, _ = io.WriteString(h, raw)
	return hex.EncodeToString(h.Sum(nil))
}

func collapseKey(item *pendingItem) string {
	return strings.Join([]string{item.BotID, item.SessionID, item.TaskID, item.InputHash, item.Cwd, item.Tool}, "\x00")
}

func collapseKeyReq(req Request, in inspected) string {
	return strings.Join([]string{req.BotID, req.SessionID, req.TaskID, in.Hash, req.Cwd, normTool(req.ToolName)}, "\x00")
}

func splitKey(k string) (bot, session string, ok bool) {
	parts := strings.Split(k, "\x00")
	if len(parts) < 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func newID(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func filterTokens(in []token, keep func(token) bool) []token {
	out := in[:0]
	for _, t := range in {
		if keep(t) {
			out = append(out, t)
		}
	}
	return out
}

func filterGrants(in []grant, keep func(grant) bool) []grant {
	out := in[:0]
	for _, g := range in {
		if keep(g) {
			out = append(out, g)
		}
	}
	return out
}
