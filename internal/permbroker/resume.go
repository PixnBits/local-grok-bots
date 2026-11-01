package permbroker

import (
	"context"
	"time"
)

const (
	// OriginNative is a daemon run_shell ask. Approving it resumes that run.
	OriginNative = "native"
	// OriginHook is a CLI socket ask. The hook cannot wait, so a decision
	// posts a note instead of executing a saved call.
	OriginHook = "hook"
)

// resumeBind is one critical execution tied to a pending id.
// It is not a once-token and takeToken will not accept it.
type resumeBind struct {
	BotID     string
	SessionID string
	Tool      string
	Hash      string
	Cwd       string
	Expires   time.Time
}

// PendingSnapshot is enough to show the card again after a restart.
// It is not permission to run. ResumeEval decides that.
type PendingSnapshot struct {
	ID         string    `json:"id"`
	BotID      string    `json:"bot_id"`
	SessionID  string    `json:"session_id"`
	RunID      string    `json:"run_id"`
	TaskID     string    `json:"task_id"`
	Cwd        string    `json:"cwd"`
	Tool       string    `json:"tool"`
	Argv       []string  `json:"argv"`
	Raw        string    `json:"raw"`
	InputHash  string    `json:"input_hash"`
	Level      Level     `json:"level"`
	Eligible   bool      `json:"eligible"`
	Compound   bool      `json:"compound"`
	HardAsk    bool      `json:"hard_ask"`
	Literal    bool      `json:"literal"`
	Operators  []string  `json:"operators"`
	Advisory   string    `json:"advisory,omitempty"`
	AdvSource  string    `json:"adv_source,omitempty"`
	AdvChecked bool      `json:"adv_checked,omitempty"`
	TaskText   string    `json:"task_text,omitempty"`
	CritReason string    `json:"crit_reason,omitempty"`
	GitReason  string    `json:"git_reason,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	Ruleset    int       `json:"ruleset"`
	Classifier string    `json:"classifier,omitempty"`
	Origin     string    `json:"origin"`
}

// SnapshotPending copies an open item. The caller stores it with the checkpoint.
func (e *Engine) SnapshotPending(id string) (PendingSnapshot, bool) {
	if e == nil || id == "" {
		return PendingSnapshot{}, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	item := e.byID[id]
	if item == nil {
		return PendingSnapshot{}, false
	}
	return snapshotItem(item), true
}

func snapshotItem(item *pendingItem) PendingSnapshot {
	return PendingSnapshot{
		ID: item.ID, BotID: item.BotID, SessionID: item.SessionID, RunID: item.RunID,
		TaskID: item.TaskID, Cwd: item.Cwd, Tool: item.Tool,
		Argv: append([]string(nil), item.Argv...), Raw: item.Raw, InputHash: item.InputHash,
		Level: item.Level, Eligible: item.Eligible, Compound: item.Compound,
		HardAsk: item.HardAsk, Literal: item.Literal,
		Operators: append([]string(nil), item.Operators...),
		Advisory:  item.Advisory, AdvSource: item.AdvSource, AdvChecked: item.AdvChecked,
		TaskText: item.TaskText, CritReason: item.CritReason, GitReason: item.GitReason,
		CreatedAt: item.CreatedAt, Ruleset: item.Ruleset, Classifier: item.Classifier,
		Origin: item.Origin,
	}
}

// RestorePending puts a checkpoint's item back so a decision after restart
// can reach Decide. A dead id, or a collapse key already held by another
// item, is refused. This does not change the bot's current task.
func (e *Engine) RestorePending(s PendingSnapshot) error {
	if e == nil {
		return ErrNotFound
	}
	if s.ID == "" || s.BotID == "" || s.SessionID == "" || s.Tool == "" || s.InputHash == "" {
		return ErrNotFound
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, dead := e.dead[s.ID]; dead {
		return ErrStale
	}
	if cur := e.byID[s.ID]; cur != nil {
		return nil
	}
	item := &pendingItem{
		ID: s.ID, BotID: s.BotID, SessionID: s.SessionID, RunID: s.RunID, TaskID: s.TaskID,
		Cwd: s.Cwd, Tool: normTool(s.Tool), Argv: append([]string(nil), s.Argv...),
		Raw: s.Raw, InputHash: s.InputHash, Level: s.Level, Eligible: s.Eligible,
		Compound: s.Compound, HardAsk: s.HardAsk, Literal: s.Literal,
		Operators: append([]string(nil), s.Operators...),
		Advisory:  s.Advisory, AdvSource: s.AdvSource, AdvChecked: s.AdvChecked,
		TaskText: s.TaskText, CritReason: s.CritReason, GitReason: s.GitReason,
		CreatedAt: s.CreatedAt, Ruleset: s.Ruleset, Classifier: s.Classifier,
		Origin: s.Origin,
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = e.now()
	}
	key := collapseKey(item)
	if other, ok := e.byKey[key]; ok && other != item.ID {
		return ErrStale
	}
	e.byID[item.ID] = item
	e.byKey[key] = item.ID
	return nil
}

// ReleasePending shows a native ask once its checkpoint is durable.
func (e *Engine) ReleasePending(id string) {
	if e == nil || id == "" {
		return
	}
	e.mu.Lock()
	delete(e.staged, id)
	e.mu.Unlock()
}

// BuryPending drops an ask that could not be checkpointed.
func (e *Engine) BuryPending(id string) {
	if e == nil || id == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	item := e.byID[id]
	if item == nil {
		delete(e.staged, id)
		return
	}
	e.bury(item)
}

// ResumeEval runs the normal pipeline for a suspended call.
// A would-be ask does not open a new pending item. A critical bind is
// consumed only here. A deny rule still wins, and takeToken still
// refuses critical commands.
func (e *Engine) ResumeEval(ctx context.Context, req Request, pendingID string) Decision {
	req.ResumeID = pendingID
	return e.Evaluate(ctx, req)
}

// DropFreshApproval removes the once-token and the critical bind created
// for a decision that must not run.
func (e *Engine) DropFreshApproval(bot, session, hash, cwd, pendingID string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.binds, pendingID)
	want := canonCwd(cwd)
	e.tokens = filterTokens(e.tokens, func(t token) bool {
		if t.BotID == bot && t.SessionID == session && t.Hash == hash && canonCwd(t.Cwd) == want {
			return false
		}
		return true
	})
}

// AuditCheckpoint writes one resume, suspend, cancel, or notify row.
// scope carries the reason: approve, deny, policy, tamper, cwd, missing, or cancelled.
func (e *Engine) AuditCheckpoint(bot, session, run, task, cwd, tool, pendingID, decision, scope string) {
	if e == nil || decision == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.auditDecision(Request{
		BotID: bot, SessionID: session, RunID: run, TaskID: task, Cwd: cwd, ToolName: tool,
	}, inspected{
		Hash: hashRaw(tool, pendingID), ClassNote: "none", Raw: pendingID,
	}, decision, decision, pendingID, "daemon", "", scope)
}

func (e *Engine) keepResumeBind(item *pendingItem) {
	if item == nil {
		return
	}
	if e.binds == nil {
		e.binds = map[string]resumeBind{}
	}
	e.binds[item.ID] = resumeBind{
		BotID: item.BotID, SessionID: item.SessionID, Tool: item.Tool,
		Hash: item.InputHash, Cwd: item.Cwd, Expires: e.now().Add(e.approvalTTL()),
	}
}

func (e *Engine) consumeBind(req Request, in inspected) bool {
	if req.ResumeID == "" || in.Level != LevelCritical {
		return false
	}
	b, ok := e.binds[req.ResumeID]
	if !ok {
		return false
	}
	delete(e.binds, req.ResumeID)
	if !tokenLive(token{Expires: b.Expires}, e.now()) {
		return false
	}
	if b.BotID != req.BotID || b.SessionID != req.SessionID || b.Tool != normTool(req.ToolName) {
		return false
	}
	if b.Hash != in.Hash || canonCwd(b.Cwd) != canonCwd(req.Cwd) {
		return false
	}
	return true
}

func (e *Engine) dropBindsLocked(bot, session string) {
	for id, b := range e.binds {
		if b.BotID != bot {
			continue
		}
		if session != "" && b.SessionID != session {
			continue
		}
		delete(e.binds, id)
	}
}

func withoutScope(in []string, drop string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != drop {
			out = append(out, s)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}
