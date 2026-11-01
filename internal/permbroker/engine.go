package permbroker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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

	// DefaultApprovalTTL is how long a once-token stays valid when
	// policy does not set approval_ttl. A task grant uses the shorter
	// of this value and TaskGrantCap. Pending items do not expire.
	DefaultApprovalTTL = 15 * time.Minute
	// MinApprovalTTL and MaxApprovalTTL bound the policy knob.
	MinApprovalTTL = time.Minute
	MaxApprovalTTL = 24 * time.Hour

	// JailSock is the path a future jail would see. Claude is not inside
	// the daemon jail, so the hook is given the host socket path instead.
	JailSock = "/lgb-perm.sock"
)

var (
	ErrStale          = errors.New("pending item is cancelled or stale")
	ErrNotFound       = errors.New("pending item not found")
	ErrRuleNotFound   = errors.New("rule not found")
	ErrScope          = errors.New("scope is not allowed for this command")
	ErrBadDecision    = errors.New("decision must be approve or deny")
	ErrNotConfirmable = errors.New("rule does not need confirm")
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
	Workspace string
	Repos     []string
	ToolName  string
	ToolInput json.RawMessage
	ToolUseID string
	PeerUID   int
	PeerPID   int
	// Origin is "native" for a daemon run_shell ask and "hook" for the
	// CLI socket. Empty keeps the older once-token behaviour.
	Origin string
	// ResumeID is set only by ResumeEval. A would-be ask then consumes a
	// one-shot bind for that pending id, or denies. It does not open a
	// new pending item. The checkpoint is not authority.
	ResumeID string
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
	HardAsk    bool
	Parts      []Part
	Operators  []string
	Advisory   string
	AdvSource  string
	AdvChecked bool
	TaskText   string
	CritReason string
	GitReason  string
	Literal    bool
	CreatedAt  time.Time
	Ruleset    int
	Classifier string
	Origin     string
}

// Pending is the redacted view returned to an admin.
type Pending struct {
	ID         string        `json:"id"`
	BotID      string        `json:"bot_id"`
	SessionID  string        `json:"session_id"`
	RunID      string        `json:"run_id"`
	TaskID     string        `json:"task_id"`
	Tool       string        `json:"tool"`
	Argv       []string      `json:"argv,omitempty"`
	Command    string        `json:"command,omitempty"`
	Cwd        string        `json:"cwd"`
	Level      Level         `json:"level"`
	InputHash  string        `json:"input_hash"`
	CreatedAt  time.Time     `json:"created_at"`
	Ruleset    int           `json:"ruleset"`
	Compound   bool          `json:"compound,omitempty"`
	BotName    string        `json:"bot_name"`
	HardAsk    bool          `json:"hard_ask"`
	Eligible   bool          `json:"eligible"`
	Allowed    []string      `json:"allowed_scopes"`
	Parts      []PendingPart `json:"parts"`
	Operators  []string      `json:"operators"`
	Advisory   Advisory      `json:"advisory"`
	TaskText   string        `json:"task_text"`
	Suggest    bool          `json:"suggest_always"`
	CritReason string        `json:"critical_reason"`
	GitReason  string        `json:"git_reason,omitempty"`
	Origin     string        `json:"origin,omitempty"`
}

// PendingPart is one command inside a pending card.
type PendingPart struct {
	Argv    []string `json:"argv"`
	Raw     string   `json:"raw"`
	Granted bool     `json:"granted_for_task"`
	HasRule bool     `json:"has_bot_rule"`
}

// Advisory is the classifier note shown on a card.
type Advisory struct {
	Text    string `json:"text"`
	Source  string `json:"source"`
	Checked bool   `json:"checked"`
}

type token struct {
	BotID     string
	SessionID string
	Tool      string
	Hash      string
	Cwd       string
	Expires   time.Time
	// HoldTask keeps a spare once-token from a task, bot, or global
	// approval until the task id changes. The same task still uses
	// the grant or the rule, including the non-literal refusal.
	HoldTask string
}

type grant struct {
	BotID     string
	SessionID string
	TaskID    string
	Hash      string
	Cwd       string
	Expires   time.Time
	Argv      []string
	Raw       string
	TaskText  string
}

// Engine decides tool calls and stores rules outside the jail.
type Engine struct {
	mu         sync.Mutex
	writeMu    sync.Mutex
	dir        string
	rulesPath  string
	rules      rulesFile
	dirty      bool
	closed     bool
	stopCh     chan struct{}
	flushCh    chan struct{}
	flushWG    sync.WaitGroup
	table      table
	audit      *fileAudit
	auditor    Auditor
	classifier Classifier
	now        func() time.Time
	critical   []string
	// inspectHook runs outside the engine lock. Tests use it to stall one bot.
	inspectHook func(context.Context, Request)
	// hookGuard runs at the start of Evaluate, outside the lock.
	// A non-nil error denies the call before a token or a pending item.
	hookGuard func(bot string) error
	// afterEval runs under the lock after a once-token is taken and before
	// the allow is returned. Tests stall here so a deadline can land after
	// the token is gone. Production leaves it nil.
	afterEval func()

	byID   map[string]*pendingItem
	byKey  map[string]string
	denied map[string]struct{}
	dead   map[string]struct{}
	// staged hides a native ask until its checkpoint is durable.
	staged map[string]struct{}
	// binds are one-shot critical approvals keyed by pending id.
	// takeToken does not accept them. Only ResumeEval can consume one.
	binds  map[string]resumeBind
	tokens []token
	grants []grant
	active map[string]Turn

	// resolver maps argv0 to an absolute allowlisted binary. Nil uses
	// the pinned root-owned PATH. The rule key stays the literal argv.
	resolver func(string) (string, bool)
	bots     map[string]botCtx
	userTask map[string]string
	userText map[string]string
	ttl      time.Duration
	// approvals are human approvals in memory, for the suggest-always hint.
	approvals []approvalStamp
	reqRing   map[string][]ringReq
	outcomes  []OutcomeView

	// hookIDs are the pinned hook and any daemon-owned copy.
	// launchPID is the CLI process started for a bot.
	hookIDs   []hookID
	launchPID map[string]int

	// snapBlob is the git baseline used when a call has no per-bot workspace.
	snapSet  bool
	snapWS   string
	snapBlob []byte

	// savedBaseline is the persisted per-bot snapshot, keyed by bot id.
	// baselineCorrupt means the file could not be read. Git commands ask
	// until an admin records a baseline for that bot.
	baselinePath    string
	savedBaseline   map[string][]byte
	baselineCorrupt bool

	// revokeFail is a test hook. When set, RevokeRule returns it and
	// leaves the rule in place.
	revokeFail error
}

// botCtx is the workspace, homes, and git baseline for one bot.
// The socket does not receive those on the wire. Another bot's
// workspace is outside this one.
type botCtx struct {
	Workspace string
	Repos     []string
	Home      string
	UserHome  string
	Env       []string
	snapSet   bool
	snapBlob  []byte
}

type hookID struct {
	Dev uint64
	Ino uint64
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
	rulesPath := filepath.Join(dir, "rules.json")
	doc, err := loadRules(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("permission broker rules file %s: %w", rulesPath, err)
	}
	aud, err := openAudit(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		return nil, err
	}
	baselinePath := filepath.Join(dir, gitBaselineName)
	saved, corrupt := loadGitBaseline(baselinePath)
	e := &Engine{
		dir:             dir,
		rulesPath:       filepath.Join(dir, "rules.json"),
		baselinePath:    baselinePath,
		savedBaseline:   saved,
		baselineCorrupt: corrupt,
		rules:           doc,
		table:           table{extra: append([]RiskEntry(nil), risks...)},
		audit:           aud,
		auditor:         auditor,
		classifier:      NopClassifier{},
		now:             time.Now,
		byID:            map[string]*pendingItem{},
		byKey:           map[string]string{},
		denied:          map[string]struct{}{},
		dead:            map[string]struct{}{},
		staged:          map[string]struct{}{},
		binds:           map[string]resumeBind{},
		active:          map[string]Turn{},
		resolver:        resolvePinned,
		bots:            map[string]botCtx{},
		userTask:        map[string]string{},
		userText:        map[string]string{},
		reqRing:         map[string][]ringReq{},
		launchPID:       map[string]int{},
		stopCh:          make(chan struct{}),
		flushCh:         make(chan struct{}, 1),
	}
	e.flushWG.Add(1)
	go e.flushLoop()
	return e, nil
}

// Close flushes rule-use counts, stops that flusher, and closes the audit file.
// It does not delete rules. A second call does nothing.
func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	close(e.stopCh)
	e.mu.Unlock()
	e.flushWG.Wait()
	e.flushRules()
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
// the previous table stays. A successful replace bumps the ruleset, which
// cancels pending items, once-tokens, and task grants, and is audited.
func (e *Engine) SetRisks(risks []RiskEntry) error {
	if err := ValidateRisk(risks); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	// The daemon publishes the policy it just opened. That call carries
	// the same raises and has nothing open, so it must not write an
	// audit row. A later publish that changes the raises, or that finds
	// a pending item, once-token, or task grant, still cancels them.
	if sameRisks(e.table.extra, risks) && len(e.byID) == 0 && len(e.tokens) == 0 && len(e.grants) == 0 {
		return nil
	}
	e.table.extra = append([]RiskEntry(nil), risks...)
	e.rules.Version++
	e.invalidateLocked()
	e.auditDecision(Request{}, inspected{ClassNote: "none", Raw: "policy risks replaced"}, "invalidate", "invalidate", "", "policy", "", "")
	e.dirty = true
	e.pokeFlushLocked()
	return nil
}

func sameRisks(a, b []RiskEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Tool != b[i].Tool || a[i].Level != b[i].Level || !argvEqual(a[i].Argv, b[i].Argv) {
			return false
		}
	}
	return true
}

// AddCriticalPaths marks paths that always ask. A call that names one is
// critical and is never allowed by a rule or a once-token.
func (e *Engine) AddCriticalPaths(paths ...string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.critical = mergeCritical(e.critical, paths)
}

// SetCriticalPaths replaces the critical path list. Tests use an empty
// list to drop paths added earlier.
func (e *Engine) SetCriticalPaths(paths []string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.critical = mergeCritical(nil, paths)
}

// SetInspectHook installs a function that runs before each evaluate,
// outside the engine lock. Nil clears it.
func (e *Engine) SetInspectHook(fn func(context.Context, Request)) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.inspectHook = fn
	e.mu.Unlock()
}

// SetHookGuard installs the per-call hook check. Nil clears it.
// The function runs outside the engine lock. A non-nil error denies
// the call and does not spend a token or open a pending item.
func (e *Engine) SetHookGuard(fn func(string) error) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.hookGuard = fn
	e.mu.Unlock()
}

// SetAfterEval installs a function that runs under the engine lock after
// a once-token is taken and before that allow is returned. Nil clears it.
func (e *Engine) SetAfterEval(fn func()) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.afterEval = fn
	e.mu.Unlock()
}

// Note appends an audit row that is not a tool verdict. The decision is
// stored as given. Callers use it for a hook identity mismatch.
func (e *Engine) Note(bot, decision, input string) {
	if e == nil || decision == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.auditDecision(Request{BotID: bot}, inspected{Raw: input, ClassNote: "none"}, decision, decision, "", "fail-closed", "", "")
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

// SetBotContext stores the workspace and configured repos the socket
// uses for one bot. The workspace is that bot's directory. An empty
// repos slice means an explicit repo flag is not eligible. Homes, the
// managed environment, and the git baseline stay when the workspace
// does not change.
func (e *Engine) SetBotContext(bot, workspace string, repos []string) {
	if e == nil || bot == "" {
		return
	}
	e.mu.Lock()
	prev := e.bots[bot]
	next := botCtx{
		Workspace: workspace,
		Repos:     append([]string(nil), repos...),
		Home:      prev.Home,
		UserHome:  prev.UserHome,
		Env:       append([]string(nil), prev.Env...),
	}
	if prev.Workspace == workspace && prev.snapSet {
		next.snapSet = true
		next.snapBlob = append([]byte(nil), prev.snapBlob...)
	} else if blob, ok := e.savedBaseline[bot]; ok && !e.baselineCorrupt {
		next.snapSet = true
		next.snapBlob = append([]byte(nil), blob...)
	}
	e.bots[bot] = next
	e.mu.Unlock()
}

// EnsureBotHomes fills an empty bot home or user home and keeps the
// stored environment. A later SetBotRuntime still replaces that environment.
func (e *Engine) EnsureBotHomes(bot, home, userHome string) {
	if e == nil || bot == "" {
		return
	}
	e.mu.Lock()
	b := e.bots[bot]
	if strings.TrimSpace(b.Home) == "" {
		b.Home = home
	}
	if strings.TrimSpace(b.UserHome) == "" {
		b.UserHome = userHome
	}
	e.bots[bot] = b
	e.mu.Unlock()
}

// SetBotRuntime stores the bot home, the user home, and the managed CLI
// environment. Git config outside the repo is read from those homes.
func (e *Engine) SetBotRuntime(bot, home, userHome string, env []string) {
	if e == nil || bot == "" {
		return
	}
	e.mu.Lock()
	b := e.bots[bot]
	b.Home = home
	b.UserHome = userHome
	b.Env = append([]string(nil), env...)
	e.bots[bot] = b
	e.maybeUpgradeBaselineLocked(bot)
	e.mu.Unlock()
}

// SetApprovalTTL sets how long a new once-token and a new task grant
// stay valid. Values outside 1m..24h are clamped. Zero keeps the default.
func (e *Engine) SetApprovalTTL(d time.Duration) {
	if e == nil {
		return
	}
	if d != 0 {
		if d < MinApprovalTTL {
			d = MinApprovalTTL
		}
		if d > MaxApprovalTTL {
			d = MaxApprovalTTL
		}
	}
	e.mu.Lock()
	e.ttl = d
	e.mu.Unlock()
}

func (e *Engine) approvalTTL() time.Duration {
	if e == nil || e.ttl == 0 {
		return DefaultApprovalTTL
	}
	return e.ttl
}

// ClassifierMayAllow reports whether a future classifier may contribute
// an allow for this bot. It is false until that bot has a workspace and
// a git baseline that still matches, and it is false when the git scan
// finds a risk. The classifier still cannot allow a call today.
func (e *Engine) ClassifierMayAllow(bot string) bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.classifierMayAllowLocked(bot)
}

func (e *Engine) classifierMayAllowLocked(bot string) bool {
	if autoAllowGOOS != "linux" {
		return false
	}
	b, ok := e.bots[bot]
	// Workspace and a matching baseline are one condition.
	if !ok || strings.TrimSpace(b.Workspace) == "" || !b.snapSet || e.baselineCorrupt || !bytes.Equal(b.snapBlob, gitBaselineBlob(b.Workspace, homesOf(b))) {
		return false
	}
	if gitConfigRisk(b.Workspace, homesOf(b), b.Env) != "" {
		return false
	}
	return true
}

// classifierMayAllowCommandLocked is the guard for any classifier input
// that would contribute to an allow. The classifier still cannot allow
// a call. Each condition is separate so a test can drop one of them.
// commandMayAllow is the command half of the allow guard. It does not
// look at the bot baseline. A task grant for a compound does not use it:
// a compound is not eligible and is still grantable.
func commandMayAllow(in inspected) bool {
	if !in.Literal || !in.Eligible || in.Compound {
		return false
	}
	if in.Level == LevelCritical || in.GitRisk != "" {
		return false
	}
	return true
}

func (e *Engine) classifierMayAllowCommandLocked(bot string, in inspected) bool {
	if !commandMayAllow(in) {
		return false
	}
	return e.classifierMayAllowLocked(bot)
}

// ClassifierMayAllowCommand reports the allow guard for one command and bot.
func (e *Engine) ClassifierMayAllowCommand(bot string, in inspected) bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.classifierMayAllowCommandLocked(bot, in)
}

// RegisterLaunch records the CLI process started for bot.
func (e *Engine) RegisterLaunch(bot string, pid int) {
	if e == nil || bot == "" || pid <= 1 {
		return
	}
	e.mu.Lock()
	if e.launchPID == nil {
		e.launchPID = map[string]int{}
	}
	e.launchPID[bot] = pid
	e.mu.Unlock()
}

// ClearLaunch forgets the CLI process for bot.
func (e *Engine) ClearLaunch(bot string) {
	if e == nil || bot == "" {
		return
	}
	e.mu.Lock()
	delete(e.launchPID, bot)
	e.mu.Unlock()
}

// ClearHookIDs drops every pinned hook identity.
func (e *Engine) ClearHookIDs() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.hookIDs = nil
	e.mu.Unlock()
}

// SetHookIdentity records a device and inode the socket peer must match.
func (e *Engine) SetHookIdentity(dev, ino uint64) {
	if e == nil || (dev == 0 && ino == 0) {
		return
	}
	e.mu.Lock()
	e.hookIDs = append(e.hookIDs, hookID{Dev: dev, Ino: ino})
	e.mu.Unlock()
}

// NoteHookFile records the binary at path when it is owned by root or
// by this process. A daemon-owned copy of the hook is recorded this way.
func (e *Engine) NoteHookFile(path string) error {
	if e == nil {
		return errors.New("no broker")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	dev, ino, uid, ok := fileIdentity(info)
	if !ok {
		return errors.New("hook identity")
	}
	if uid != 0 && int(uid) != os.Getuid() {
		return errors.New("hook owner")
	}
	e.SetHookIdentity(dev, ino)
	return nil
}

func (e *Engine) peerExpect(bot string) ([]hookID, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ids := append([]hookID(nil), e.hookIDs...)
	root := 0
	if e.launchPID != nil {
		root = e.launchPID[bot]
	}
	return ids, root
}

// UserTask is the latest user-message id for the bot.
func (e *Engine) UserTask(bot string) string {
	if e == nil {
		return ""
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.userTask[bot]
}

// NoteUserMessage records a user message. A new id ends grants and
// pending items for the previous task of this bot, in every session.
func (e *Engine) NoteUserMessage(bot, task string) {
	e.NoteUserText(bot, task, "")
}

// NoteUserText records the user message id and a redacted copy of the
// text that started the task. The copy is what a pending card shows.
func (e *Engine) NoteUserText(bot, task, text string) {
	if e == nil || bot == "" || task == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	prev := e.userTask[bot]
	if e.userTask == nil {
		e.userTask = map[string]string{}
	}
	e.userTask[bot] = task
	if e.userText == nil {
		e.userText = map[string]string{}
	}
	if strings.TrimSpace(text) != "" {
		e.userText[bot] = clipText(flattenSpace(Redact(text)), 200)
	}
	if cur, ok := e.active[bot]; ok && cur.Task != task {
		cur.Task = task
		e.active[bot] = cur
	}
	if prev != "" && prev != task {
		e.endTaskLocked(bot, task)
	}
}

// SnapshotGit records the git baseline for a call that has no per-bot
// workspace. A later change makes a git command ask. It does not write
// the persisted per-bot file.
func (e *Engine) SnapshotGit(workspace string) {
	if e == nil || strings.TrimSpace(workspace) == "" {
		return
	}
	blob := gitBaselineBlob(workspace, nil)
	e.mu.Lock()
	e.snapSet = true
	e.snapWS = workspace
	e.snapBlob = blob
	e.mu.Unlock()
}

// SnapshotBot records the git baseline for one bot when that bot has
// none yet. A turn start does not replace a baseline that is already
// stored. The record is written to the baseline file. An unreadable
// baseline file is left unchanged so git commands keep asking.
func (e *Engine) SnapshotBot(bot string) {
	if e == nil || bot == "" {
		return
	}
	e.mu.Lock()
	if e.baselineCorrupt || e.bots[bot].snapSet {
		e.mu.Unlock()
		return
	}
	b := e.bots[bot]
	ws := b.Workspace
	homes := homesOf(b)
	e.mu.Unlock()
	if strings.TrimSpace(ws) == "" {
		return
	}
	blob := gitBaselineBlob(ws, homes)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.baselineCorrupt {
		return
	}
	b = e.bots[bot]
	if b.Workspace != ws || b.snapSet {
		return
	}
	if e.savedBaseline == nil {
		e.savedBaseline = map[string][]byte{}
	}
	e.savedBaseline[bot] = append([]byte(nil), blob...)
	if err := e.persistBaselinesLocked(); err != nil {
		delete(e.savedBaseline, bot)
		log.Printf("permission broker: git baseline file is unreadable: %s", e.baselinePath)
		return
	}
	b.snapSet = true
	b.snapBlob = append([]byte(nil), blob...)
	e.bots[bot] = b
}

// RebaselineBot records the git baseline for one bot again and writes
// the baseline file. It does not bump the ruleset. The bot needs a
// workspace. An audit row is written when the file is stored.
func (e *Engine) RebaselineBot(bot string) error {
	if e == nil || strings.TrimSpace(bot) == "" {
		return ErrNotFound
	}
	e.mu.Lock()
	b := e.bots[bot]
	ws := b.Workspace
	homes := homesOf(b)
	e.mu.Unlock()
	if strings.TrimSpace(ws) == "" {
		return ErrNotFound
	}
	blob := gitBaselineBlob(ws, homes)
	e.mu.Lock()
	defer e.mu.Unlock()
	b = e.bots[bot]
	if b.Workspace != ws {
		return ErrNotFound
	}
	if e.savedBaseline == nil {
		e.savedBaseline = map[string][]byte{}
	}
	prev, had := e.savedBaseline[bot]
	e.savedBaseline[bot] = append([]byte(nil), blob...)
	if err := e.persistBaselinesLocked(); err != nil {
		if had {
			e.savedBaseline[bot] = prev
		} else {
			delete(e.savedBaseline, bot)
		}
		log.Printf("permission broker: git baseline file is unreadable: %s", e.baselinePath)
		return err
	}
	b.snapSet = true
	b.snapBlob = append([]byte(nil), blob...)
	e.bots[bot] = b
	e.auditDecision(Request{BotID: bot}, inspected{
		ClassNote: "none", Hash: hashRaw("git-baseline", bot),
	}, "git_rebaseline", "git_rebaseline", "", "human", "", "")
	return nil
}

// SaveRule stores an exact argv rule. Critical, compounds, and commands
// that are not rule-eligible are refused. High and unclassified cannot
// be global. The ruleset version bumps, which cancels pending items,
// tokens, and grants. The change is audited.
func (e *Engine) SaveRule(rule Rule) (Rule, error) {
	if e == nil {
		return Rule{}, ErrScope
	}
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	rule.Tool = normTool(rule.Tool)
	rule.Argv = append([]string(nil), rule.Argv...)
	if rule.Tool != ToolShell || len(rule.Argv) == 0 {
		return Rule{}, ErrScope
	}
	if hitsCritical(Request{ToolName: ToolShell}, inspected{Argv: rule.Argv, Raw: strings.Join(rule.Argv, " ")}, e.critical) {
		return Rule{}, ErrScope
	}
	switch rule.Effect {
	case EffectAllow, EffectAsk, EffectDeny:
	default:
		return Rule{}, ErrScope
	}
	if rule.Scope != ScopeBot && rule.Scope != ScopeGlobal {
		return Rule{}, ErrScope
	}
	if rule.Scope == ScopeBot && strings.TrimSpace(rule.BotID) == "" {
		return Rule{}, ErrScope
	}
	if rule.Scope == ScopeGlobal {
		rule.BotID = ""
	}
	cls := classifyArgv(rule.Argv, "", "", nil, e.resolver)
	lvl := maxLevel(e.table.level(ToolShell, rule.Argv), cls.Level)
	if cls.Hard || !cls.Eligible || lvl == LevelCritical || cls.Level == LevelCritical {
		return Rule{}, ErrScope
	}
	if !scopeAllowed(lvl, true, false, false, true, rule.Scope) {
		return Rule{}, ErrScope
	}
	return e.commitRule(rule, lvl)
}

func (e *Engine) commitRule(rule Rule, level Level) (Rule, error) {
	rule.ID = newID("r_")
	rule.CreatedAt = e.now()
	rule.Uses = 0
	rule.LastUsedAt = time.Time{}
	next := e.rules
	next.Version++
	next.Rules = append(append([]Rule(nil), e.rules.Rules...), rule)
	if err := saveRules(e.rulesPath, next); err != nil {
		return Rule{}, err
	}
	e.rules = next
	e.dirty = false
	e.invalidateLocked()
	e.auditRule(rule, level)
	return rule, nil
}

// RuleView is one saved rule for an admin list. Argv and pattern text
// are redacted. Kind is exact when the stored kind is empty.
type RuleView struct {
	ID           string    `json:"id"`
	Effect       string    `json:"effect"`
	Scope        string    `json:"scope"`
	BotID        string    `json:"bot_id,omitempty"`
	Argv         []string  `json:"argv,omitempty"`
	Pattern      string    `json:"pattern,omitempty"`
	Kind         string    `json:"kind"`
	Source       string    `json:"source,omitempty"`
	Active       *bool     `json:"active,omitempty"`
	NeedsConfirm bool      `json:"needs_confirm,omitempty"`
	Confirmable  bool      `json:"confirmable"`
	NeverReason  string    `json:"never_reason,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	LastUsedAt   time.Time `json:"last_used_at,omitempty"`
	Uses         int       `json:"uses"`
	SourceLine   string    `json:"source_line,omitempty"`
}

// ListRules returns bot and global rules. The hook socket does not call this.
func (e *Engine) ListRules() []RuleView {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]RuleView, 0, len(e.rules.Rules))
	for _, rule := range e.rules.Rules {
		out = append(out, e.ruleView(rule))
	}
	return out
}

func (e *Engine) ruleView(rule Rule) RuleView {
	kind := rule.Kind
	if kind == "" {
		kind = "exact"
	}
	why := ""
	if rule.Effect == EffectAllow && (storedKind(&rule) == "legacy" || needsConfirm(rule)) {
		why = e.neverMatchReason(rule)
	}
	view := RuleView{
		ID: rule.ID, Effect: rule.Effect, Scope: rule.Scope, BotID: rule.BotID,
		Argv: redactArgv(rule.Argv), Kind: kind, Source: rule.Source,
		NeedsConfirm: rule.NeedsConfirm,
		Confirmable:  needsConfirm(rule) && why == "",
		NeverReason:  why,
		CreatedAt:    rule.CreatedAt, LastUsedAt: rule.LastUsedAt, Uses: rule.Uses,
	}
	if rule.Active != nil {
		v := *rule.Active
		view.Active = &v
	}
	if rule.Pattern != "" {
		view.Pattern = Redact(rule.Pattern)
	}
	if rule.Text != "" {
		view.SourceLine = Redact(rule.Text)
	} else if rule.Source != "" {
		view.SourceLine = rule.Source
	}
	return view
}

// ConfirmRule activates one imported allow that is waiting for review.
// The ruleset bumps. The audit row records the id and a hash. A rule
// that is already active is refused and the ruleset stays.
func (e *Engine) ConfirmRule(id string) (string, error) {
	if e == nil {
		return "", ErrRuleNotFound
	}
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	id = strings.TrimSpace(id)
	idx := -1
	for i, rule := range e.rules.Rules {
		if rule.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return "", ErrRuleNotFound
	}
	rule := e.rules.Rules[idx]
	if !needsConfirm(rule) {
		return "", ErrNotConfirmable
	}
	if why := e.neverMatchReason(rule); why != "" {
		return "", &InputError{Code: "never_matches", Msg: why}
	}
	rule.NeedsConfirm = false
	rule.Active = nil
	next := e.rules
	next.Version++
	next.Rules = append([]Rule(nil), e.rules.Rules...)
	next.Rules[idx] = rule
	if err := saveRules(e.rulesPath, next); err != nil {
		return "", err
	}
	e.rules = next
	e.dirty = false
	e.invalidateLocked()
	sum := ruleAuditHash(rule)
	e.auditDecision(Request{BotID: rule.BotID, ToolName: rule.Tool}, inspected{
		Hash: sum, ClassNote: "none",
	}, "rule_confirm", "rule_confirm", "", "human", rule.ID, rule.Scope)
	return sum, nil
}

func needsConfirm(rule Rule) bool {
	if rule.Effect != EffectAllow {
		return false
	}
	if rule.NeedsConfirm {
		return true
	}
	return rule.Active != nil && !*rule.Active
}

const (
	neverCommand = "This command cannot be allowed by a rule"
	neverStar    = "A * stands for exactly one word and cannot be last."
)

// neverMatchReason explains an allow that cannot match a shell command.
// A bad command wins over a pattern that is not expressible. A legacy
// glob such as "git diff*" still names git diff; the star is not a word.
func (e *Engine) neverMatchReason(rule Rule) string {
	if rule.Effect != EffectAllow {
		return ""
	}
	kind := rule.Kind
	if kind == "" {
		kind = "exact"
	}
	switch kind {
	case "exact":
		return e.commandNever(rule.Argv)
	case "pattern":
		if ValidatePattern(rule.Pattern) != nil {
			return e.legacyNever(rule)
		}
		return e.commandNever(patternWitnessArgv(rule.Pattern))
	case "legacy":
		return e.legacyNever(rule)
	default:
		return ""
	}
}

// legacyNever is the reason a legacy allow cannot match. The witness is
// the glob with stars removed, so "git diff*" is the command git diff.
func (e *Engine) legacyNever(rule Rule) string {
	if rule.Tool != "" && normTool(rule.Tool) != ToolShell {
		return neverCommand
	}
	if _, err := filepath.Match(rule.Pattern, "x"); err != nil {
		return neverStar
	}
	return e.commandNever(legacyWitnessArgv(rule.Pattern))
}

func (e *Engine) commandNever(argv []string) string {
	if len(argv) == 0 {
		return neverCommand
	}
	if hitsCritical(Request{ToolName: ToolShell}, inspected{Argv: argv, Raw: strings.Join(argv, " ")}, e.critical) {
		return neverCommand
	}
	cls := classifyArgv(argv, "", "", nil, e.resolver)
	lvl := maxLevel(e.table.level(ToolShell, argv), cls.Level)
	if cls.Hard || !cls.Eligible || lvl == LevelCritical || cls.Level == LevelCritical || lvl == LevelUnclassified || cls.Level == LevelUnclassified {
		return neverCommand
	}
	return ""
}

func patternWitnessArgv(pattern string) []string {
	words := strings.Fields(pattern)
	out := make([]string, 0, len(words))
	for _, w := range words {
		if strings.Contains(w, "*") {
			out = append(out, "x")
			continue
		}
		out = append(out, w)
	}
	return out
}

func legacyWitnessArgv(pattern string) []string {
	cleaned := strings.Map(func(r rune) rune {
		if r == '*' || r == '?' {
			return -1
		}
		return r
	}, pattern)
	return strings.Fields(cleaned)
}

func ruleAuditHash(rule Rule) string {
	argvHash := hashParts(normTool(rule.Tool), rule.Argv)
	if len(rule.Argv) == 0 && rule.Pattern != "" {
		argvHash = hashRaw(rule.Kind, rule.Pattern)
	}
	return hashRevoke(rule.ID, rule.Effect, argvHash)
}

// RevokeRule removes one saved rule, including a read-only legacy row.
// The ruleset bumps, which cancels pending items, tokens, and grants.
// The audit row records ids and hashes and does not record argv text.
func (e *Engine) RevokeRule(id string) error {
	if e == nil {
		return ErrRuleNotFound
	}
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.revokeFail != nil {
		return e.revokeFail
	}
	id = strings.TrimSpace(id)
	idx := -1
	for i, rule := range e.rules.Rules {
		if rule.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ErrRuleNotFound
	}
	rule := e.rules.Rules[idx]
	next := e.rules
	next.Version++
	next.Rules = append([]Rule(nil), e.rules.Rules...)
	next.Rules = append(next.Rules[:idx], next.Rules[idx+1:]...)
	if err := saveRules(e.rulesPath, next); err != nil {
		return err
	}
	e.rules = next
	e.dirty = false
	e.invalidateLocked()
	e.auditRevoke(rule)
	return nil
}

func (e *Engine) auditRevoke(rule Rule) {
	argvHash := hashParts(normTool(rule.Tool), rule.Argv)
	if len(rule.Argv) == 0 && rule.Pattern != "" {
		argvHash = hashRaw(rule.Kind, rule.Pattern)
	}
	e.auditDecision(Request{BotID: rule.BotID, ToolName: rule.Tool}, inspected{
		Hash: hashRevoke(rule.ID, rule.Effect, argvHash), ClassNote: "none",
	}, "revoke", "revoke", "", "human", rule.ID, rule.Scope)
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
	e.dropBindsLocked(bot, session)
}

func (e *Engine) endTaskLocked(bot, keepTask string) {
	for id, item := range e.byID {
		if item.BotID == bot && item.TaskID != keepTask {
			e.dead[id] = struct{}{}
			delete(e.byID, id)
			delete(e.byKey, collapseKey(item))
			delete(e.staged, id)
		}
	}
	e.grants = filterGrants(e.grants, func(g grant) bool {
		if g.BotID != bot {
			return true
		}
		return g.TaskID == keepTask
	})
	e.dropBindsLocked(bot, "")
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
// Filesystem work runs before the engine lock is taken. The once-token
// check and the final level both happen under the lock.
func (e *Engine) Evaluate(ctx context.Context, req Request) Decision {
	if e == nil {
		return Decision{Verdict: VerdictDeny, Reason: "denied", Actor: "fail-closed"}
	}
	e.mu.Lock()
	guard := e.hookGuard
	e.mu.Unlock()
	if guard != nil {
		if err := guard(req.BotID); err != nil {
			return Decision{Verdict: VerdictDeny, Reason: "hook changed", Actor: "fail-closed"}
		}
	}
	snap := e.capture(req)
	if snap.hook != nil {
		snap.hook(ctx, req)
	}
	if ctx.Err() != nil {
		return e.failClosed(req)
	}
	in := inspectSnap(ctx, req, snap)
	if ctx.Err() != nil {
		return e.failClosed(req)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if d, stop := e.cancelled(ctx, req, in); stop {
		return d
	}
	in = e.raiseToCurrent(req, in)
	if strings.TrimSpace(req.BotID) == "" || strings.TrimSpace(req.SessionID) == "" {
		return e.finish(req, in, VerdictDeny, "denied", "", "fail-closed", "")
	}
	if rule := e.matchDeny(req.BotID, in); rule != nil {
		if d, stop := e.cancelled(ctx, req, in); stop {
			return d
		}
		e.touch(rule)
		return e.finish(req, in, VerdictDeny, "denied by rule "+rule.ID, "", rule.ID, rule.ID)
	}
	if tok, ok := e.takeToken(ctx, req, in); ok {
		if e.afterEval != nil {
			e.afterEval()
		}
		if ctx.Err() != nil {
			e.tokens = append(e.tokens, tok)
			return e.finish(req, in, VerdictDeny, "denied", "", "fail-closed", "")
		}
		return e.finish(req, in, VerdictAllow, "approved", "", "human", "")
	}
	if d, stop := e.cancelled(ctx, req, in); stop {
		return d
	}
	if in.Level == LevelCritical || !in.Eligible {
		if rule := e.matchFlexAsk(req.BotID, in); rule != nil {
			if d, stop := e.cancelled(ctx, req, in); stop {
				return d
			}
			return e.applyRule(req, in, rule)
		}
		if in.Level != LevelCritical && e.grantCovers(req, in) {
			if d, stop := e.cancelled(ctx, req, in); stop {
				return d
			}
			if !autoAllowOK(in) {
				return e.ask(req, in)
			}
			return e.finish(req, in, VerdictAllow, "allowed for this task", "", "policy", "")
		}
		if d, stop := e.cancelled(ctx, req, in); stop {
			return d
		}
		return e.ask(req, in)
	}
	if rule := e.matchScoped(req.BotID, in, ScopeBot); rule != nil {
		if d, stop := e.cancelled(ctx, req, in); stop {
			return d
		}
		return e.applyRule(req, in, rule)
	}
	if in.Level == LevelLow || in.Level == LevelMedium {
		if rule := e.matchScoped("", in, ScopeGlobal); rule != nil {
			if d, stop := e.cancelled(ctx, req, in); stop {
				return d
			}
			return e.applyRule(req, in, rule)
		}
	}
	if e.grantCovers(req, in) {
		if d, stop := e.cancelled(ctx, req, in); stop {
			return d
		}
		if !autoAllowOK(in) {
			return e.ask(req, in)
		}
		return e.finish(req, in, VerdictAllow, "allowed for this task", "", "policy", "")
	}
	if d, stop := e.cancelled(ctx, req, in); stop {
		return d
	}
	return e.ask(req, in)
}

// cancelled is the last check before a one-time approval, a rule use,
// a task grant, or a new pending item. A deadline that already replied
// deny must not change that state.
func (e *Engine) cancelled(ctx context.Context, req Request, in inspected) (Decision, bool) {
	if ctx.Err() == nil {
		return Decision{}, false
	}
	return e.finish(req, in, VerdictDeny, "denied", "", "fail-closed", ""), true
}

func (e *Engine) applyRule(req Request, in inspected, rule *Rule) Decision {
	if rule.Effect == EffectAllow && (!autoAllowOK(in) || !commandMayAllow(in) || raisedBlocks(in, rule)) {
		return e.ask(req, in)
	}
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
	// A resumed call must not open another card. The bind, when one was
	// recorded for this pending id, allows exactly that execution.
	if req.ResumeID != "" {
		if e.consumeBind(req, in) {
			return e.finish(req, in, VerdictAllow, "approved", req.ResumeID, "human", "")
		}
		return e.finish(req, in, VerdictDeny, "denied", "", "policy", "")
	}
	key := collapseKeyReq(req, in)
	if _, ok := e.denied[key]; ok {
		return e.finish(req, in, VerdictDeny, "denied", "", "human", "")
	}
	if id, ok := e.byKey[key]; ok {
		return e.finishAsk(req, in, id)
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
		HardAsk:    in.HardAsk,
		Parts:      append([]Part(nil), in.Parts...),
		Operators:  append([]string(nil), in.Operators...),
		Advisory:   in.Advisory,
		AdvSource:  in.AdvisorySource,
		AdvChecked: in.AdvisoryChecked,
		TaskText:   e.userText[req.BotID],
		CritReason: in.CriticalReason,
		GitReason:  in.GitReason,
		Literal:    in.Literal,
		CreatedAt:  e.now(),
		Ruleset:    e.rules.Version,
		Classifier: in.ClassNote,
		Origin:     req.Origin,
	}
	e.byID[item.ID] = item
	e.byKey[key] = item.ID
	// Stage only asks that belong to a durable run. Direct execTool calls
	// (no run id) stay visible to ListPending. The run loop hides the card
	// until the checkpoint file and the waiting status are both durable.
	if req.Origin == OriginNative && req.RunID != "" {
		if e.staged == nil {
			e.staged = map[string]struct{}{}
		}
		e.staged[item.ID] = struct{}{}
	}
	return e.finishAsk(req, in, item.ID)
}

// finishAsk records an ask. The hook still receives a deny, because it
// cannot wait. The audit row is "ask", not "deny": nothing was refused.
func (e *Engine) finishAsk(req Request, in inspected, pendingID string) Decision {
	reason := pendingReason(pendingID)
	e.noteRequest(req, in)
	e.noteOutcome(req, in, VerdictDeny, reason, pendingID, "")
	e.auditDecision(req, in, "ask", reason, pendingID, "policy", "", "")
	return Decision{
		Verdict: VerdictDeny, Reason: reason, PendingID: pendingID,
		Level: in.Level, Actor: "policy", RuleID: "", InputHash: in.Hash,
		Eligible: in.Eligible, Compound: in.Compound,
	}
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
		if _, hide := e.staged[item.ID]; hide {
			continue
		}
		out = append(out, e.pendingView(item))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func (e *Engine) pendingView(item *pendingItem) Pending {
	source := item.AdvSource
	if source == "" {
		source = "table"
	}
	view := Pending{
		ID: item.ID, BotID: item.BotID, BotName: item.BotID,
		SessionID: item.SessionID, RunID: item.RunID, TaskID: item.TaskID,
		Tool: item.Tool, Argv: redactArgv(item.Argv), Command: Redact(item.Raw),
		Cwd: item.Cwd, Level: item.Level, InputHash: item.InputHash,
		CreatedAt: item.CreatedAt, Ruleset: item.Ruleset, Compound: item.Compound,
		HardAsk: item.HardAsk, Eligible: item.Eligible,
		Allowed:   allowedScopes(item.Level, item.Eligible, item.Compound, item.HardAsk, item.Literal),
		Operators: append([]string{}, item.Operators...),
		Advisory:  Advisory{Text: item.Advisory, Source: source, Checked: item.AdvChecked},
		TaskText:  item.TaskText, Suggest: e.suggestAlways(item),
		CritReason: item.CritReason, GitReason: item.GitReason,
		Origin: item.Origin,
	}
	if item.Origin == OriginHook && item.Level == LevelCritical {
		view.Allowed = withoutScope(view.Allowed, ScopeOnce)
	}
	if view.Operators == nil {
		view.Operators = []string{}
	}
	if view.Allowed == nil {
		view.Allowed = []string{}
	}
	view.Parts = e.pendingParts(item)
	return view
}

func allowedScopes(level Level, eligible, compound, hard, literal bool) []string {
	var out []string
	for _, scope := range []string{ScopeOnce, ScopeTask, ScopeBot, ScopeGlobal} {
		if scopeAllowed(level, eligible, compound, hard, literal, scope) {
			out = append(out, scope)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

func (e *Engine) pendingParts(item *pendingItem) []PendingPart {
	parts := item.Parts
	if len(parts) == 0 {
		raw := item.Raw
		if raw == "" {
			raw = strings.Join(item.Argv, " ")
		}
		parts = []Part{{Argv: item.Argv, Raw: raw, Hash: item.InputHash}}
	}
	now := e.now()
	req := Request{BotID: item.BotID, SessionID: item.SessionID, TaskID: item.TaskID, Cwd: item.Cwd}
	out := make([]PendingPart, 0, len(parts))
	for _, p := range parts {
		out = append(out, PendingPart{
			Argv: redactArgv(p.Argv), Raw: Redact(p.Raw),
			Granted: e.grantHas(req, p.Hash, now),
			HasRule: e.partHasBotRule(item.BotID, p.Argv),
		})
	}
	return out
}

func (e *Engine) partHasBotRule(bot string, argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	view := inspected{
		Eligible: true, Literal: true, Argv: argv,
		Raw: strings.Join(argv, " "), Level: LevelLow,
	}
	for i := range e.rules.Rules {
		rule := &e.rules.Rules[i]
		if rule.Scope != ScopeBot || rule.BotID != bot {
			continue
		}
		if ruleHit(rule, view, rule.Effect == EffectDeny) {
			return true
		}
	}
	return false
}

func (e *Engine) suggestAlways(item *pendingItem) bool {
	if item == nil || item.Compound {
		return false
	}
	if item.Level != LevelLow && item.Level != LevelMedium {
		return false
	}
	return e.approvalCount(item.BotID, item.InputHash) >= 2
}

func (e *Engine) approvalCount(bot, hash string) int {
	if bot == "" || hash == "" {
		return 0
	}
	cut := e.now().Add(-24 * time.Hour)
	n := 0
	for _, s := range e.approvals {
		if s.Bot == bot && s.Hash == hash && s.At.After(cut) {
			n++
		}
	}
	return n
}

func (e *Engine) noteApproval(item *pendingItem) {
	if item == nil {
		return
	}
	cut := e.now().Add(-24 * time.Hour)
	next := make([]approvalStamp, 0, len(e.approvals)+1)
	for _, s := range e.approvals {
		if s.At.After(cut) {
			next = append(next, s)
		}
	}
	next = append(next, approvalStamp{Bot: item.BotID, Hash: item.InputHash, At: e.now()})
	e.approvals = next
}

// Decide approves or denies one pending item. Approve does not stop a
// run. Scope is required for approve and ignored for deny. An accepted
// decision is audited when it is stored.
func (e *Engine) Decide(id, decision, scope string) error {
	if e == nil {
		return ErrNotFound
	}
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
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
		e.auditHuman(item, "deny", "")
		e.pushOutcome(itemOutcome(item, "denied", "", 0))
		return nil
	case "approve":
		if !scopeAllowed(item.Level, item.Eligible, item.Compound, item.HardAsk, item.Literal, scope) {
			return ErrScope
		}
		switch scope {
		case ScopeOnce:
			if item.Origin == OriginHook && item.Level == LevelCritical {
				return ErrScope
			}
			// A native critical approval is bound to this pending id.
			// It is not a once-token. takeToken still refuses critical.
			if item.Origin == OriginNative && item.Level == LevelCritical {
				e.keepResumeBind(item)
				break
			}
			e.keepOnceToken(item, "")
		case ScopeTask:
			exp := e.grantExpiry()
			text := e.userText[item.BotID]
			if len(item.Parts) > 0 {
				for _, p := range item.Parts {
					if p.Hash == "" {
						return ErrScope
					}
					e.grants = append(e.grants, grant{
						BotID: item.BotID, SessionID: item.SessionID, TaskID: item.TaskID,
						Hash: p.Hash, Cwd: item.Cwd, Expires: exp,
						Argv: append([]string(nil), p.Argv...), Raw: p.Raw, TaskText: text,
					})
				}
				break
			}
			e.grants = append(e.grants, grant{
				BotID: item.BotID, SessionID: item.SessionID, TaskID: item.TaskID,
				Hash: item.InputHash, Cwd: item.Cwd, Expires: exp,
				Argv: append([]string(nil), item.Argv...), Raw: item.Raw, TaskText: text,
			})
		case ScopeBot, ScopeGlobal:
			if err := e.addRuleLocked(item, scope); err != nil {
				return err
			}
		default:
			return ErrScope
		}
		// Hook mode retries the identical command after the next user
		// message. That message drops a task grant, so task, bot, and
		// global approvals also keep the same one-time token. It stays
		// held for this task so the grant or rule still decides here.
		if scope != ScopeOnce {
			e.keepOnceToken(item, item.TaskID)
		}
		e.bury(item)
		e.auditHuman(item, "approve", scope)
		e.noteApproval(item)
		e.pushOutcome(itemOutcome(item, "approved", "", 0))
		return nil
	default:
		return ErrBadDecision
	}
}

// BatchItem is one id from a deny-all or approve-all call.
type BatchItem struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// BatchReport is the per-item result of a batch decision. A stale or
// unknown id is skipped. The other ids are still applied.
type BatchReport struct {
	Results  []BatchItem `json:"results"`
	OKCount  int         `json:"ok_count"`
	Skipped  int         `json:"skipped"`
	Denied   int         `json:"denied,omitempty"`
	Approved int         `json:"approved,omitempty"`
}

// DenyAll denies the listed ids. An empty list is refused and denies
// nothing. A stale or unknown id is skipped. Each denied item is audited.
func (e *Engine) DenyAll(ids []string) (BatchReport, error) {
	if e == nil {
		return BatchReport{}, ErrNotFound
	}
	if len(ids) == 0 {
		return BatchReport{}, &InputError{Code: "ids", Msg: "ids required"}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.denyAllLocked(ids), nil
}

func (e *Engine) denyAllLocked(ids []string) BatchReport {
	rep := BatchReport{Results: make([]BatchItem, 0, len(ids))}
	for _, id := range ids {
		item := e.byID[id]
		if item == nil {
			msg := ErrNotFound.Error()
			if _, dead := e.dead[id]; dead {
				msg = ErrStale.Error()
			}
			rep.Results = append(rep.Results, BatchItem{ID: id, Error: msg})
			rep.Skipped++
			continue
		}
		e.denied[collapseKey(item)] = struct{}{}
		e.bury(item)
		e.auditHuman(item, "deny", "")
		e.pushOutcome(itemOutcome(item, "denied", "", 0))
		rep.Results = append(rep.Results, BatchItem{ID: id, OK: true})
		rep.OKCount++
		rep.Denied++
	}
	return rep
}

// ApproveAll approves the listed ids once. An empty list is refused and
// approves nothing. A stale or unknown id is skipped. Scope is once.
func (e *Engine) ApproveAll(ids []string) (BatchReport, error) {
	if e == nil {
		return BatchReport{}, ErrNotFound
	}
	if len(ids) == 0 {
		return BatchReport{}, &InputError{Code: "ids", Msg: "ids required"}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	rep := BatchReport{Results: make([]BatchItem, 0, len(ids))}
	for _, id := range ids {
		if _, dead := e.dead[id]; dead {
			rep.Results = append(rep.Results, BatchItem{ID: id, Error: ErrStale.Error()})
			rep.Skipped++
			continue
		}
		item := e.byID[id]
		if item == nil {
			rep.Results = append(rep.Results, BatchItem{ID: id, Error: ErrNotFound.Error()})
			rep.Skipped++
			continue
		}
		if item.Ruleset != e.rules.Version {
			e.bury(item)
			rep.Results = append(rep.Results, BatchItem{ID: id, Error: ErrStale.Error()})
			rep.Skipped++
			continue
		}
		if item.Origin == OriginHook && item.Level == LevelCritical {
			rep.Results = append(rep.Results, BatchItem{ID: id, Error: ErrScope.Error()})
			rep.Skipped++
			continue
		}
		if item.Origin == OriginNative && item.Level == LevelCritical {
			e.keepResumeBind(item)
		} else {
			e.keepOnceToken(item, "")
		}
		e.bury(item)
		e.auditHuman(item, "approve", ScopeOnce)
		e.noteApproval(item)
		e.pushOutcome(itemOutcome(item, "approved", "", 0))
		rep.Results = append(rep.Results, BatchItem{ID: id, OK: true})
		rep.OKCount++
		rep.Approved++
	}
	return rep, nil
}

// SetRevokeFailure makes the next RevokeRule calls return err and keep
// the rule. A nil err clears the hook. Tests use this for replace.
func (e *Engine) SetRevokeFailure(err error) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.revokeFail = err
	e.mu.Unlock()
}

// ReplaceRule stores the draft, then revokes id. The locks are not held
// across both calls. When the revoke fails, both rules stay and revoked
// is false.
func (e *Engine) ReplaceRule(id string, d RuleDraft) (string, bool, error) {
	if e == nil {
		return "", false, ErrRuleNotFound
	}
	rule, err := e.CreateRule(d)
	if err != nil {
		return "", false, err
	}
	if err := e.RevokeRule(id); err != nil {
		return rule.ID, false, err
	}
	return rule.ID, true, nil
}

func raisedBlocks(in inspected, rule *Rule) bool {
	if !in.RaisedHigh || rule == nil {
		return false
	}
	return rule.Scope == ScopeBot || rule.Scope == ScopeGlobal
}

func (e *Engine) bury(item *pendingItem) {
	if item == nil {
		return
	}
	e.dead[item.ID] = struct{}{}
	delete(e.byID, item.ID)
	delete(e.byKey, collapseKey(item))
	delete(e.staged, item.ID)
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
	e.dirty = false
	e.invalidateLocked()
	e.auditRule(rule, item.Level)
	return nil
}

func (e *Engine) touch(rule *Rule) {
	rule.Uses++
	rule.LastUsedAt = e.now()
	e.dirty = true
	e.pokeFlushLocked()
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
	e.binds = map[string]resumeBind{}
	e.staged = map[string]struct{}{}
}

func (e *Engine) grantExpiry() time.Time {
	d := TaskGrantCap
	if ttl := e.approvalTTL(); ttl < d {
		d = ttl
	}
	return e.now().Add(d)
}

func (e *Engine) keepOnceToken(item *pendingItem, holdTask string) {
	if item == nil {
		return
	}
	e.tokens = append(e.tokens, token{
		BotID: item.BotID, SessionID: item.SessionID, Tool: item.Tool,
		Hash: item.InputHash, Cwd: item.Cwd, Expires: e.now().Add(e.approvalTTL()),
		HoldTask: holdTask,
	})
}

func (e *Engine) takeToken(ctx context.Context, req Request, in inspected) (token, bool) {
	if in.Level == LevelCritical || in.GitRisk != "" {
		return token{}, false
	}
	want := normTool(req.ToolName)
	if want == "" {
		return token{}, false
	}
	now := e.now()
	cwd := canonCwd(req.Cwd)
	expired := false
	for i, t := range e.tokens {
		match := t.Tool != "" && t.Tool == want && t.BotID == req.BotID && t.SessionID == req.SessionID && t.Hash == in.Hash && canonCwd(t.Cwd) == cwd
		if match && !tokenLive(t, now) {
			expired = true
			continue
		}
		if !tokenLive(t, now) {
			continue
		}
		if t.HoldTask != "" && t.HoldTask == req.TaskID {
			continue
		}
		if t.Tool == "" || t.Tool != want {
			continue
		}
		if t.BotID == req.BotID && t.SessionID == req.SessionID && t.Hash == in.Hash && canonCwd(t.Cwd) == cwd {
			if ctx.Err() != nil {
				return token{}, false
			}
			e.tokens = append(e.tokens[:i], e.tokens[i+1:]...)
			return t, true
		}
	}
	if expired {
		e.pushOutcome(outcomeFrom(req, in, "expired", "", 0))
	}
	return token{}, false
}

func tokenLive(t token, now time.Time) bool {
	if t.Expires.IsZero() || !now.Before(t.Expires) {
		return false
	}
	return true
}

func (e *Engine) grantCovers(req Request, in inspected) bool {
	// Literal stays with autoAllowOK. Rejecting it here would ask before
	// that choke, and the non-literal grant golden would stay green if
	// the choke were removed.
	if in.HardAsk || in.Level == LevelCritical || in.GitRisk != "" {
		return false
	}
	now := e.now()
	if len(in.Parts) > 0 {
		for _, part := range in.Parts {
			if part.Hash == "" || !e.grantHas(req, part.Hash, now) {
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

func (e *Engine) matchDeny(bot string, in inspected) *Rule {
	view := in
	view.Eligible = true
	if rule := e.match(bot, view, EffectDeny); rule != nil {
		return rule
	}
	for _, p := range in.Parts {
		part := inspected{Eligible: true, Argv: p.Argv, Raw: p.Raw, Level: in.Level, GitRisk: in.GitRisk}
		if rule := e.match(bot, part, EffectDeny); rule != nil {
			return rule
		}
	}
	return nil
}

func (e *Engine) match(bot string, in inspected, effect string) *Rule {
	var found *Rule
	for i := range e.rules.Rules {
		rule := &e.rules.Rules[i]
		if rule.Effect != effect || !scopeMatches(rule, bot) {
			continue
		}
		if !ruleHit(rule, in, effect == EffectDeny) {
			continue
		}
		found = rule
	}
	return found
}

func (e *Engine) matchScoped(bot string, in inspected, scope string) *Rule {
	if !in.Eligible || in.Compound || in.Level == LevelCritical || in.GitRisk != "" {
		return nil
	}
	var exactAsk, flexAsk, exactAllow, flexAllow *Rule
	for i := range e.rules.Rules {
		rule := &e.rules.Rules[i]
		if rule.Scope != scope {
			continue
		}
		if scope == ScopeBot && rule.BotID != bot {
			continue
		}
		if !ruleHit(rule, in, false) {
			continue
		}
		flex := storedKind(rule) != "exact"
		switch rule.Effect {
		case EffectAsk:
			if flex {
				flexAsk = rule
			} else {
				exactAsk = rule
			}
		case EffectAllow:
			if flex {
				flexAllow = rule
			} else {
				exactAllow = rule
			}
		}
	}
	switch {
	case exactAsk != nil:
		return exactAsk
	case flexAsk != nil:
		return flexAsk
	case exactAllow != nil:
		return exactAllow
	default:
		return flexAllow
	}
}

func (e *Engine) matchFlexAsk(bot string, in inspected) *Rule {
	var found *Rule
	for _, scope := range []string{ScopeBot, ScopeGlobal} {
		for i := range e.rules.Rules {
			rule := &e.rules.Rules[i]
			if rule.Effect != EffectAsk || rule.Scope != scope {
				continue
			}
			if rule.Kind != "pattern" && rule.Kind != "legacy" {
				continue
			}
			if scope == ScopeBot && rule.BotID != bot {
				continue
			}
			if ruleHit(rule, in, false) {
				found = rule
			}
		}
	}
	return found
}

func scopeMatches(rule *Rule, bot string) bool {
	if rule.Scope == ScopeGlobal {
		return true
	}
	return rule.Scope == ScopeBot && rule.BotID == bot
}

type inspected struct {
	Eligible        bool
	Compound        bool
	HardAsk         bool
	Literal         bool
	Argv            []string
	Raw             string
	Hash            string
	Level           Level
	Parts           []Part
	Operators       []string
	ClassNote       string
	GitRisk         string
	GitReason       string
	RaisedHigh      bool
	Advisory        string
	AdvisorySource  string
	AdvisoryChecked bool
	CriticalReason  string
}

func commandUsesGit(p Parse) bool {
	if len(p.Argv) > 0 && baseName(p.Argv[0]) == "git" {
		return true
	}
	for _, part := range p.Parts {
		if len(part.Argv) > 0 && baseName(part.Argv[0]) == "git" {
			return true
		}
	}
	return false
}

// gitRiskTool is a shell tool whose git config is a hard ask.
// Claude Bash and the daemon run_shell share that scan.
func gitRiskTool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "bash", "run_shell":
		return true
	default:
		return false
	}
}

func readBaselineFile(path string) ([]byte, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false
		}
		return []byte("unreadable"), true
	}
	return b, true
}

func subdirGit(cwd, ws string) bool {
	if cwd == "" || ws == "" {
		return false
	}
	cwd = filepath.Clean(cwd)
	ws = filepath.Clean(ws)
	if cwd == ws || !lexicalInside(cwd, ws) {
		return false
	}
	for _, rel := range []string{".git", ".gitattributes", filepath.Join(".git", "config")} {
		if _, err := os.Lstat(filepath.Join(cwd, rel)); err == nil {
			return true
		}
	}
	return false
}

func toolPaths(raw json.RawMessage) []string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(n any) {
		switch x := n.(type) {
		case map[string]any:
			for _, key := range []string{"file_path", "path", "notebook_path"} {
				if s, ok := x[key].(string); ok && s != "" {
					out = append(out, s)
				}
			}
			for _, child := range x {
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(v)
	return out
}

func (e *Engine) finish(req Request, in inspected, verdict, reason, pendingID, actor, ruleID string) Decision {
	if reason == "" {
		reason = "denied"
	}
	e.noteRequest(req, in)
	e.noteOutcome(req, in, verdict, reason, pendingID, ruleID)
	e.auditDecision(req, in, verdict, reason, pendingID, actor, ruleID, "")
	return Decision{
		Verdict: verdict, Reason: reason, PendingID: pendingID,
		Level: in.Level, Actor: actor, RuleID: ruleID, InputHash: in.Hash,
		Eligible: in.Eligible, Compound: in.Compound,
	}
}

func (e *Engine) auditHuman(item *pendingItem, decision, scope string) {
	if item == nil {
		return
	}
	e.auditDecision(Request{
		BotID: item.BotID, SessionID: item.SessionID, RunID: item.RunID, TaskID: item.TaskID,
		Cwd: item.Cwd, ToolName: item.Tool,
	}, inspected{
		Eligible: item.Eligible, Argv: item.Argv, Raw: item.Raw, Hash: item.InputHash,
		Level: item.Level, ClassNote: item.Classifier,
	}, decision, decision, item.ID, "human", "", scope)
}

func (e *Engine) auditRule(rule Rule, level Level) {
	e.auditDecision(Request{BotID: rule.BotID}, inspected{
		Eligible: true, Argv: rule.Argv, Hash: hashParts(ToolShell, rule.Argv), Level: level, ClassNote: "none",
	}, rule.Effect, "rule", "", "human", rule.ID, rule.Scope)
}

func (e *Engine) auditDecision(req Request, in inspected, verdict, reason, pendingID, actor, ruleID, scope string) {
	note := in.ClassNote
	if note == "" {
		note = "none"
	}
	row := AuditRow{
		Time: e.now(), BotID: req.BotID, SessionID: req.SessionID, RunID: req.RunID, TaskID: req.TaskID,
		Tool: normTool(req.ToolName), Argv: redactArgv(in.Argv), Input: clip(Redact(in.Raw), 500),
		InputHash: in.Hash, Cwd: req.Cwd, Decision: verdict, Scope: scope, PendingID: pendingID,
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

func hashRevoke(id, effect, argvHash string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, "v1\x00revoke\x00")
	_, _ = io.WriteString(h, id)
	_, _ = h.Write([]byte{0})
	_, _ = io.WriteString(h, effect)
	_, _ = h.Write([]byte{0})
	_, _ = io.WriteString(h, argvHash)
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
