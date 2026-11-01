package daemon

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/permbroker"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

const (
	ckOpen      = "open"
	ckConsumed  = "consumed"
	ckCancelled = "cancelled"
	ckRefused   = "refused"

	deniedByUser = "denied by user"

	// hookNoteMarker is written only by notifyHook. mapHist keeps that
	// message as a system line. The visible sentence is not the check.
	hookNoteMarker = "\u2063lgb-hook-note\u2063"
	hookNoteRunes  = 300

	// approvalRetention is how long a terminal checkpoint or a hook-sent
	// marker stays on disk. Tombstones stay; each is an id and a time.
	approvalRetention  = 7 * 24 * time.Hour
	approvalSweepEvery = time.Hour
)

// approvalWaitError is the ask the run loop turns into a checkpoint.
// Error() stays the broker's pending-approval sentence so a direct
// execTool call still reports that text.
type approvalWaitError struct {
	PendingID string
	Reason    string
	Cwd       string
	SessionID string
	TaskID    string
	Level     string
	Command   string
}

func (e *approvalWaitError) Error() string {
	if e == nil {
		return "pending approval"
	}
	if e.Reason != "" {
		return e.Reason
	}
	return "pending approval " + e.PendingID + "; retry the identical command after approval"
}

type runIDKey struct{}

func withRunID(ctx context.Context, id string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, runIDKey{}, id)
}

func runIDFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	s, _ := ctx.Value(runIDKey{}).(string)
	return s
}

// checkpoint is one suspended native tool call. The MAC is over the
// pending id and the raw payload bytes. The file is not permission to run.
type checkpoint struct {
	V         int                        `json:"v"`
	BotID     string                     `json:"bot_id"`
	RunID     string                     `json:"run_id"`
	TaskID    string                     `json:"task_id"`
	SessionID string                     `json:"session_id"`
	PendingID string                     `json:"pending_id"`
	ToolName  string                     `json:"tool_name"`
	ToolArgs  map[string]any             `json:"tool_args"`
	CallID    string                     `json:"call_id"`
	Cwd       string                     `json:"cwd"`
	Messages  []model.Message            `json:"messages"`
	State     string                     `json:"state"`
	Result    string                     `json:"result,omitempty"`
	HasResult bool                       `json:"has_result,omitempty"`
	Origin    string                     `json:"origin"`
	Pending   permbroker.PendingSnapshot `json:"pending"`
}

type ckEnvelope struct {
	Payload json.RawMessage `json:"payload"`
	MAC     string          `json:"mac"`
}

type shellOnceSlot struct {
	command   string
	cwd       string
	pendingID string
	until     time.Time
}

type shellOnceIDKey struct{}

func withShellOnceID(ctx context.Context, id string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, shellOnceIDKey{}, id)
}

func shellOnceIDFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	s, _ := ctx.Value(shellOnceIDKey{}).(string)
	return s
}

func (a *App) checkpointDir() string {
	if a == nil {
		return ""
	}
	return filepath.Join(a.cfg.DataDir, "permbroker", "checkpoints")
}

func (a *App) checkpointPath(id string) (string, error) {
	if !safePendingID(id) {
		return "", errors.New("pending id")
	}
	dir := a.checkpointDir()
	if dir == "" {
		return "", errors.New("no data dir")
	}
	return filepath.Join(dir, id+".json"), nil
}

func safePendingID(id string) bool {
	if id == "" || len(id) > 80 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func (a *App) checkpointKey() ([]byte, error) {
	if a == nil || a.cfg.DataDir == "" {
		return nil, errors.New("no data dir")
	}
	path := filepath.Join(a.cfg.DataDir, "permbroker", "checkpoint.key")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err == nil {
		fi, sterr := os.Stat(path)
		if sterr != nil {
			return nil, sterr
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("checkpoint key is too open")
		}
		if len(b) != 32 {
			return nil, errors.New("checkpoint key")
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".key-")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return nil, err
	}
	if _, err := tmp.Write(key); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return nil, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func macPayload(key []byte, id string, payload []byte) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(id))
	_, _ = m.Write([]byte{0})
	_, _ = m.Write(payload)
	return m.Sum(nil)
}

// writeCheckpointUnlocked stores ck. The caller holds a.ckMu.
func (a *App) writeCheckpointUnlocked(ck checkpoint) error {
	if ck.V == 0 {
		ck.V = 1
	}
	if ck.PendingID == "" || ck.Pending.ID != ck.PendingID || ck.Origin != permbroker.OriginNative {
		return errors.New("checkpoint")
	}
	path, err := a.checkpointPath(ck.PendingID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	key, err := a.checkpointKey()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(ck)
	if err != nil {
		return err
	}
	env := ckEnvelope{Payload: raw, MAC: hex.EncodeToString(macPayload(key, ck.PendingID, raw))}
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ck-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Chmod(path, 0o600)
}

func (a *App) writeCheckpoint(ck checkpoint) error {
	a.ckMu.Lock()
	defer a.ckMu.Unlock()
	return a.writeCheckpointUnlocked(ck)
}

// readCheckpointUnlocked reports kind "missing" or "tamper". A tampered
// file is not decoded into a usable checkpoint. The caller holds a.ckMu.
func (a *App) readCheckpointUnlocked(id string) (checkpoint, string) {
	path, err := a.checkpointPath(id)
	if err != nil {
		return checkpoint{}, "tamper"
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return checkpoint{}, "missing"
		}
		return checkpoint{}, "tamper"
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm()&0o077 != 0 {
		return checkpoint{}, "tamper"
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	var env ckEnvelope
	if err := dec.Decode(&env); err != nil {
		return checkpoint{}, "tamper"
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return checkpoint{}, "tamper"
	}
	if len(env.Payload) == 0 || env.MAC == "" {
		return checkpoint{}, "tamper"
	}
	key, err := a.checkpointKey()
	if err != nil {
		return checkpoint{}, "tamper"
	}
	got, err := hex.DecodeString(env.MAC)
	if err != nil || !hmac.Equal(got, macPayload(key, id, env.Payload)) {
		return checkpoint{}, "tamper"
	}
	pdec := json.NewDecoder(strings.NewReader(string(env.Payload)))
	pdec.DisallowUnknownFields()
	var ck checkpoint
	if err := pdec.Decode(&ck); err != nil {
		return checkpoint{}, "tamper"
	}
	if err := pdec.Decode(&extra); err != io.EOF {
		return checkpoint{}, "tamper"
	}
	if ck.V != 1 || ck.PendingID != id || ck.Pending.ID != id || ck.Origin != permbroker.OriginNative {
		return checkpoint{}, "tamper"
	}
	if ck.BotID == "" || ck.RunID == "" || ck.ToolName == "" || ck.SessionID == "" {
		return checkpoint{}, "tamper"
	}
	switch ck.State {
	case ckOpen, ckConsumed, ckCancelled, ckRefused:
	default:
		return checkpoint{}, "tamper"
	}
	if ck.Pending.BotID != ck.BotID || ck.Pending.RunID != ck.RunID || ck.Pending.Origin != permbroker.OriginNative {
		return checkpoint{}, "tamper"
	}
	if len(ck.Messages) == 0 {
		return checkpoint{}, "tamper"
	}
	return ck, ""
}

func (a *App) readCheckpoint(id string) (checkpoint, string) {
	a.ckMu.Lock()
	defer a.ckMu.Unlock()
	return a.readCheckpointUnlocked(id)
}

func (a *App) setWaitTool(botID, tool string) {
	a.ckMu.Lock()
	defer a.ckMu.Unlock()
	if a.waitTool == nil {
		a.waitTool = map[string]string{}
	}
	if tool == "" {
		delete(a.waitTool, botID)
		return
	}
	a.waitTool[botID] = tool
}

func (a *App) waitingTool(botID string) string {
	if a == nil {
		return ""
	}
	a.ckMu.Lock()
	defer a.ckMu.Unlock()
	return a.waitTool[botID]
}

func (a *App) clearWait(botID string) {
	a.setWaitTool(botID, "")
}

// suspendForApproval stores the ask and ends the run in waiting.
// The model does not see the pending-approval sentence. A failed write
// fails the run instead of asking the model to retry.
func (a *App) suspendForApproval(bot store.Bot, runID string, msgs []model.Message, name string, args map[string]any, callID string, wait *approvalWaitError) error {
	if a == nil || a.broker == nil || wait == nil || wait.PendingID == "" || runID == "" {
		return errors.New("approval checkpoint")
	}
	snap, ok := a.broker.SnapshotPending(wait.PendingID)
	if !ok {
		return errors.New("approval checkpoint")
	}
	ck := checkpoint{
		V: 1, BotID: bot.ID, RunID: runID, TaskID: wait.TaskID, SessionID: wait.SessionID,
		PendingID: wait.PendingID, ToolName: name, ToolArgs: args, CallID: callID,
		Cwd: wait.Cwd, Messages: cloneMsgs(msgs), State: ckOpen,
		Origin: permbroker.OriginNative, Pending: snap,
	}
	if ck.TaskID == "" {
		ck.TaskID = snap.TaskID
	}
	if ck.SessionID == "" {
		ck.SessionID = snap.SessionID
	}
	if err := a.writeCheckpoint(ck); err != nil {
		a.broker.BuryPending(wait.PendingID)
		return err
	}
	okRun, err := a.st.SuspendRun(runID)
	if err != nil || !okRun {
		a.broker.BuryPending(wait.PendingID)
		ck.State = ckRefused
		_ = a.writeCheckpoint(ck)
		if err != nil {
			return err
		}
		return errors.New("could not suspend run")
	}
	a.broker.ReleasePending(wait.PendingID)
	a.setWaitTool(bot.ID, name)
	a.broker.AuditCheckpoint(bot.ID, ck.SessionID, runID, ck.TaskID, ck.Cwd, name, wait.PendingID, "suspend", "")
	a.bus.Publish(runID, "status", map[string]any{"state": "waiting", "text": name})
	return nil
}

// loadApprovalCheckpoints restores open native asks after a restart and
// continues a call that already ran. A bad file is not restored. A waiting
// run whose checkpoint cannot be loaded is failed, and the bot goes idle.
func (a *App) loadApprovalCheckpoints() {
	if a == nil || a.broker == nil {
		return
	}
	a.loadDeadLedger()
	a.sweepApprovalFiles(time.Now())
	dir := a.checkpointDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		a.failUncoveredWaiting("", "missing")
		return
	}
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		ck, kind := a.readCheckpoint(id)
		if kind == "tamper" {
			a.broker.AuditCheckpoint("", "", "", "", "", "", id, "resume_refused", "tamper")
			continue
		}
		if kind != "" {
			continue
		}
		switch ck.State {
		case ckOpen:
			if a.deadCorrupt || a.tombstoned(id) || !a.runWaiting(ck.RunID) {
				scope := "replay"
				if !a.tombstoned(id) && !a.deadCorrupt {
					scope = "stale"
				}
				a.dropOpenCheckpoint(ck, scope)
				continue
			}
			if err := a.broker.RestorePending(ck.Pending); err != nil {
				a.dropOpenCheckpoint(ck, "missing")
				continue
			}
			a.setWaitTool(ck.BotID, ck.ToolName)
		case ckConsumed:
			if ck.HasResult {
				run, err := a.st.GetRun(ck.RunID)
				if err == nil && run.Status == "waiting" {
					a.continueApproval(ck, ck.Result, "approve")
				}
				continue
			}
			a.failApproval(ck, "approval interrupted")
		}
	}
	a.failUncoveredWaiting("", "missing")
}

func (a *App) afterBrokerDecision(id, decision string, snap permbroker.PendingSnapshot) {
	if a == nil || a.broker == nil || id == "" {
		return
	}
	ck, kind := a.readCheckpoint(id)
	if kind == "tamper" {
		a.refuseSnap(snap, id, "tamper")
		return
	}
	if kind == "" && ck.State == ckOpen && (a.tombstoned(id) || !a.runWaiting(ck.RunID)) {
		scope := "replay"
		if !a.tombstoned(id) {
			scope = "stale"
		}
		a.dropOpenCheckpoint(ck, scope)
		return
	}
	if kind == "missing" {
		if snap.Origin == permbroker.OriginNative || strings.HasPrefix(snap.SessionID, "shell:") {
			a.refuseSnap(snap, id, "missing")
			return
		}
		a.notifyHook(snap, decision)
		return
	}
	switch ck.State {
	case ckCancelled:
		a.dropFresh(ck)
		a.broker.AuditCheckpoint(ck.BotID, ck.SessionID, ck.RunID, ck.TaskID, ck.Cwd, ck.ToolName, ck.PendingID, "resume_refused", "cancelled")
		return
	case ckConsumed, ckRefused:
		return
	}
	if decision == "deny" {
		a.resumeDenied(ck)
		return
	}
	if decision == "approve" {
		a.resumeApproved(ck)
	}
}

func (a *App) refuseOpen(id string, snap permbroker.PendingSnapshot, scope string) {
	ck, kind := a.readCheckpoint(id)
	if kind == "tamper" {
		a.refuseSnap(snap, id, "tamper")
		return
	}
	if kind != "" || ck.State != ckOpen {
		return
	}
	a.refuseCheckpoint(ck, scope)
}

func (a *App) refuseSnap(snap permbroker.PendingSnapshot, id, scope string) {
	if a == nil || a.broker == nil {
		return
	}
	a.broker.DropFreshApproval(snap.BotID, snap.SessionID, snap.InputHash, snap.Cwd, id)
	a.broker.AuditCheckpoint(snap.BotID, snap.SessionID, snap.RunID, snap.TaskID, snap.Cwd, snap.Tool, id, "resume_refused", scope)
	if snap.RunID != "" {
		if ok, _ := a.st.FailWaiting(snap.RunID, "approval refused"); ok {
			a.persistRunNotice(snap.BotID, snap.RunID, "error", "approval refused")
		}
		_ = a.st.SetStatus(snap.BotID, "idle")
		a.clearWait(snap.BotID)
	}
}

func (a *App) refuseCheckpoint(ck checkpoint, scope string) {
	a.dropFresh(ck)
	a.ckMu.Lock()
	_ = a.rememberDeadUnlocked(ck.PendingID)
	cur, kind := a.readCheckpointUnlocked(ck.PendingID)
	if kind == "" && cur.State == ckOpen {
		cur.State = ckRefused
		_ = a.writeCheckpointUnlocked(cur)
	}
	a.ckMu.Unlock()
	a.broker.AuditCheckpoint(ck.BotID, ck.SessionID, ck.RunID, ck.TaskID, ck.Cwd, ck.ToolName, ck.PendingID, "resume_refused", scope)
	a.failApproval(ck, "approval refused")
}

func (a *App) dropFresh(ck checkpoint) {
	if a == nil || a.broker == nil {
		return
	}
	a.broker.DropFreshApproval(ck.BotID, ck.SessionID, ck.Pending.InputHash, ck.Cwd, ck.PendingID)
}

func (a *App) failApproval(ck checkpoint, msg string) {
	if a == nil || a.st == nil || ck.RunID == "" {
		return
	}
	if ok, _ := a.st.FailWaiting(ck.RunID, msg); ok {
		a.persistRunNotice(ck.BotID, ck.RunID, "error", msg)
	} else if run, err := a.st.GetRun(ck.RunID); err == nil && run.Status == "running" {
		_, _ = a.finishRun(ck.RunID, "error", msg)
	}
	_ = a.st.SetStatus(ck.BotID, "idle")
	a.clearWait(ck.BotID)
}

func (a *App) resumeDenied(ck checkpoint) {
	if !a.markConsumed(ck.PendingID) {
		return
	}
	a.saveResult(ck.PendingID, deniedByUser)
	a.continueApproval(ck, deniedByUser, "deny")
}

func (a *App) resumeApproved(ck checkpoint) {
	resolved, err := a.prepareResumeCwd(&ck)
	if err != nil {
		a.refuseCheckpoint(ck, "cwd")
		return
	}
	bot, err := a.st.GetBot(ck.BotID)
	if err != nil {
		a.refuseCheckpoint(ck, "missing")
		return
	}
	ws := a.botWorkspace(ck.BotID)
	repos := a.effPol(ck.BotID).EffectiveGitHubRepos(bot.GitHubAllow)
	a.broker.SetBotContext(ck.BotID, ws, repos)
	cmd := shellCommandOf(ck.ToolArgs)
	raw, err := json.Marshal(map[string]string{"command": cmd})
	if err != nil {
		a.refuseCheckpoint(ck, "policy")
		return
	}
	d := a.broker.ResumeEval(a.ctx, permbroker.Request{
		BotID: ck.BotID, SessionID: ck.SessionID, RunID: ck.RunID, TaskID: ck.TaskID,
		Cwd: resolved, Workspace: ws, Repos: repos,
		ToolName: ck.ToolName, ToolInput: raw, Origin: permbroker.OriginNative,
	}, ck.PendingID)
	if d.Verdict != permbroker.VerdictAllow {
		a.broker.DropFreshApproval(ck.BotID, ck.SessionID, ck.Pending.InputHash, ck.Cwd, ck.PendingID)
		a.refuseCheckpoint(ck, "policy")
		return
	}
	if !a.markConsumed(ck.PendingID) {
		a.broker.DropFreshApproval(ck.BotID, ck.SessionID, ck.Pending.InputHash, ck.Cwd, ck.PendingID)
		return
	}
	a.armShellOnce(ck.BotID, ck.PendingID, cmd, resolved)
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.execSavedCall(ck)
	}()
}

func (a *App) prepareResumeCwd(ck *checkpoint) (string, error) {
	ws := a.botWorkspace(ck.BotID)
	resolved, _, err := a.confirmShellCwd(ck.BotID, ws, ck.Cwd)
	if err != nil {
		return "", err
	}
	a.shellCwdMu.Lock()
	if a.shellCwd == nil {
		a.shellCwd = map[string]string{}
	}
	a.shellCwd[ck.BotID] = resolved
	a.shellCwdMu.Unlock()
	return resolved, nil
}

func (a *App) execSavedCall(ck checkpoint) {
	defer a.clearShellOnce(ck.BotID, ck.PendingID)
	bot, err := a.st.GetBot(ck.BotID)
	if err != nil {
		a.failApproval(ck, "approval refused")
		return
	}
	result, terr := a.execTool(withShellOnceID(a.ctx, ck.PendingID), bot, ck.ToolName, ck.ToolArgs)
	var wait *approvalWaitError
	if errors.As(terr, &wait) {
		a.failApproval(ck, "approval refused")
		return
	}
	body := result
	if terr != nil {
		body = terr.Error()
	}
	a.saveResult(ck.PendingID, body)
	argJSON, _ := json.Marshal(redactValue(ck.ToolArgs))
	_ = a.st.AddRunTool(ck.RunID, ck.BotID, store.ToolRecord{
		Name: ck.ToolName, Arguments: argJSON, OK: terr == nil, Result: clip(body, 4000),
	})
	a.continueApproval(ck, body, "approve")
}

func (a *App) continueApproval(ck checkpoint, body, scope string) {
	if a == nil || a.st == nil {
		return
	}
	msgs := append(cloneMsgs(ck.Messages), model.Message{Role: "tool", ToolName: ck.ToolName, Content: body})
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	if a.closing {
		return
	}
	ok, err := a.st.ResumeRun(ck.RunID)
	if err != nil {
		return
	}
	if !ok {
		run, gerr := a.st.GetRun(ck.RunID)
		if gerr != nil || run.Status != "running" {
			return
		}
	}
	if err := a.st.SetStatus(ck.BotID, "running"); err != nil {
		return
	}
	if a.pending == nil {
		a.pending = map[string][]model.Message{}
	}
	a.pending[ck.RunID] = msgs
	a.clearWait(ck.BotID)
	a.startLoopLocked(ck.BotID, ck.RunID)
	if a.broker != nil {
		a.broker.AuditCheckpoint(ck.BotID, ck.SessionID, ck.RunID, ck.TaskID, ck.Cwd, ck.ToolName, ck.PendingID, "resume", scope)
	}
	a.bus.Publish(ck.RunID, "status", map[string]any{"state": "working", "text": "working"})
}

func (a *App) markConsumed(id string) bool {
	a.ckMu.Lock()
	defer a.ckMu.Unlock()
	ck, kind := a.readCheckpointUnlocked(id)
	if kind != "" || ck.State != ckOpen {
		return false
	}
	if err := a.rememberDeadUnlocked(id); err != nil {
		return false
	}
	ck.State = ckConsumed
	ck.HasResult = false
	ck.Result = ""
	return a.writeCheckpointUnlocked(ck) == nil
}

func (a *App) saveResult(id, body string) {
	a.ckMu.Lock()
	defer a.ckMu.Unlock()
	ck, kind := a.readCheckpointUnlocked(id)
	if kind != "" {
		return
	}
	ck.Result = body
	ck.HasResult = true
	if ck.State == ckOpen {
		ck.State = ckConsumed
	}
	_ = a.writeCheckpointUnlocked(ck)
}

func (a *App) armShellOnce(botID, pendingID, command, cwd string) {
	if a == nil || botID == "" || command == "" {
		return
	}
	a.shellCwdMu.Lock()
	defer a.shellCwdMu.Unlock()
	if a.shellOnce == nil {
		a.shellOnce = map[string]shellOnceSlot{}
	}
	a.shellOnce[botID] = shellOnceSlot{
		command: command, cwd: cwd, pendingID: pendingID,
		until: time.Now().Add(2 * time.Minute),
	}
}

func (a *App) clearShellOnce(botID, pendingID string) {
	if a == nil || botID == "" {
		return
	}
	a.shellCwdMu.Lock()
	defer a.shellCwdMu.Unlock()
	slot, ok := a.shellOnce[botID]
	if !ok {
		return
	}
	if pendingID != "" && slot.pendingID != pendingID {
		return
	}
	delete(a.shellOnce, botID)
}

func (a *App) takeShellOnce(ctx context.Context, botID, command, cwd string) bool {
	if a == nil {
		return false
	}
	a.shellCwdMu.Lock()
	defer a.shellCwdMu.Unlock()
	slot, ok := a.shellOnce[botID]
	if !ok {
		return false
	}
	if slot.pendingID != "" && shellOnceIDFrom(ctx) != slot.pendingID {
		return false
	}
	if time.Now().After(slot.until) || slot.command != command || filepath.Clean(slot.cwd) != filepath.Clean(cwd) {
		return false
	}
	delete(a.shellOnce, botID)
	return true
}

func shellCommandOf(args map[string]any) string {
	if args == nil {
		return ""
	}
	if s, ok := args["command"].(string); ok && s != "" {
		return s
	}
	s, _ := args["cmd"].(string)
	return s
}

func (a *App) cancelBotApprovals(botID, reason string) {
	a.eachOpen(func(ck checkpoint) bool {
		if botID != "" && ck.BotID != botID {
			return false
		}
		a.cancelCheckpoint(ck, reason)
		return true
	})
}

func (a *App) cancelApprovalsExceptTask(botID, keepTask, reason string) {
	a.eachOpen(func(ck checkpoint) bool {
		if ck.BotID != botID || ck.TaskID == keepTask {
			return false
		}
		a.cancelCheckpoint(ck, reason)
		return true
	})
}

func (a *App) cancelRunApproval(botID, runID, reason string) {
	a.eachOpen(func(ck checkpoint) bool {
		if ck.BotID != botID || ck.RunID != runID {
			return false
		}
		a.cancelCheckpoint(ck, reason)
		return true
	})
}

func (a *App) eachOpen(fn func(checkpoint) bool) {
	if a == nil {
		return
	}
	dir := a.checkpointDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		ck, kind := a.readCheckpoint(id)
		if kind != "" || ck.State != ckOpen {
			continue
		}
		fn(ck)
	}
}

func (a *App) cancelCheckpoint(ck checkpoint, reason string) {
	a.ckMu.Lock()
	cur, kind := a.readCheckpointUnlocked(ck.PendingID)
	if kind != "" || cur.State != ckOpen {
		a.ckMu.Unlock()
		return
	}
	cur.State = ckCancelled
	if err := a.rememberDeadUnlocked(ck.PendingID); err != nil {
		a.ckMu.Unlock()
		return
	}
	if err := a.writeCheckpointUnlocked(cur); err != nil {
		a.ckMu.Unlock()
		return
	}
	a.ckMu.Unlock()
	a.clearShellOnce(ck.BotID, ck.PendingID)
	if a.broker != nil {
		a.broker.AuditCheckpoint(ck.BotID, ck.SessionID, ck.RunID, ck.TaskID, ck.Cwd, ck.ToolName, ck.PendingID, "cancel", reason)
		a.broker.DropFreshApproval(ck.BotID, ck.SessionID, ck.Pending.InputHash, ck.Cwd, ck.PendingID)
	}
	if ok, _ := a.st.CancelWaiting(ck.RunID); ok {
		a.persistRunNotice(ck.BotID, ck.RunID, "cancelled", "")
	}
	a.clearWait(ck.BotID)
}

func (a *App) notifyHook(snap permbroker.PendingSnapshot, decision string) {
	if a == nil || a.broker == nil || a.st == nil || snap.ID == "" {
		return
	}
	if snap.Origin != permbroker.OriginHook {
		return
	}
	if snap.Level == permbroker.LevelCritical && decision == "approve" {
		return
	}
	if snap.TaskID == "" || a.broker.UserTask(snap.BotID) != snap.TaskID {
		return
	}
	var text string
	switch decision {
	case "approve":
		cmd := snap.Raw
		if cmd == "" {
			cmd = strings.Join(snap.Argv, " ")
		}
		text = "Notice: request " + snap.ID + " was approved; the command shown below as data: " + hookCommandData(cmd)
	case "deny":
		text = "Notice: request " + snap.ID + " was denied."
	default:
		return
	}
	text = hookNoteMarker + text
	if !a.claimHookSent(snap.ID) {
		return
	}
	if _, err := a.st.AddMessage(store.Message{
		BotID: snap.BotID, Thread: "user", Role: "system", Content: text,
	}); err != nil {
		return
	}
	a.broker.AuditCheckpoint(snap.BotID, snap.SessionID, snap.RunID, snap.TaskID, snap.Cwd, snap.Tool, snap.ID, "cli_notify", decision)
	a.kick(snap.BotID)
}

func (a *App) claimHookSent(id string) bool {
	if !safePendingID(id) {
		return false
	}
	dir := filepath.Join(a.cfg.DataDir, "permbroker", "hook-sent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return false
	}
	path := filepath.Join(dir, id)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	key, err := a.checkpointKey()
	if err != nil {
		f.Close()
		os.Remove(path)
		return false
	}
	sum := macPayload(key, id, []byte("hook-sent"))
	if _, err := f.Write([]byte(hex.EncodeToString(sum))); err != nil {
		f.Close()
		os.Remove(path)
		return false
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return false
	}
	return true
}

// hookCommandData is one JSON string, at most hookNoteRunes, with an
// ellipsis when the command was cut. Newlines and control characters
// stay inside the quotes.
func hookCommandData(cmd string) string {
	rs := []rune(cmd)
	if len(rs) > hookNoteRunes {
		cmd = string(rs[:hookNoteRunes-1]) + "…"
	}
	b, err := json.Marshal(cmd)
	if err != nil {
		return `""`
	}
	return string(b)
}

// claimDecision marks id as being decided. The caller must releaseDecision.
// False means another decision owns it, or the checkpoint is already terminal.
func (a *App) claimDecision(id string) bool {
	if a == nil || !safePendingID(id) {
		return false
	}
	a.ckMu.Lock()
	defer a.ckMu.Unlock()
	if a.deciding == nil {
		a.deciding = map[string]struct{}{}
	}
	if _, ok := a.deciding[id]; ok {
		return false
	}
	ck, kind := a.readCheckpointUnlocked(id)
	if kind == "" && ck.State != ckOpen {
		return false
	}
	a.deciding[id] = struct{}{}
	return true
}

func (a *App) releaseDecision(id string) {
	if a == nil || id == "" {
		return
	}
	a.ckMu.Lock()
	defer a.ckMu.Unlock()
	delete(a.deciding, id)
}

func (a *App) runWaiting(id string) bool {
	if a == nil || a.st == nil || id == "" {
		return false
	}
	run, err := a.st.GetRun(id)
	return err == nil && run.Status == "waiting"
}

// dropOpenCheckpoint refuses an open file that must not be restored:
// a tombstoned id, a run that is not waiting, or a pending item that
// cannot be put back. It does not execute the saved call.
func (a *App) dropOpenCheckpoint(ck checkpoint, scope string) {
	a.refuseCheckpoint(ck, scope)
}

func (a *App) tombstonePath() string {
	if a == nil || a.cfg.DataDir == "" {
		return ""
	}
	return filepath.Join(a.cfg.DataDir, "permbroker", "tombstones.json")
}

func (a *App) tombstoned(id string) bool {
	if a == nil {
		return false
	}
	a.ckMu.Lock()
	defer a.ckMu.Unlock()
	return a.tombstonedUnlocked(id)
}

func (a *App) tombstonedUnlocked(id string) bool {
	if a.deadCorrupt {
		return true
	}
	if a.deadAt == nil {
		return false
	}
	_, ok := a.deadAt[id]
	return ok
}

func (a *App) loadDeadLedger() {
	if a == nil {
		return
	}
	a.ckMu.Lock()
	defer a.ckMu.Unlock()
	a.deadAt = map[string]time.Time{}
	a.deadCorrupt = false
	path := a.tombstonePath()
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			a.deadCorrupt = true
		}
		return
	}
	fi, sterr := os.Stat(path)
	if sterr != nil || fi.Mode().Perm()&0o077 != 0 {
		a.deadCorrupt = true
		return
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	var doc struct {
		V   int               `json:"v"`
		IDs map[string]string `json:"ids"`
	}
	if err := dec.Decode(&doc); err != nil || doc.V != 1 {
		a.deadCorrupt = true
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		a.deadCorrupt = true
		return
	}
	for id, ts := range doc.IDs {
		if !safePendingID(id) {
			a.deadCorrupt = true
			a.deadAt = map[string]time.Time{}
			return
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			a.deadCorrupt = true
			a.deadAt = map[string]time.Time{}
			return
		}
		a.deadAt[id] = t
	}
}

// rememberDeadUnlocked records id in the tombstone ledger. The caller holds ckMu.
func (a *App) rememberDeadUnlocked(id string) error {
	if a == nil || !safePendingID(id) {
		return errors.New("pending id")
	}
	if a.deadAt == nil {
		a.deadAt = map[string]time.Time{}
	}
	if _, ok := a.deadAt[id]; !ok {
		a.deadAt[id] = time.Now().UTC().Truncate(time.Second)
	}
	return a.writeDeadUnlocked()
}

func (a *App) writeDeadUnlocked() error {
	ids := map[string]string{}
	for id, t := range a.deadAt {
		ids[id] = t.UTC().Format(time.RFC3339)
	}
	raw, err := json.Marshal(struct {
		V   int               `json:"v"`
		IDs map[string]string `json:"ids"`
	}{V: 1, IDs: ids})
	if err != nil {
		return err
	}
	return writeAtomic600(a.tombstonePath(), raw)
}

func writeAtomic600(path string, body []byte) error {
	if path == "" {
		return errors.New("path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tomb-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Chmod(path, 0o600)
}

// maybeSweepApprovals removes old terminal checkpoints about once an hour.
func (a *App) maybeSweepApprovals(now time.Time) {
	if a == nil {
		return
	}
	a.ckMu.Lock()
	due := a.lastSweep.IsZero() || now.Sub(a.lastSweep) >= approvalSweepEvery
	a.ckMu.Unlock()
	if !due {
		return
	}
	a.sweepApprovalFiles(now)
}

// sweepApprovalFiles deletes terminal checkpoints and hook-sent markers
// older than approvalRetention. Open checkpoints and tombstones stay.
// The caller does not hold ckMu.
func (a *App) sweepApprovalFiles(now time.Time) {
	if a == nil {
		return
	}
	a.ckMu.Lock()
	a.lastSweep = now
	a.ckMu.Unlock()
	a.sweepCheckpointDir(now)
	a.sweepHookSent(now)
}

func (a *App) sweepCheckpointDir(now time.Time) {
	dir := a.checkpointDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cut := now.Add(-approvalRetention)
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		info, err := ent.Info()
		if err != nil || info.ModTime().After(cut) {
			continue
		}
		ck, kind := a.readCheckpoint(id)
		if kind != "" {
			continue
		}
		switch ck.State {
		case ckConsumed, ckCancelled, ckRefused:
		default:
			continue
		}
		path, err := a.checkpointPath(id)
		if err != nil {
			continue
		}
		_ = os.Remove(path)
	}
}

func (a *App) sweepHookSent(now time.Time) {
	if a == nil || a.cfg.DataDir == "" {
		return
	}
	dir := filepath.Join(a.cfg.DataDir, "permbroker", "hook-sent")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cut := now.Add(-approvalRetention)
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		info, err := ent.Info()
		if err != nil || info.ModTime().After(cut) {
			continue
		}
		_ = os.Remove(filepath.Join(dir, ent.Name()))
	}
}

// failUncoveredWaiting fails waiting runs that no open checkpoint covers.
// scope is the audit reason, usually "missing". The bot is set idle.
func (a *App) failUncoveredWaiting(botID, scope string) {
	if a == nil || a.st == nil {
		return
	}
	if scope == "" {
		scope = "missing"
	}
	a.auditUnreadableCheckpoints()
	runs, err := a.st.ListWaiting()
	if err != nil {
		return
	}
	covered := a.openRunIDs()
	for _, run := range runs {
		if botID != "" && run.BotID != botID {
			continue
		}
		if covered[run.ID] {
			continue
		}
		if ok, _ := a.st.FailWaiting(run.ID, "approval refused"); ok {
			a.persistRunNotice(run.BotID, run.ID, "error", "approval refused")
		}
		_ = a.st.SetStatus(run.BotID, "idle")
		a.clearWait(run.BotID)
		if a.broker != nil {
			a.broker.AuditCheckpoint(run.BotID, "", run.ID, "", "", "", "", "resume_refused", scope)
		}
	}
}

func (a *App) openRunIDs() map[string]bool {
	out := map[string]bool{}
	if a == nil {
		return out
	}
	dir := a.checkpointDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		ck, kind := a.readCheckpoint(id)
		if kind != "" || ck.State != ckOpen {
			continue
		}
		if a.tombstoned(id) {
			continue
		}
		out[ck.RunID] = true
	}
	return out
}

func (a *App) auditUnreadableCheckpoints() {
	if a == nil || a.broker == nil {
		return
	}
	dir := a.checkpointDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if _, kind := a.readCheckpoint(id); kind == "tamper" {
			a.broker.AuditCheckpoint("", "", "", "", "", "", id, "resume_refused", "tamper")
		}
	}
}

// auditMiss records a decision whose pending item is already gone.
// It does not write the checkpoint and does not call refuseOpen.
func (a *App) auditMiss(id string, snap permbroker.PendingSnapshot) {
	if a == nil || a.broker == nil || id == "" {
		return
	}
	_, kind := a.readCheckpoint(id)
	if kind != "" && snap.ID == "" {
		return
	}
	a.broker.AuditCheckpoint(snap.BotID, snap.SessionID, snap.RunID, snap.TaskID, snap.Cwd, snap.Tool, id, "resume_refused", "missing")
}
