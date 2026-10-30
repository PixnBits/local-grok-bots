package daemon

import (
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

// turnSnap is the policy pair captured at the start of one bot turn.
type turnSnap struct {
	eff     policy.Policy
	secret  policy.Policy
	freshOK bool
}

// pol returns a copy of the published snapshot.
func (a *App) pol() policy.Policy {
	if a == nil {
		return policy.Policy{}
	}
	p := a.polCur.Load()
	if p == nil {
		return policy.Policy{}
	}
	return *p
}

// setPol publishes a copy of p.
func (a *App) setPol(p policy.Policy) {
	if a == nil {
		return
	}
	if a.broker != nil {
		if err := a.broker.SetRisks(p.BrokerRisks); err != nil {
			return
		}
	}
	cp := p
	a.polCur.Store(&cp)
}

// editPol copies the snapshot, applies fn, and publishes the copy.
func (a *App) editPol(fn func(*policy.Policy)) {
	if a == nil || fn == nil {
		return
	}
	cur := a.pol()
	fn(&cur)
	a.setPol(cur)
}

func (a *App) held(botID string) (turnSnap, bool) {
	if a == nil || botID == "" {
		return turnSnap{}, false
	}
	a.turnMu.Lock()
	defer a.turnMu.Unlock()
	s, ok := a.turnHeld[botID]
	return s, ok
}

// holdTurn re-reads the policy file once and keeps that pair until release.
func (a *App) holdTurn(botID string) func() {
	if a == nil || botID == "" {
		return func() {}
	}
	fresh, err := a.policyNow()
	freshOK := err == nil && (strings.TrimSpace(a.cfg.PolicyPath) == "" || fresh.Loaded)
	eff := a.pol()
	secret := eff
	if freshOK {
		secret = fresh
	}
	a.turnMu.Lock()
	if a.turnHeld == nil {
		a.turnHeld = map[string]turnSnap{}
	}
	a.turnHeld[botID] = turnSnap{eff: eff, secret: secret, freshOK: freshOK}
	a.turnMu.Unlock()
	return func() {
		a.turnMu.Lock()
		delete(a.turnHeld, botID)
		a.turnMu.Unlock()
	}
}

// effPol is the snapshot for a held turn, or the published snapshot.
func (a *App) effPol(botID string) policy.Policy {
	if s, ok := a.held(botID); ok {
		return s.eff
	}
	return a.pol()
}

func (a *App) nextGen() uint64 {
	if a == nil {
		return 0
	}
	return a.loadGen.Add(1)
}

func (a *App) installedGeneration() uint64 {
	if a == nil {
		return 0
	}
	a.installMu.Lock()
	defer a.installMu.Unlock()
	return a.installedGen
}

// noteGen records a generation that does not change the snapshot.
func (a *App) noteGen(gen uint64) {
	if a == nil {
		return
	}
	a.installMu.Lock()
	if gen > a.installedGen {
		a.installedGen = gen
	}
	a.installMu.Unlock()
}

// consider installs a loaded policy when gen is newer than the last install.
func (a *App) consider(gen uint64, fresh policy.Policy) {
	if a == nil {
		return
	}
	path := strings.TrimSpace(a.cfg.PolicyPath)
	if !fresh.Loaded {
		if path != "" {
			a.failVoice(gen)
			return
		}
		a.noteGen(gen)
		return
	}
	next := a.startPol.WithHot(fresh)
	block, nextSTT := a.prepVoice(next)
	a.publish(gen, next, block, nextSTT, policy.RestartKeys(a.startPol, fresh))
}

func (a *App) failVoice(gen uint64) {
	if a == nil {
		return
	}
	cur := a.pol()
	next := a.startPol.VoiceOff()
	next.ClaudeTransport = cur.ClaudeTransport
	a.publish(gen, next, "", nil, nil)
}

func (a *App) publish(gen uint64, next policy.Policy, block string, nextSTT STT, keys []string) {
	if a == nil {
		return
	}
	a.installMu.Lock()
	if gen <= a.installedGen {
		a.installMu.Unlock()
		return
	}
	var logKeys []string
	if keys != nil {
		sig := strings.Join(keys, ",")
		if sig != a.restartSig {
			a.restartSig = sig
			if sig != "" {
				logKeys = append([]string(nil), keys...)
			}
		}
	}
	prevBlock := a.voiceBlock
	same := policy.HotEqual(a.pol(), next) && a.voiceBlock == block && sttSame(a.stt, nextSTT)
	if !same {
		a.setPol(next)
		a.voiceBlock = block
		a.stt = nextSTT
	}
	a.installedGen = gen
	a.installMu.Unlock()
	if len(logKeys) > 0 {
		a.noteRestart(logKeys)
	}
	if same {
		return
	}
	if block != "" && block != prevBlock {
		a.writeStartup("local-grok-bots: WARN: %s\n", block)
		a.log("", "voice_path", map[string]any{"warning": block})
	}
	a.RefreshProtectSnapshot()
	a.notePermCallback()
}

func sttSame(a, b STT) bool {
	ab, am, aok := sttPaths(a)
	bb, bm, bok := sttPaths(b)
	if !aok || !bok {
		return false
	}
	return ab == bb && am == bm
}

func sttPaths(s STT) (bin, model string, ok bool) {
	if s == nil {
		return "", "", true
	}
	w, is := s.(WhisperCLI)
	if !is {
		return "", "", false
	}
	return w.Bin, w.Model, true
}

func (a *App) noteRestart(keys []string) {
	if a == nil || len(keys) == 0 {
		return
	}
	detail := map[string]any{"settings": append([]string(nil), keys...)}
	a.log("", "policy_restart_required", detail)
	if a.audit != nil && a.audit.Enabled() {
		rec := map[string]any{"action": "policy_restart_required", "settings": append([]string(nil), keys...)}
		a.audit.Write(rec)
	}
}

// notePermErr logs a permission-callback error when the text changes.
// An empty error clears the previous text so the same error can be logged again later.
func (a *App) notePermErr(err error) {
	if a == nil {
		return
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	a.installMu.Lock()
	if msg == a.permErr {
		a.installMu.Unlock()
		return
	}
	a.permErr = msg
	a.installMu.Unlock()
	if msg == "" {
		return
	}
	a.log("", "perm_callback_error", map[string]any{"error": msg})
}
