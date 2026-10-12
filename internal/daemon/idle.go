package daemon

import (
	"context"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/store"
)

const (
	defaultIdleAfter = 30 * time.Minute
	defaultImminent  = 2 * time.Minute
)

func (a *App) idleTimeout() time.Duration {
	if a.idleAfter > 0 {
		return a.idleAfter
	}
	return defaultIdleAfter
}

func (a *App) imminentWindow() time.Duration {
	if a.imminent > 0 {
		return a.imminent
	}
	return defaultImminent
}

func (a *App) touchActivity(botID string) {
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	if a.activity == nil {
		a.activity = map[string]time.Time{}
	}
	a.activity[botID] = time.Now()
}

func (a *App) setCLIPID(botID string, pid int) {
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	if st := a.loops[botID]; st != nil {
		st.cliPID = pid
	}
}

func (a *App) clearCLIPID(botID, runID string) {
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	if st := a.loops[botID]; st != nil && st.runID == runID {
		st.cliPID = 0
	}
}

// killIdle stops a live CLI that has had no user message and no turn start
// within the idle window, unless a user-created timer will fire inside the
// imminent window. A bot-created timer does not keep the process alive.
func (a *App) killIdle() {
	if a.ctx.Err() != nil {
		return
	}
	idle := a.idleTimeout()
	now := time.Now()
	type cand struct {
		id     string
		last   time.Time
		cancel context.CancelFunc
	}
	a.rtMu.Lock()
	var cands []cand
	for id, st := range a.loops {
		if st == nil || !st.running || st.cancel == nil || st.cliPID == 0 {
			continue
		}
		cands = append(cands, cand{id: id, last: a.activity[id], cancel: st.cancel})
	}
	a.rtMu.Unlock()
	for _, c := range cands {
		if c.last.IsZero() || now.Sub(c.last) < idle {
			continue
		}
		if a.timerSoon(c.id, now) {
			continue
		}
		c.cancel()
	}
}

func (a *App) timerSoon(botID string, now time.Time) bool {
	timers, err := a.st.ListTimers(botID)
	if err != nil {
		return true
	}
	low := store.FormatTime(now.Add(-2 * time.Second))
	high := store.FormatTime(now.Add(a.imminentWindow()))
	for _, tm := range timers {
		if tm.Source != "user" {
			continue
		}
		if tm.Enabled && tm.NextFireAt > low && tm.NextFireAt <= high {
			return true
		}
	}
	return false
}
