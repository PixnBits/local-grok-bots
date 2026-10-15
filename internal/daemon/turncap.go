package daemon

import (
	"fmt"
	"sync"
	"time"
)

// botTurns counts, per bot, the turns other bots or timers started in the
// last hour, so a DM loop is held to the same hourly cap as scheduled turns
// (cli.lgb.max_scheduled_per_hour).
type botTurns struct {
	mu   sync.Mutex
	now  func() time.Time
	seen map[string][]time.Time
}

func (a *App) turnCounter() *botTurns {
	a.turnsOnce.Do(func() {
		a.turns = &botTurns{now: time.Now, seen: map[string][]time.Time{}}
	})
	return a.turns
}

// take records one turn for botID unless the last hour already holds limit.
// limit <= 0 means no cap.
func (c *botTurns) take(botID string, limit int, force bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	cut := now.Add(-time.Hour)
	kept := c.seen[botID][:0]
	for _, t := range c.seen[botID] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if !force && limit > 0 && len(kept) >= limit {
		c.seen[botID] = kept
		return false
	}
	c.seen[botID] = append(kept, now)
	return true
}

// noteScheduledTurn counts a timer-fired turn toward the bot's hourly cap.
// Timers are already capped when created, so this never refuses.
func (a *App) noteScheduledTurn(botID string) {
	_, perHour := a.policy.BotTimerLimits()
	a.turnCounter().take(botID, perHour, true)
}

// allowBotTurn reports whether another bot may start a turn for botID. Over
// the cap it logs and audits bot_turn_cap and returns an error for the sender.
func (a *App) allowBotTurn(fromID, botID, via string) error {
	_, perHour := a.policy.BotTimerLimits()
	if a.turnCounter().take(botID, perHour, false) {
		return nil
	}
	fields := map[string]any{"from": fromID, "via": via, "limit": perHour}
	a.log(botID, "bot_turn_cap", fields)
	if a.audit != nil && a.audit.Enabled() {
		rec := map[string]any{"event": "bot_turn_cap", "bot_id": botID}
		for k, v := range fields {
			rec[k] = v
		}
		a.audit.Write(rec)
	}
	return fmt.Errorf("recipient reached %d bot-started turns this hour (cli.lgb.max_scheduled_per_hour); message not sent", perHour)
}
