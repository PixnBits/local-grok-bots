package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func (a *App) effectiveRunTimeout(bot store.Bot, pol policy.Policy) time.Duration {
	ceil, _ := pol.RunTimeoutCeiling(pol.UsesCLI())
	if bot.RunTimeout > 0 {
		d := bot.RunTimeout.Duration()
		if d > 0 && d < ceil {
			return d
		}
	}
	return ceil
}

func (a *App) effectiveToolRounds(bot store.Bot, pol policy.Policy) int {
	ceil := pol.EffectiveToolRounds()
	if bot.ToolRounds > 0 && bot.ToolRounds < ceil {
		return bot.ToolRounds
	}
	return ceil
}

func (a *App) effectiveShellTimeout(bot store.Bot, pol policy.Policy) time.Duration {
	ceil := pol.EffectiveShellTimeout()
	if bot.ShellTimeout > 0 {
		d := bot.ShellTimeout.Duration()
		if d > 0 && d < ceil {
			return d
		}
	}
	return ceil
}

func (a *App) shellCap(bot store.Bot) time.Duration {
	if shellRunCap != policy.DefaultOllamaShellTimeout {
		return shellRunCap
	}
	if a == nil {
		return shellRunCap
	}
	return a.effectiveShellTimeout(bot, a.effPol(bot.ID))
}

func (a *App) botLimits(b store.Bot) *store.BotLimits {
	pol := a.effPol(b.ID)
	runCeil, runSrc := pol.RunTimeoutCeiling(pol.UsesCLI())
	roundCeil, roundSrc := pol.ToolRoundsCeiling()
	shellCeil, shellSrc := pol.ShellTimeoutCeiling()
	runVal := a.effectiveRunTimeout(b, pol)
	roundVal := a.effectiveToolRounds(b, pol)
	shellVal := a.effectiveShellTimeout(b, pol)
	return &store.BotLimits{
		RunTimeout: store.LimitDuration{
			Value:         compactDuration(runVal),
			Source:        limitSource(b.RunTimeout.Duration() > 0 && b.RunTimeout.Duration() <= runCeil),
			Ceiling:       compactDuration(runCeil),
			CeilingSource: runSrc,
			CeilingKey:    pol.RunTimeoutCeilingKey(pol.UsesCLI()),
		},
		ToolRounds: store.LimitInt{
			Value:         roundVal,
			Source:        limitSource(b.ToolRounds > 0 && b.ToolRounds <= roundCeil),
			Ceiling:       roundCeil,
			CeilingSource: roundSrc,
			CeilingKey:    pol.ToolRoundsCeilingKey(),
		},
		ShellTimeout: store.LimitDuration{
			Value:         compactDuration(shellVal),
			Source:        limitSource(b.ShellTimeout.Duration() > 0 && b.ShellTimeout.Duration() <= shellCeil),
			Ceiling:       compactDuration(shellCeil),
			CeilingSource: shellSrc,
			CeilingKey:    pol.ShellTimeoutCeilingKey(),
		},
	}
}

func limitSource(botInForce bool) string {
	if botInForce {
		return "bot"
	}
	return "policy"
}

func (a *App) runTimeoutOrigin(bot store.Bot, pol policy.Policy) string {
	ceil, src := pol.RunTimeoutCeiling(pol.UsesCLI())
	botSet := bot.RunTimeout > 0 && bot.RunTimeout.Duration() <= ceil
	if botSet {
		return "set on this bot"
	}
	return ceilingParen(src)
}

func toolRoundLimitBody(n, botRounds, ceiling int, ceilingSource string) string {
	unit := roundsUnit(n)
	if botRounds > 0 && botRounds < ceiling {
		return fmt.Sprintf("The run used all %d %s (set on this bot). Press Continue, or raise the limit under Permissions & access, up to %d.", n, unit, ceiling)
	}
	head := fmt.Sprintf("The run used all %d %s (%s).", n, unit, ceilingParen(ceilingSource))
	switch ceilingSource {
	case "policy.toml":
		return head + " Press Continue, or ask whoever manages policy.toml to raise it."
	case "your administrator":
		return head + " Press Continue."
	default:
		return head + " Press Continue, or raise the limit in policy.toml."
	}
}

func (a *App) shellCapMessage(bot store.Bot, cap time.Duration) string {
	pol := policy.Policy{}
	if a != nil {
		pol = a.effPol(bot.ID)
	}
	ceil, src := pol.ShellTimeoutCeiling()
	botSet := bot.ShellTimeout > 0 && bot.ShellTimeout.Duration() <= ceil
	return fmt.Sprintf("stopped after %s (%s)", compactDuration(cap), shellParen(botSet, src))
}

func (a *App) auditLimitChanges(oldBot, newBot store.Bot, by string) {
	if a == nil || a.audit == nil || !a.audit.Enabled() {
		return
	}
	type pair struct {
		field string
		old   any
		new   any
	}
	var changes []pair
	if oldBot.RunTimeout != newBot.RunTimeout {
		changes = append(changes, pair{"run_timeout", store.CompactDuration(oldBot.RunTimeout.Duration()), store.CompactDuration(newBot.RunTimeout.Duration())})
	}
	if oldBot.ShellTimeout != newBot.ShellTimeout {
		changes = append(changes, pair{"shell_timeout", store.CompactDuration(oldBot.ShellTimeout.Duration()), store.CompactDuration(newBot.ShellTimeout.Duration())})
	}
	if oldBot.ToolRounds != newBot.ToolRounds {
		changes = append(changes, pair{"tool_rounds", oldBot.ToolRounds, newBot.ToolRounds})
	}
	for _, c := range changes {
		a.audit.Write(map[string]any{
			"action": "bot_limits_changed",
			"bot_id": newBot.ID,
			"by":     by,
			"field":  c.field,
			"old":    c.old,
			"new":    c.new,
		})
	}
}

func parseOptionalDuration(raw json.RawMessage) (time.Duration, error) {
	if string(raw) == "null" || string(raw) == `""` {
		return 0, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, errors.New(msgDurationExample)
	}
	return parseDurationString(s)
}

func parseOptionalToolRounds(raw json.RawMessage, ceiling int) (int, error) {
	reject := func() (int, error) {
		return 0, errors.New(toolRoundsRangeMessage(ceiling))
	}
	if string(raw) == "null" {
		return 0, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return reject()
	}
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err != nil || n.String() != strconv.FormatInt(i, 10) {
			return reject()
		}
		if i == 0 {
			return 0, nil
		}
		if i < 1 || i > 100 {
			return reject()
		}
		return int(i), nil
	default:
		return reject()
	}
}

func parseDurationString(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, errors.New(msgDurationExample)
	}
	if err := requireWholeSeconds(d); err != nil {
		return 0, err
	}
	return d, nil
}

func requireWholeSeconds(d time.Duration) error {
	if d >= time.Second && d%time.Second == 0 {
		return nil
	}
	return errors.New(msgWholeSeconds)
}

func (a *App) checkBotLimitCeilings(pol policy.Policy, run, shell time.Duration, rounds int, runSet, shellSet, roundsSet bool) error {
	if runSet && run > 0 {
		if err := requireWholeSeconds(run); err != nil {
			return err
		}
		ceil, src := pol.RunTimeoutCeiling(pol.UsesCLI())
		if run > ceil {
			return errors.New(aboveCeilingMessage("run_timeout", compactDuration(ceil), src))
		}
	}
	if shellSet && shell > 0 {
		if err := requireWholeSeconds(shell); err != nil {
			return err
		}
		ceil, src := pol.ShellTimeoutCeiling()
		if shell > ceil {
			return errors.New(aboveCeilingMessage("shell_timeout", compactDuration(ceil), src))
		}
	}
	if roundsSet && rounds > 0 {
		ceil, src := pol.ToolRoundsCeiling()
		if rounds > ceil {
			return errors.New(aboveCeilingMessage("tool_rounds", strconv.Itoa(ceil), src))
		}
	}
	return nil
}

// noteShellSignalRefused records a PID Trim would not signal.
func (a *App) noteShellSignalRefused(bot store.Bot, pid int, reason string) {
	if a == nil {
		return
	}
	detail := map[string]any{
		"action": "shell_signal_refused",
		"bot_id": bot.ID,
		"pid":    pid,
		"reason": reason,
	}
	if bot.ActiveRunID != nil && *bot.ActiveRunID != "" {
		detail["run_id"] = *bot.ActiveRunID
	}
	a.log(bot.ID, "shell_signal_refused", detail)
	if a.audit != nil && a.audit.Enabled() {
		rec := make(map[string]any, len(detail))
		for k, v := range detail {
			rec[k] = v
		}
		a.audit.Write(rec)
	}
}

// noteClampedLimits logs each stored limit that is above the published ceiling.
// The same bot, field, stored value, effective value, and source are logged once per process.
func (a *App) noteClampedLimits(pol policy.Policy) {
	if a == nil || a.st == nil {
		return
	}
	bots, err := a.st.ListBots()
	if err != nil {
		return
	}
	runCeil, runSrc := pol.RunTimeoutCeiling(pol.UsesCLI())
	roundCeil, roundSrc := pol.ToolRoundsCeiling()
	shellCeil, shellSrc := pol.ShellTimeoutCeiling()
	runKey := pol.RunTimeoutCeilingKey(pol.UsesCLI())
	roundKey := pol.ToolRoundsCeilingKey()
	shellKey := pol.ShellTimeoutCeilingKey()
	for _, b := range bots {
		if d := b.RunTimeout.Duration(); d > runCeil {
			a.noteClamp(b.ID, "run_timeout", compactDuration(d), compactDuration(runCeil), runSrc, runKey)
		}
		if b.ToolRounds > roundCeil {
			a.noteClamp(b.ID, "tool_rounds", b.ToolRounds, roundCeil, roundSrc, roundKey)
		}
		if d := b.ShellTimeout.Duration(); d > shellCeil {
			a.noteClamp(b.ID, "shell_timeout", compactDuration(d), compactDuration(shellCeil), shellSrc, shellKey)
		}
	}
}

func (a *App) noteClamp(botID, field string, stored, effective any, source, configKey string) {
	key := fmt.Sprintf("%s|%s|%v|%v|%s|%s", botID, field, stored, effective, source, configKey)
	a.clampMu.Lock()
	if a.clampSeen == nil {
		a.clampSeen = map[string]struct{}{}
	}
	if _, ok := a.clampSeen[key]; ok {
		a.clampMu.Unlock()
		return
	}
	a.clampSeen[key] = struct{}{}
	a.clampMu.Unlock()
	detail := map[string]any{
		"bot_id":    botID,
		"field":     field,
		"stored":    stored,
		"effective": effective,
		"source":    source,
	}
	if configKey != "" {
		detail["key"] = configKey
	}
	a.log(botID, "bot_limit_clamped", detail)
	if a.audit != nil && a.audit.Enabled() {
		rec := map[string]any{
			"action":    "bot_limit_clamped",
			"bot_id":    botID,
			"field":     field,
			"stored":    stored,
			"effective": effective,
			"source":    source,
		}
		if configKey != "" {
			rec["key"] = configKey
		}
		a.audit.Write(rec)
	}
}
