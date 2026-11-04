package daemon

import (
	"bytes"
	"encoding/json"
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
	runCeil, _ := pol.RunTimeoutCeiling(pol.UsesCLI())
	roundCeil, _ := pol.ToolRoundsCeiling()
	shellCeil, _ := pol.ShellTimeoutCeiling()
	runVal := a.effectiveRunTimeout(b, pol)
	roundVal := a.effectiveToolRounds(b, pol)
	shellVal := a.effectiveShellTimeout(b, pol)
	return &store.BotLimits{
		RunTimeout: store.LimitDuration{
			Value:   compactDuration(runVal),
			Source:  limitSource(b.RunTimeout.Duration() > 0 && b.RunTimeout.Duration() <= runCeil),
			Ceiling: compactDuration(runCeil),
		},
		ToolRounds: store.LimitInt{
			Value:   roundVal,
			Source:  limitSource(b.ToolRounds > 0 && b.ToolRounds <= roundCeil),
			Ceiling: roundCeil,
		},
		ShellTimeout: store.LimitDuration{
			Value:   compactDuration(shellVal),
			Source:  limitSource(b.ShellTimeout.Duration() > 0 && b.ShellTimeout.Duration() <= shellCeil),
			Ceiling: compactDuration(shellCeil),
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
	ceil, _ := pol.RunTimeoutCeiling(pol.UsesCLI())
	if bot.RunTimeout > 0 && bot.RunTimeout.Duration() <= ceil {
		return "run_timeout, set on this bot"
	}
	if pol.UsesCLI() {
		return "cli.turn_timeout in policy.toml"
	}
	return "ollama.run_timeout in policy.toml"
}

func toolRoundLimitBody(n int, botSet bool, ceiling int) string {
	if botSet {
		return fmt.Sprintf("The run used all %d tool rounds (tool_rounds, set on this bot). Raise it under Permissions & access, up to %d.", n, ceiling)
	}
	return fmt.Sprintf("The run used all %d tool rounds (ollama.tool_rounds in policy.toml).", n)
}

func (a *App) shellCapMessage(bot store.Bot, cap time.Duration) string {
	shown := compactDuration(cap)
	pol := a.effPol(bot.ID)
	ceil := pol.EffectiveShellTimeout()
	if bot.ShellTimeout > 0 && bot.ShellTimeout.Duration() <= ceil {
		return fmt.Sprintf("stopped after %s (shell_timeout set on this bot)", shown)
	}
	return fmt.Sprintf("stopped after %s (shell_timeout from policy)", shown)
}

func (a *App) auditLimitChanges(oldBot, newBot store.Bot) {
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
			"field":  c.field,
			"old":    c.old,
			"new":    c.new,
		})
	}
}

func aboveCeilingMessage(field, value, ceiling, source string) string {
	return fmt.Sprintf("%s %s is above the limit of %s set by %s", field, value, ceiling, source)
}

func parseOptionalDuration(raw json.RawMessage, field string) (time.Duration, error) {
	if string(raw) == "null" || string(raw) == `""` {
		return 0, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, fmt.Errorf("invalid %s", field)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid %s", field)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", field)
	}
	return d, nil
}

func parseOptionalToolRounds(raw json.RawMessage) (int, error) {
	if string(raw) == "null" {
		return 0, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return 0, fmt.Errorf("invalid tool_rounds")
	}
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err != nil || n.String() != strconv.FormatInt(i, 10) {
			return 0, fmt.Errorf("invalid tool_rounds")
		}
		if i == 0 {
			return 0, nil
		}
		if i < 0 {
			return 0, fmt.Errorf("tool_rounds must be positive")
		}
		if i < 1 || i > 100 {
			return 0, fmt.Errorf("tool_rounds must be an integer from 1 to 100")
		}
		return int(i), nil
	default:
		return 0, fmt.Errorf("invalid tool_rounds")
	}
}

func parseDurationString(s, field string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid %s", field)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", field)
	}
	return d, nil
}

func (a *App) checkBotLimitCeilings(pol policy.Policy, run, shell time.Duration, rounds int, runSet, shellSet, roundsSet bool) error {
	if runSet && run > 0 {
		ceil, src := pol.RunTimeoutCeiling(pol.UsesCLI())
		if run > ceil {
			return fmt.Errorf("%s", aboveCeilingMessage("run_timeout", compactDuration(run), compactDuration(ceil), src))
		}
	}
	if shellSet && shell > 0 {
		if shell < time.Second {
			return fmt.Errorf("shell_timeout must be at least 1s")
		}
		ceil, src := pol.ShellTimeoutCeiling()
		if shell > ceil {
			return fmt.Errorf("%s", aboveCeilingMessage("shell_timeout", compactDuration(shell), compactDuration(ceil), src))
		}
	}
	if roundsSet && rounds > 0 {
		ceil, src := pol.ToolRoundsCeiling()
		if rounds > ceil {
			return fmt.Errorf("%s", aboveCeilingMessage("tool_rounds", strconv.Itoa(rounds), strconv.Itoa(ceil), src))
		}
	}
	return nil
}
