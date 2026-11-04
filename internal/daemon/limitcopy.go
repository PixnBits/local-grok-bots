package daemon

import "fmt"

// Limit sentences shared with web/app.js. The words match the JS helpers.
// Parsers still decide what is accepted. This file only builds the text.

const (
	msgDurationExample = "Enter a time like 90s, 5m or 1h."
	msgWholeSeconds    = "Use whole seconds, like 2s."
)

func limitLabel(field string) string {
	switch field {
	case "tool_rounds":
		return "Tool rounds"
	case "shell_timeout":
		return "Shell timeout"
	default:
		return "Run timeout"
	}
}

// aboveCeilingMessage is the 400 text when a limit is above its ceiling.
// source is the plain ceiling name.
func aboveCeilingMessage(field, ceiling, source string) string {
	label := limitLabel(field)
	switch source {
	case "your administrator":
		return fmt.Sprintf("%s can be at most %s, the most your administrator allows. Enter %s or less.", label, ceiling, ceiling)
	case "this system":
		return fmt.Sprintf("%s can be at most %s on this system. Enter %s or less.", label, ceiling, ceiling)
	case "policy.toml":
		return fmt.Sprintf("%s can be at most %s (set in policy.toml). Enter %s or less, or leave it blank to use %s.", label, ceiling, ceiling, ceiling)
	default:
		return fmt.Sprintf("%s can be at most %s. Enter %s or less, or leave it blank.", label, ceiling, ceiling)
	}
}

func toolRoundsRangeMessage(ceiling int) string {
	if ceiling < 1 {
		ceiling = 1
	}
	return fmt.Sprintf("Enter a whole number from 1 to %d.", ceiling)
}

func roundsUnit(n int) string {
	if n == 1 {
		return "tool round"
	}
	return "tool rounds"
}

// ceilingParen is the parenthetical for a ceiling that is in force.
func ceilingParen(source string) string {
	switch source {
	case "policy.toml":
		return "set in policy.toml"
	case "your administrator":
		return "the most your administrator allows"
	case "this system":
		return "the limit on this system"
	default:
		return "the built-in default"
	}
}

// shellParen is the parenthetical in a shell-timeout tool result.
func shellParen(botInForce bool, source string) string {
	if botInForce {
		return "shell timeout set on this bot"
	}
	switch source {
	case "policy.toml":
		return "shell timeout, set in policy.toml"
	case "your administrator":
		return "shell timeout, the most your administrator allows"
	case "this system":
		return "shell timeout on this system"
	default:
		return "shell timeout, the built-in default"
	}
}
