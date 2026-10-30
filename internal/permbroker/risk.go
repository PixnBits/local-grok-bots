package permbroker

import (
	"errors"
	"fmt"
	"strings"
)

// TableVersion is the starter table shipped with this broker.
// Run 2 replaces the rows. The version string changes with them.
const TableVersion = "builtin-2026-10-29.1"

// ErrLevelLowered is a startup error. Policy may raise a shipped level.
// It may not lower one.
var ErrLevelLowered = errors.New("policy risk level is lower than the shipped level")

// ErrBadLevel is a startup error for an unknown level name.
var ErrBadLevel = errors.New("risk level must be unclassified, low, medium, high, or critical")

// RiskEntry is one exact argv and the level it forces. Tool is shell
// for Bash and run_shell. An empty tool means shell.
type RiskEntry struct {
	Tool  string
	Argv  []string
	Level Level
}

// shipped is the starter table. It sets levels only.
// git push stays high so it cannot become a global rule.
// gh auth, gh secret, and gh ssh-key are critical as a prefix:
// gh auth token is critical too.
var shipped = []RiskEntry{
	{Tool: "shell", Argv: []string{"git", "status"}, Level: LevelLow},
	{Tool: "shell", Argv: []string{"git", "push"}, Level: LevelHigh},
	{Tool: "shell", Argv: []string{"gh", "auth"}, Level: LevelCritical},
	{Tool: "shell", Argv: []string{"gh", "secret"}, Level: LevelCritical},
	{Tool: "shell", Argv: []string{"gh", "ssh-key"}, Level: LevelCritical},
}

// ValidateRisk rejects a policy entry that lowers a shipped level.
// An argv the table does not list has an unclassified floor, so any
// explicit level is a raise or an equal value.
func ValidateRisk(entries []RiskEntry) error {
	for i, e := range entries {
		lvl, ok := parseLevel(string(e.Level))
		if !ok {
			return fmt.Errorf("%w (%d)", ErrBadLevel, i)
		}
		tool := normTool(e.Tool)
		if base, ok := shippedExact(tool, e.Argv); ok && Rank(lvl) < Rank(base) {
			return fmt.Errorf("%w for %s", ErrLevelLowered, strings.Join(e.Argv, " "))
		}
		if pre, ok := shippedCriticalPrefix(tool, e.Argv); ok && Rank(lvl) < Rank(pre) && !argvEqual(e.Argv, prefixArgv(tool, e.Argv)) {
			// A longer argv is classified by the critical prefix. Policy
			// may name that longer argv only at critical or above.
			return fmt.Errorf("%w for %s", ErrLevelLowered, strings.Join(e.Argv, " "))
		}
	}
	return nil
}

func prefixArgv(tool string, argv []string) []string {
	best := -1
	var got []string
	for _, e := range shipped {
		if e.Tool != tool || e.Level != LevelCritical || len(e.Argv) > len(argv) || len(e.Argv) <= best {
			continue
		}
		if argvEqual(e.Argv, argv[:len(e.Argv)]) {
			best = len(e.Argv)
			got = e.Argv
		}
	}
	return got
}

// table is the shipped rows plus policy raises.
type table struct {
	extra []RiskEntry
}

func (t table) level(tool string, argv []string) Level {
	tool = normTool(tool)
	lvl := LevelUnclassified
	if base, ok := shippedExact(tool, argv); ok {
		lvl = base
	}
	if pre, ok := shippedCriticalPrefix(tool, argv); ok && Rank(pre) > Rank(lvl) {
		lvl = pre
	}
	for _, e := range t.extra {
		if normTool(e.Tool) != tool || !argvEqual(e.Argv, argv) {
			continue
		}
		if Rank(e.Level) > Rank(lvl) {
			lvl = e.Level
		}
	}
	// A policy row that names a critical prefix's longer argv.
	for _, e := range t.extra {
		if normTool(e.Tool) != tool || e.Level != LevelCritical {
			continue
		}
		if len(e.Argv) > 0 && len(argv) >= len(e.Argv) && argvEqual(e.Argv, argv[:len(e.Argv)]) && Rank(e.Level) > Rank(lvl) {
			lvl = e.Level
		}
	}
	return lvl
}

func shippedExact(tool string, argv []string) (Level, bool) {
	for _, e := range shipped {
		if e.Tool == tool && argvEqual(e.Argv, argv) {
			return e.Level, true
		}
	}
	return "", false
}

func shippedCriticalPrefix(tool string, argv []string) (Level, bool) {
	best := 0
	var lvl Level
	for _, e := range shipped {
		if e.Tool != tool || e.Level != LevelCritical || len(e.Argv) == 0 || len(e.Argv) > len(argv) {
			continue
		}
		if argvEqual(e.Argv, argv[:len(e.Argv)]) && len(e.Argv) >= best {
			best = len(e.Argv)
			lvl = e.Level
		}
	}
	return lvl, best > 0
}

func normTool(tool string) string {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "", "shell", "bash", "run_shell":
		return "shell"
	default:
		return strings.ToLower(strings.TrimSpace(tool))
	}
}

func argvEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isShellTool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "bash", "run_shell", "shell":
		return true
	default:
		return false
	}
}
