package permbroker

import (
	"errors"
	"fmt"
	"strings"
)

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

// ValidateRisk rejects a policy entry that lowers a shipped level.
// An argv the table does not list has an unclassified floor, so any
// explicit level is a raise or an equal value. The shipped tables set
// the floor. They do not allow the command.
func ValidateRisk(entries []RiskEntry) error {
	for i, e := range entries {
		lvl, ok := parseLevel(string(e.Level))
		if !ok {
			return fmt.Errorf("%w (%d)", ErrBadLevel, i)
		}
		base := builtinLevel(e.Tool, e.Argv)
		if Rank(lvl) < Rank(base) {
			return fmt.Errorf("%w for %s", ErrLevelLowered, strings.Join(e.Argv, " "))
		}
	}
	return nil
}

// table is the shipped rows plus policy raises. A policy row never
// lowers the shipped level.
type table struct {
	extra []RiskEntry
}

func (t table) level(tool string, argv []string) Level {
	tool = normTool(tool)
	lvl := builtinLevel(tool, argv)
	for _, e := range t.extra {
		if normTool(e.Tool) != tool || !argvEqual(e.Argv, argv) {
			continue
		}
		if Rank(e.Level) > Rank(lvl) {
			lvl = e.Level
		}
	}
	for _, e := range t.extra {
		if normTool(e.Tool) != tool || e.Level != LevelCritical || len(e.Argv) == 0 || len(argv) < len(e.Argv) {
			continue
		}
		if argvEqual(e.Argv, argv[:len(e.Argv)]) && Rank(LevelCritical) > Rank(lvl) {
			lvl = LevelCritical
		}
	}
	return lvl
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
