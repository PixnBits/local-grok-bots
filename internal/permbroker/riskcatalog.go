package permbroker

import (
	"sort"
	"strings"
)

// RiskRow is one read-only line of the risk table.
type RiskRow struct {
	Level      string   `json:"level"`
	Matches    []string `json:"matches"`
	AppliesTo  string   `json:"applies_to"`
	RaisedFrom string   `json:"raised_from,omitempty"`
}

// RiskCatalog is the shipped table plus policy rows that raise a level.
type RiskCatalog struct {
	Version  string    `json:"version"`
	Builtin  []RiskRow `json:"builtin"`
	Stricter []RiskRow `json:"stricter"`
}

// RiskTables returns the shipped rows and the policy raises on this engine.
func (e *Engine) RiskTables() RiskCatalog {
	cat := RiskCatalog{Version: TableVersion, Builtin: builtinRiskRows(), Stricter: []RiskRow{}}
	if e == nil {
		return cat
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, extra := range e.table.extra {
		base := builtinLevel(extra.Tool, extra.Argv)
		if Rank(extra.Level) <= Rank(base) {
			continue
		}
		match := strings.Join(extra.Argv, " ")
		if match == "" {
			match = normTool(extra.Tool)
		}
		cat.Stricter = append(cat.Stricter, RiskRow{
			Level: string(extra.Level), Matches: []string{match},
			AppliesTo: normTool(extra.Tool), RaisedFrom: string(base),
		})
	}
	return cat
}

func builtinRiskRows() []RiskRow {
	var rows []RiskRow
	walkGit(nil, gitTable(), &rows)
	walkGH([]string{"gh"}, ghTable(), &rows)
	for _, name := range []string{"head", "tail", "wc", "sort", "uniq", "cut", "grep", "jq"} {
		rows = append(rows, RiskRow{Level: string(LevelLow), Matches: []string{name}, AppliesTo: "shell"})
	}
	for _, pair := range []struct {
		name  string
		level Level
	}{
		{"read", LevelLow}, {"glob", LevelLow}, {"grep", LevelLow},
		{"write", LevelMedium}, {"edit", LevelMedium}, {"multiedit", LevelMedium}, {"notebookedit", LevelMedium},
		{"webfetch", LevelHigh}, {"websearch", LevelHigh}, {"task", LevelHigh},
	} {
		rows = append(rows, RiskRow{Level: string(pair.level), Matches: []string{pair.name}, AppliesTo: pair.name})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].AppliesTo != rows[j].AppliesTo {
			return rows[i].AppliesTo < rows[j].AppliesTo
		}
		return strings.Join(rows[i].Matches, " ") < strings.Join(rows[j].Matches, " ")
	})
	return rows
}

func walkGit(prefix []string, table map[string]gitCmd, rows *[]RiskRow) {
	names := make([]string, 0, len(table))
	for name := range table {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		cmd := table[name]
		argv := append(append([]string{}, prefix...), name)
		if prefix == nil {
			argv = append([]string{"git"}, name)
		}
		if cmd.level != "" {
			*rows = append(*rows, RiskRow{
				Level: string(cmd.level), Matches: []string{strings.Join(argv, " ")}, AppliesTo: "shell",
			})
		}
		if len(cmd.sub) > 0 {
			walkGit(argv, cmd.sub, rows)
		}
	}
}

func walkGH(prefix []string, table map[string]ghCmd, rows *[]RiskRow) {
	names := make([]string, 0, len(table))
	for name := range table {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		cmd := table[name]
		argv := append(append([]string{}, prefix...), name)
		if cmd.level != "" {
			*rows = append(*rows, RiskRow{
				Level: string(cmd.level), Matches: []string{strings.Join(argv, " ")}, AppliesTo: "shell",
			})
		}
		if len(cmd.sub) > 0 {
			walkGH(argv, cmd.sub, rows)
		}
	}
}
