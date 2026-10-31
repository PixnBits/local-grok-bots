package permbroker

import (
	"runtime"
	"strings"
	"unicode"

	"mvdan.cc/sh/v3/syntax"
)

// autoAllowGOOS is the OS that may auto-allow. Tests set it.
// A deny rule does not use this.
var autoAllowGOOS = runtime.GOOS

// autoAllowOK is the choke for every allow that is not a human
// one-time approval: a saved rule, a task grant, and a confirmed
// legacy allow. Off Linux, or when any word is not literal, it is false.
func autoAllowOK(in inspected) bool {
	if autoAllowGOOS != "linux" {
		return false
	}
	if !in.Literal {
		return false
	}
	return true
}

// surfaceParse recovers argv text when ParseCommand stopped because a
// word was not literal. The caller still marks the command non-literal.
// A parse that is not that case, or a word with no source span, is refused.
func surfaceParse(src string) (Parse, []string, bool) {
	if badShellSource(src) {
		return Parse{}, nil, false
	}
	f, err := parseLang(src, syntax.LangBash)
	if err != nil {
		return Parse{}, nil, false
	}
	stages, ops, nonLit, ok := surfaceFile(src, f)
	if !ok || !nonLit {
		return Parse{}, nil, false
	}
	out := finishWalk(Parse{Raw: src}, stages)
	if len(out.Argv) == 0 && len(out.Parts) == 0 {
		return Parse{}, nil, false
	}
	return out, ops, true
}

// commandOperators lists joining operators for a command the parser accepts.
// A command it does not walk yields no operators.
func commandOperators(src string) []string {
	if badShellSource(src) {
		return nil
	}
	f, err := parseLang(src, syntax.LangBash)
	if err != nil {
		return nil
	}
	_, ops, _, ok := surfaceFile(src, f)
	if !ok {
		return nil
	}
	return ops
}

func surfaceFile(src string, f *syntax.File) (stages []stage, ops []string, nonLit bool, ok bool) {
	if f == nil || len(f.Stmts) == 0 {
		return nil, nil, false, false
	}
	for i, st := range f.Stmts {
		if i > 0 {
			ops = append(ops, ";")
		}
		got, stop, nl, good := surfaceStmt(src, st)
		if !good {
			return nil, nil, false, false
		}
		if nl {
			nonLit = true
		}
		ops = append(ops, stop...)
		stages = append(stages, got...)
	}
	if len(stages) == 0 {
		return nil, nil, false, false
	}
	return stages, ops, nonLit, true
}

func surfaceStmt(src string, st *syntax.Stmt) ([]stage, []string, bool, bool) {
	if st == nil || st.Cmd == nil {
		return nil, nil, false, false
	}
	if st.Background || st.Coprocess || st.Negated {
		return nil, nil, false, false
	}
	for _, r := range st.Redirs {
		if !redirOK(r) {
			return nil, nil, false, false
		}
	}
	switch cmd := st.Cmd.(type) {
	case *syntax.CallExpr:
		argv, nl, good := looseCallArgv(src, cmd)
		if !good {
			return nil, nil, false, false
		}
		return []stage{{argv: argv}}, nil, nl, true
	case *syntax.BinaryCmd:
		name, known := binOpName(cmd.Op)
		if !known {
			return nil, nil, false, false
		}
		left, lops, lnl, lok := surfaceStmt(src, cmd.X)
		if !lok {
			return nil, nil, false, false
		}
		right, rops, rnl, rok := surfaceStmt(src, cmd.Y)
		if !rok {
			return nil, nil, false, false
		}
		if cmd.Op == syntax.Pipe || cmd.Op == syntax.PipeAll {
			for i := range right {
				right[i].downstream = true
			}
		}
		ops := append(append([]string{}, lops...), name)
		ops = append(ops, rops...)
		return append(left, right...), ops, lnl || rnl, true
	default:
		return nil, nil, false, false
	}
}

func looseCallArgv(src string, call *syntax.CallExpr) ([]string, bool, bool) {
	if call == nil || len(call.Assigns) > 0 || len(call.Args) == 0 {
		return nil, false, false
	}
	nonLit := false
	argv := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
		if s, ok := literalWord(w); ok {
			argv = append(argv, s)
			continue
		}
		s, ok := wordSource(src, w)
		if !ok {
			return nil, false, false
		}
		nonLit = true
		argv = append(argv, s)
	}
	return argv, nonLit, true
}

func wordSource(src string, w *syntax.Word) (string, bool) {
	if w == nil || len(w.Parts) == 0 {
		return "", false
	}
	start := int(w.Pos().Offset())
	end := int(w.End().Offset())
	if start < 0 || end <= start || end > len(src) {
		return "", false
	}
	s := src[start:end]
	if strings.TrimSpace(s) == "" {
		return "", false
	}
	return s, true
}

func binOpName(op syntax.BinCmdOperator) (string, bool) {
	switch op {
	case syntax.AndStmt:
		return "&&", true
	case syntax.OrStmt:
		return "||", true
	case syntax.Pipe:
		return "|", true
	case syntax.PipeAll:
		return "|&", true
	default:
		return "", false
	}
}

// cleanAdvisory drops control characters and keeps the first 300 bytes
// of what remains. The cut is on bytes so a long note cannot grow the card.
func cleanAdvisory(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	return clip(s, 300)
}

// flattenSpace turns runs of spaces and newlines into one space.
func flattenSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// clipText is cleanAdvisory with a caller-chosen limit.
func clipText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	return clip(s, n)
}
