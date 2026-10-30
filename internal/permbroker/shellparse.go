// Package-level shell parsing for exact-argv rules.
//
// This run accepts one simple command whose words are all literals.
// Anything else is not eligible and the engine asks. Run 2 fills Parts
// for compounds and tightens the wrapper list. ParseCommand stays the
// entry point so that work does not change callers.
package permbroker

import (
	"bytes"
	"strings"
	"unicode"

	"mvdan.cc/sh/v3/syntax"
)

// Part is one simple command inside a compound. This run leaves Parts
// empty. Run 2 fills one entry per pipeline stage so a task grant can
// cover each stage.
type Part struct {
	Argv []string
	Hash string
	Raw  string
}

// Parse is the normalized shape of one shell string.
type Parse struct {
	Eligible bool
	Compound bool
	Argv     []string
	Raw      string
	Parts    []Part
	Reason   string
}

// ParseCommand normalizes a shell command. Eligible is true only for a
// single simple command of literal words. Argv is those words after
// quote removal. A parse error, a bash/POSIX difference, a comment, a
// substitution, a glob, or a wrapper argv0 is not eligible.
func ParseCommand(src string) Parse {
	out := Parse{Raw: src}
	if src == "" || strings.TrimSpace(src) == "" {
		out.Reason = "empty"
		return out
	}
	if badShellSource(src) {
		out.Compound = true
		out.Reason = "unsupported syntax"
		return out
	}
	bash, err := parseLang(src, syntax.LangBash)
	if err != nil {
		out.Compound = true
		out.Reason = "parse"
		return out
	}
	posix, perr := parseLang(src, syntax.LangPOSIX)
	if perr != nil || !samePrint(bash, posix) {
		out.Compound = true
		out.Reason = "shell dialect"
		return out
	}
	if hasComment(bash) {
		out.Reason = "comment"
		out.Compound = true
		return out
	}
	if len(bash.Stmts) != 1 {
		out.Compound = true
		out.Reason = "compound"
		return out
	}
	st := bash.Stmts[0]
	if st == nil || st.Background || st.Coprocess || st.Negated || st.Cmd == nil {
		out.Compound = true
		out.Reason = "compound"
		return out
	}
	call, ok := st.Cmd.(*syntax.CallExpr)
	if !ok {
		out.Compound = true
		out.Reason = "compound"
		return out
	}
	if len(call.Assigns) > 0 {
		out.Reason = "assignment"
		return out
	}
	for _, r := range st.Redirs {
		if !redirOK(r) {
			out.Reason = "redirect"
			return out
		}
	}
	if len(call.Args) == 0 {
		out.Reason = "empty"
		return out
	}
	argv := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
		word, ok := literalWord(w)
		if !ok {
			out.Reason = "not a literal"
			return out
		}
		argv = append(argv, word)
	}
	if wrapperArgv(argv) {
		out.Reason = "wrapper"
		return out
	}
	out.Eligible = true
	out.Argv = argv
	return out
}

func badShellSource(src string) bool {
	if strings.Contains(src, "\\\n") || strings.Contains(src, "\\\r") || strings.ContainsRune(src, '\r') {
		return true
	}
	for _, r := range src {
		switch r {
		case '\u037e', '\uff1b', '\uff06', '\uff5c', '\u2223':
			return true
		}
		if r != '\t' && r != '\n' && unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func parseLang(src string, lang syntax.LangVariant) (*syntax.File, error) {
	p := syntax.NewParser(syntax.Variant(lang), syntax.KeepComments(true))
	return p.Parse(strings.NewReader(src), "")
}

func samePrint(a, b *syntax.File) bool {
	if a == nil || b == nil {
		return false
	}
	var ab, bb bytes.Buffer
	pr := syntax.NewPrinter()
	if err := pr.Print(&ab, a); err != nil {
		return false
	}
	if err := pr.Print(&bb, b); err != nil {
		return false
	}
	return ab.String() == bb.String()
}

func hasComment(f *syntax.File) bool {
	if f == nil || len(f.Last) > 0 {
		return true
	}
	for _, st := range f.Stmts {
		if st != nil && len(st.Comments) > 0 {
			return true
		}
	}
	return false
}

func redirOK(r *syntax.Redirect) bool {
	if r == nil || r.Hdoc != nil {
		return false
	}
	word, ok := literalWord(r.Word)
	if !ok {
		return false
	}
	fd := ""
	if r.N != nil {
		fd = r.N.Value
		if fd == "" || strings.ContainsAny(fd, "{}") {
			return false
		}
	}
	switch r.Op {
	case syntax.RdrOut:
		return word == "/dev/null" && (fd == "" || fd == "1" || fd == "2")
	case syntax.DplOut:
		return fd == "2" && word == "1"
	default:
		return false
	}
}

func literalWord(w *syntax.Word) (string, bool) {
	if w == nil || len(w.Parts) == 0 {
		return "", false
	}
	var b strings.Builder
	for _, part := range w.Parts {
		s, ok := literalPart(part, false)
		if !ok {
			return "", false
		}
		b.WriteString(s)
	}
	return b.String(), true
}

func literalPart(part syntax.WordPart, quoted bool) (string, bool) {
	switch n := part.(type) {
	case *syntax.Lit:
		if !quoted && unsafeBare(n.Value) {
			return "", false
		}
		return n.Value, true
	case *syntax.SglQuoted:
		if n.Dollar {
			return "", false
		}
		return n.Value, true
	case *syntax.DblQuoted:
		var b strings.Builder
		for _, inner := range n.Parts {
			s, ok := literalPart(inner, true)
			if !ok {
				return "", false
			}
			b.WriteString(s)
		}
		return b.String(), true
	default:
		return "", false
	}
}

func unsafeBare(s string) bool {
	if strings.ContainsAny(s, "*?[{~") || strings.Contains(s, "~") {
		return true
	}
	return false
}

func wrapperArgv(argv []string) bool {
	if len(argv) == 0 {
		return true
	}
	base := argv[0]
	if i := strings.LastIndexAny(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	switch base {
	case "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish",
		"env", "xargs", "eval", "exec", "source", ".", "command", "builtin",
		"sudo", "doas", "nohup", "timeout", "nice", "ionice", "stdbuf", "setsid",
		"python", "python2", "python3", "perl", "ruby", "node", "nodejs",
		"awk", "sed":
		return true
	}
	if base == "find" {
		for _, a := range argv[1:] {
			switch a {
			case "-exec", "-execdir", "-ok", "-okdir", "-delete":
				return true
			}
			if strings.HasPrefix(a, "-fprint") {
				return true
			}
		}
	}
	return false
}
