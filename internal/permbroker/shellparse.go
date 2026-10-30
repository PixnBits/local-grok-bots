// Shell parsing for exact-argv rules.
//
// A single simple command of literal words can match a rule. A compound
// is a list or a pipe of those commands. Anything else asks. The argv
// vector, not the source text, is the rule key.
package permbroker

import (
	"bytes"
	"strings"
	"unicode"

	"mvdan.cc/sh/v3/syntax"
)

// Part is one simple command inside a compound.
type Part struct {
	Argv []string
	Hash string
	Raw  string
}

// Parse is the normalized shape of one shell string.
type Parse struct {
	Eligible  bool
	Compound  bool
	Grantable bool
	Void      bool
	Argv      []string
	Raw       string
	Parts     []Part
	LeadingCD string
	Reason    string
}

// ParseCommand normalizes a shell command. Eligible is true only for a
// single simple command of literal words. A compound lists one part per
// simple command when every part is literal. Grantable is the syntactic
// shape a task grant may cover. The engine still re-checks each part.
func ParseCommand(src string) Parse {
	out := Parse{Raw: src}
	if strings.TrimSpace(src) == "" {
		out.Reason = "empty"
		return out
	}
	if badShellSource(src) {
		out.Compound = looksCompound(src)
		out.Reason = "unsupported syntax"
		return out
	}
	bash, err := parseLang(src, syntax.LangBash)
	if err != nil {
		out.Compound = looksCompound(src)
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
		out.Compound = true
		out.Reason = "comment"
		return out
	}
	return walkFile(src, bash)
}

func looksCompound(src string) bool {
	return strings.ContainsAny(src, ";&|") || strings.Contains(src, "\n")
}

func badShellSource(src string) bool {
	if strings.Contains(src, "\\\n") || strings.Contains(src, "\\\r") || strings.ContainsRune(src, '\r') {
		return true
	}
	for _, r := range src {
		switch r {
		case '\u037e', '\uff1b', '\uff06', '\uff5c', '\u2223', '\ufeff':
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
		if stmtHasComment(st) {
			return true
		}
	}
	return false
}

func stmtHasComment(st *syntax.Stmt) bool {
	if st == nil {
		return false
	}
	if len(st.Comments) > 0 {
		return true
	}
	if bin, ok := st.Cmd.(*syntax.BinaryCmd); ok {
		return stmtHasComment(bin.X) || stmtHasComment(bin.Y)
	}
	return false
}

type stage struct {
	argv       []string
	downstream bool
}

func walkFile(src string, f *syntax.File) Parse {
	out := Parse{Raw: src}
	if f == nil || len(f.Stmts) == 0 {
		out.Reason = "empty"
		return out
	}
	var stages []stage
	for i, st := range f.Stmts {
		got, reason := walkStmt(st, false)
		if reason != "" {
			out.Reason = reason
			out.Compound = len(f.Stmts) > 1 || stmtCompound(st)
			return out
		}
		if i > 0 {
			for j := range got {
				got[j].downstream = false
			}
		}
		stages = append(stages, got...)
	}
	return finishWalk(out, stages)
}

func stmtCompound(st *syntax.Stmt) bool {
	if st == nil || st.Cmd == nil {
		return false
	}
	_, ok := st.Cmd.(*syntax.BinaryCmd)
	return ok || st.Background
}

func walkStmt(st *syntax.Stmt, downstream bool) ([]stage, string) {
	if st == nil || st.Cmd == nil {
		return nil, "empty"
	}
	if st.Background || st.Coprocess || st.Negated {
		return nil, "compound"
	}
	for _, r := range st.Redirs {
		if !redirOK(r) {
			return nil, "redirect"
		}
	}
	switch cmd := st.Cmd.(type) {
	case *syntax.CallExpr:
		argv, reason := callArgv(cmd)
		if reason != "" {
			return nil, reason
		}
		return []stage{{argv: argv, downstream: downstream}}, ""
	case *syntax.BinaryCmd:
		switch cmd.Op {
		case syntax.AndStmt, syntax.OrStmt:
			left, reason := walkStmt(cmd.X, downstream)
			if reason != "" {
				return nil, reason
			}
			right, reason := walkStmt(cmd.Y, downstream)
			if reason != "" {
				return nil, reason
			}
			return append(left, right...), ""
		case syntax.Pipe:
			left, reason := walkStmt(cmd.X, downstream)
			if reason != "" {
				return nil, reason
			}
			right, reason := walkStmt(cmd.Y, true)
			if reason != "" {
				return nil, reason
			}
			for i := range right {
				right[i].downstream = true
			}
			return append(left, right...), ""
		default:
			return nil, "compound"
		}
	default:
		return nil, "compound"
	}
}

func finishWalk(out Parse, stages []stage) Parse {
	if len(stages) == 0 {
		out.Reason = "empty"
		return out
	}
	parts := make([]Part, 0, len(stages))
	grantable := true
	void := false
	var leadingCD string
	for i, st := range stages {
		if len(st.argv) == 0 {
			grantable = false
			continue
		}
		if wrapperArgv(st.argv) {
			grantable = false
		}
		if st.downstream && !filterArgv(st.argv) {
			grantable = false
		}
		if !st.downstream && !producerOK(st.argv) {
			grantable = false
		}
		v, cd := stateVoid(st.argv)
		if v {
			void = true
			grantable = false
		}
		if cd {
			if i != 0 || st.downstream || len(st.argv) != 2 {
				void = true
				grantable = false
			} else if leadingCD == "" {
				leadingCD = st.argv[1]
			} else {
				void = true
				grantable = false
			}
		}
		parts = append(parts, Part{Argv: append([]string(nil), st.argv...), Raw: strings.Join(st.argv, " ")})
	}
	if len(stages) == 1 && !stages[0].downstream {
		if len(parts) == 0 {
			out.Reason = "empty"
			out.Grantable = false
			return out
		}
		out.Argv = parts[0].Argv
		out.Eligible = grantable && !void && leadingCD == "" && !wrapperArgv(out.Argv)
		out.Grantable = false
		out.Void = void
		if !out.Eligible && out.Reason == "" {
			switch {
			case void:
				out.Reason = "state"
			case wrapperArgv(out.Argv):
				out.Reason = "wrapper"
			default:
				out.Reason = "not eligible"
			}
		}
		if out.Eligible {
			out.Reason = ""
		}
		return out
	}
	out.Compound = true
	out.Eligible = false
	out.Parts = parts
	out.Void = void
	out.LeadingCD = leadingCD
	out.Grantable = grantable && !void
	if !out.Grantable && out.Reason == "" {
		out.Reason = "compound"
	}
	return out
}

func callArgv(call *syntax.CallExpr) ([]string, string) {
	if call == nil {
		return nil, "empty"
	}
	if len(call.Assigns) > 0 {
		return nil, "assignment"
	}
	if len(call.Args) == 0 {
		return nil, "empty"
	}
	argv := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
		word, ok := literalWord(w)
		if !ok {
			return nil, "not a literal"
		}
		argv = append(argv, word)
	}
	return argv, ""
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
	return strings.ContainsAny(s, "*?[{~") || strings.Contains(s, "~")
}

func baseName(argv0 string) string {
	base := argv0
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	return base
}

func wrapperArgv(argv []string) bool {
	if len(argv) == 0 {
		return true
	}
	switch baseName(argv[0]) {
	case "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish",
		"env", "xargs", "eval", "exec", "source", ".", "command", "builtin",
		"sudo", "doas", "nohup", "timeout", "nice", "ionice", "stdbuf", "setsid",
		"python", "python2", "python3", "perl", "ruby", "node", "nodejs",
		"awk", "sed", "tee":
		return true
	}
	if baseName(argv[0]) == "find" {
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

func stateVoid(argv []string) (void bool, cd bool) {
	if len(argv) == 0 {
		return true, false
	}
	switch baseName(argv[0]) {
	case "export", "alias", "set", "shopt", "trap", "source", "ln":
		return true, false
	case ".":
		return true, false
	case "cd":
		return false, true
	case "git":
		if gitSubcommand(argv) == "config" || gitSubcommand(argv) == "remote" {
			return true, false
		}
	}
	return false, false
}

// producerOK rejects a producer that reads a pattern or program file.
func producerOK(argv []string) bool {
	if len(argv) == 0 || wrapperArgv(argv) {
		return false
	}
	switch baseName(argv[0]) {
	case "grep":
		return grepFlagsOK(argv[1:])
	case "jq":
		return jqFlagsOK(argv[1:])
	default:
		return true
	}
}
