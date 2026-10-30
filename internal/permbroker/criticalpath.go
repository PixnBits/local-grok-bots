package permbroker

import (
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// critEnv is the home directories and managed environment used while
// resolving a path. Command substitution is not executed.
type critEnv struct {
	homes []string
	env   []string
}

// resolvedCritical is the path-resolution half of the critical check.
// It is separate from the lexical scan so a caller can see which one matched.
func resolvedCritical(req Request, in inspected, crit []string, ce critEnv) bool {
	return criticalResolved(req, in, crit, ce)
}

func criticalResolved(req Request, in inspected, crit []string, ce critEnv) bool {
	crit = normalizeCritical(crit)
	if len(crit) == 0 {
		return false
	}
	cwd := ""
	if filepath.IsAbs(req.Cwd) {
		cwd = filepath.Clean(req.Cwd)
	}
	if isShellTool(req.ToolName) && strings.TrimSpace(in.Raw) != "" {
		if shellCritical(in.Raw, cwd, crit, ce) {
			return true
		}
	}
	for _, p := range toolPaths(req.ToolInput) {
		if wordCritical(p, cwd, crit, ce) {
			return true
		}
	}
	for _, a := range in.Argv {
		if wordCritical(a, cwd, crit, ce) {
			return true
		}
	}
	for _, p := range in.Parts {
		for _, a := range p.Argv {
			if wordCritical(a, cwd, crit, ce) {
				return true
			}
		}
	}
	return false
}

func shellCritical(src, cwd string, crit []string, ce critEnv) bool {
	f, err := parseLang(src, syntax.LangBash)
	if err != nil || f == nil {
		return rawTokensCritical(src, cwd, crit, ce)
	}
	return stmtsCritical(src, f.Stmts, cwd, crit, ce)
}

func stmtsCritical(src string, stmts []*syntax.Stmt, cwd string, crit []string, ce critEnv) bool {
	cur := cwd
	for _, st := range stmts {
		hit, next := stmtCritical(src, st, cur, crit, ce)
		if hit {
			return true
		}
		cur = next
	}
	return false
}

func stmtCritical(src string, st *syntax.Stmt, cwd string, crit []string, ce critEnv) (bool, string) {
	if st == nil {
		return false, cwd
	}
	for _, r := range st.Redirs {
		if redirCritical(src, r, cwd, crit, ce) {
			return true, cwd
		}
	}
	return cmdCritical(src, st.Cmd, cwd, crit, ce)
}

func cmdCritical(src string, cmd syntax.Command, cwd string, crit []string, ce critEnv) (bool, string) {
	if cmd == nil {
		return false, cwd
	}
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		return callCritical(src, c, cwd, crit, ce)
	case *syntax.BinaryCmd:
		hit, next := stmtCritical(src, c.X, cwd, crit, ce)
		if hit {
			return true, next
		}
		return stmtCritical(src, c.Y, next, crit, ce)
	case *syntax.Subshell:
		return stmtsCritical(src, c.Stmts, cwd, crit, ce), cwd
	case *syntax.Block:
		return stmtsCritical(src, c.Stmts, cwd, crit, ce), cwd
	case *syntax.IfClause:
		if ifCritical(src, c, cwd, crit, ce) {
			return true, cwd
		}
		return false, cwd
	default:
		return wordsIn(src, cmd, cwd, crit, ce), cwd
	}
}

func ifCritical(src string, c *syntax.IfClause, cwd string, crit []string, ce critEnv) bool {
	if c == nil {
		return false
	}
	if stmtsCritical(src, c.Cond, cwd, crit, ce) || stmtsCritical(src, c.Then, cwd, crit, ce) {
		return true
	}
	return ifCritical(src, c.Else, cwd, crit, ce)
}

func callCritical(src string, c *syntax.CallExpr, cwd string, crit []string, ce critEnv) (bool, string) {
	if c == nil {
		return false, cwd
	}
	next := cwd
	raws := make([]string, 0, len(c.Args))
	args := make([]string, 0, len(c.Args))
	for _, w := range c.Args {
		raw := strings.TrimSpace(wordSurface(src, w))
		raws = append(raws, raw)
		args = append(args, stripShellQuotes(raw))
	}
	if commandBase(args) == "cd" {
		next = cdDestination(args, cwd, ce)
	}
	if implicitCwd(args) && pathRelationCritical(cwd, crit) {
		return true, next
	}
	for _, raw := range raws {
		if wordCritical(raw, cwd, crit, ce) {
			return true, next
		}
	}
	return false, next
}

func redirCritical(src string, r *syntax.Redirect, cwd string, crit []string, ce critEnv) bool {
	if r == nil || r.Word == nil {
		return false
	}
	switch r.Op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrIn, syntax.RdrAll, syntax.AppAll, syntax.ClbOut, syntax.RdrInOut:
	default:
		return false
	}
	return wordCritical(wordSurface(src, r.Word), cwd, crit, ce)
}

func wordsIn(src string, n syntax.Node, cwd string, crit []string, ce critEnv) bool {
	hit := false
	syntax.Walk(n, func(node syntax.Node) bool {
		w, ok := node.(*syntax.Word)
		if !ok {
			return true
		}
		if wordCritical(wordSurface(src, w), cwd, crit, ce) {
			hit = true
		}
		return true
	})
	return hit
}

func rawTokensCritical(src, cwd string, crit []string, ce critEnv) bool {
	for _, tok := range strings.Fields(src) {
		if wordCritical(tok, cwd, crit, ce) {
			return true
		}
	}
	return false
}

func wordSurface(src string, w *syntax.Word) string {
	if w == nil {
		return ""
	}
	if s := nodeText(src, w); s != "" {
		return s
	}
	return w.Lit()
}

func nodeText(src string, n syntax.Node) string {
	if n == nil || src == "" || !n.Pos().IsValid() || !n.End().IsValid() {
		return ""
	}
	a := int(n.Pos().Offset())
	b := int(n.End().Offset())
	if a < 0 || b > len(src) || a > b {
		return ""
	}
	return src[a:b]
}

func stripShellQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func joinCwd(cwd, dest string) string {
	if dest == "" {
		return cwd
	}
	if filepath.IsAbs(dest) {
		return filepath.Clean(dest)
	}
	if cwd == "" {
		return filepath.Clean(dest)
	}
	return filepath.Clean(filepath.Join(cwd, dest))
}

func tokenCritical(tok, cwd string, crit []string, ce critEnv) bool {
	tok = strings.TrimSpace(tok)
	if tok == "" || tok == "-" || tok == "--" {
		return false
	}
	bases := criticalBases(crit)
	if baseCritical(tok, bases) || globCouldMatch(tok, crit, bases) {
		return true
	}
	for _, piece := range splitPathToken(tok) {
		if piece == tok {
			continue
		}
		if tokenCritical(piece, cwd, crit, ce) {
			return true
		}
	}
	if pathIsCritical(tok, cwd, crit) {
		return true
	}
	for _, cand := range expandCandidates(tok, ce) {
		if pathIsCritical(cand, cwd, crit) || baseCritical(cand, bases) {
			return true
		}
	}
	return false
}

func splitPathToken(tok string) []string {
	var out []string
	if strings.HasPrefix(tok, "--") {
		if _, v, ok := strings.Cut(tok, "="); ok && v != "" {
			out = append(out, v)
		}
		return out
	}
	if strings.HasPrefix(tok, "-") && len(tok) > 2 {
		val := tok[2:]
		if looksLikePathVal(val) {
			out = append(out, val)
		}
	}
	return out
}

func looksLikePathVal(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "~") || strings.HasPrefix(s, "$") {
		return true
	}
	return strings.ContainsAny(s, `/\`)
}

func baseCritical(tok string, bases []string) bool {
	base := pathBase(stripMeta(tok))
	if base == "" || base == "." || base == ".." {
		return false
	}
	for _, b := range bases {
		if base == b {
			return true
		}
	}
	return false
}

func criticalBases(crit []string) []string {
	seen := map[string]struct{}{
		"lgb-permhook": {},
		"permbroker":   {},
	}
	for _, c := range crit {
		b := filepath.Base(c)
		low := strings.ToLower(b)
		if b == "lgb-permhook" || b == "permbroker" || strings.Contains(low, "settings") || strings.HasSuffix(low, ".json") {
			if b != "" && b != "." && b != "/" {
				seen[b] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for b := range seen {
		out = append(out, b)
	}
	return out
}

// stripMeta drops glob and parameter punctuation and keeps the text
// inside a command substitution. The substitution is not run.
func stripMeta(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '*', '?', '[', ']':
			continue
		case '$':
			if i+1 < len(s) && s[i+1] == '(' {
				end := indexMatch(s, i+1, '(', ')')
				if end > i+2 {
					b.WriteString(stripMeta(s[i+2 : end]))
					i = end
					continue
				}
			}
			if i+1 < len(s) && s[i+1] == '{' {
				end := strings.IndexByte(s[i+2:], '}')
				if end >= 0 {
					i = i + 2 + end
					continue
				}
			}
			j := i + 1
			for j < len(s) && isNameByte(s[j]) {
				j++
			}
			if j > i+1 {
				i = j - 1
				continue
			}
		case '`':
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func indexMatch(s string, open int, left, right byte) int {
	if open >= len(s) || s[open] != left {
		return -1
	}
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case left:
			depth++
		case right:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func isNameByte(b byte) bool {
	return b == '_' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

func globCouldMatch(tok string, crit, bases []string) bool {
	if !strings.ContainsAny(tok, "*?[") {
		return false
	}
	for _, c := range crit {
		if matchGlob(tok, c) || matchGlob(tok, filepath.Base(c)) {
			return true
		}
	}
	for _, seg := range strings.Split(strings.ReplaceAll(tok, `\`, "/"), "/") {
		if !strings.ContainsAny(seg, "*?[") {
			continue
		}
		for _, b := range bases {
			if matchGlob(seg, b) {
				return true
			}
		}
	}
	return false
}

func matchGlob(pattern, value string) bool {
	if pattern == "" || value == "" {
		return false
	}
	ok, err := filepath.Match(pattern, value)
	return err == nil && ok
}

func pathIsCritical(tok, cwd string, crit []string) bool {
	for _, cand := range pathCandidates(tok, cwd) {
		if pathRelationCritical(cand, crit) {
			return true
		}
		if real := resolveExistingPrefix(cand); real != "" && real != cand && pathRelationCritical(real, crit) {
			return true
		}
	}
	return false
}

// pathRelationCritical is true when cand is inside a critical path, equal
// to one, or a strict ancestor of one. The root is an ancestor of every
// absolute critical path. String prefix is not used here.
func pathRelationCritical(cand string, crit []string) bool {
	if !filepath.IsAbs(cand) {
		return false
	}
	cand = filepath.Clean(cand)
	if cand == "" || cand == "." {
		return false
	}
	for _, c := range crit {
		if c == "" || c == "/" || c == "." {
			continue
		}
		if cand == c || underRoot(cand, c) {
			return true
		}
		if cand == "/" {
			if filepath.IsAbs(c) {
				return true
			}
			continue
		}
		if underRoot(c, cand) {
			return true
		}
	}
	return false
}

func pathCandidates(tok, cwd string) []string {
	tok = filepath.Clean(tok)
	if tok == "" {
		return nil
	}
	// "." and "./" are the working directory, including a path that
	// cleans to the current directory.
	if tok == "." {
		if filepath.IsAbs(cwd) {
			return []string{filepath.Clean(cwd)}
		}
		return nil
	}
	if filepath.IsAbs(tok) {
		return []string{tok}
	}
	if cwd == "" || !filepath.IsAbs(cwd) {
		return nil
	}
	// A bare word is a path when the working directory is already inside
	// a critical directory, and when the word itself has a slash or is a
	// critical base. Callers also check the base name before this.
	return []string{filepath.Clean(filepath.Join(cwd, tok))}
}

func resolveExistingPrefix(path string) string {
	path = filepath.Clean(path)
	if path == "" {
		return ""
	}
	cur := path
	var missing []string
	for {
		if _, err := os.Lstat(cur); err == nil {
			real, err := filepath.EvalSymlinks(cur)
			if err != nil {
				real = cur
			}
			for i := len(missing) - 1; i >= 0; i-- {
				real = filepath.Join(real, missing[i])
			}
			return filepath.Clean(real)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return path
		}
		missing = append(missing, filepath.Base(cur))
		cur = parent
	}
}

func expandCandidates(tok string, ce critEnv) []string {
	homes := ce.homes
	if len(homes) == 0 {
		if h := os.Getenv("HOME"); h != "" {
			homes = []string{h}
		}
	}
	var out []string
	if tok == "~" || strings.HasPrefix(tok, "~/") {
		rest := strings.TrimPrefix(tok, "~")
		rest = strings.TrimPrefix(rest, "/")
		for _, h := range homes {
			if h == "" {
				continue
			}
			if rest == "" {
				out = append(out, filepath.Clean(h))
			} else {
				out = append(out, filepath.Clean(filepath.Join(h, rest)))
			}
		}
	}
	if strings.Contains(tok, "$HOME") || strings.Contains(tok, "${HOME}") {
		for _, h := range homes {
			if h == "" {
				continue
			}
			s := strings.ReplaceAll(tok, "${HOME}", h)
			s = strings.ReplaceAll(s, "$HOME", h)
			out = append(out, s)
		}
	}
	if expanded, ok := expandVars(tok, ce); ok {
		out = append(out, expanded)
	}
	return out
}

func firstExpand(tok string, ce critEnv) string {
	if cands := expandCandidates(tok, ce); len(cands) > 0 {
		return cands[0]
	}
	return stripShellQuotes(tok)
}

func expandVars(tok string, ce critEnv) (string, bool) {
	if !strings.Contains(tok, "$") {
		return "", false
	}
	var b strings.Builder
	changed := false
	for i := 0; i < len(tok); i++ {
		if tok[i] != '$' || i+1 >= len(tok) {
			b.WriteByte(tok[i])
			continue
		}
		if tok[i+1] == '(' || tok[i+1] == '{' && strings.HasPrefix(tok[i:], "${HOME}") {
			b.WriteByte(tok[i])
			continue
		}
		if tok[i+1] == '{' {
			end := strings.IndexByte(tok[i+2:], '}')
			if end < 0 {
				b.WriteByte(tok[i])
				continue
			}
			name := tok[i+2 : i+2+end]
			if name == "HOME" {
				b.WriteByte(tok[i])
				continue
			}
			if v, ok := lookupVar(name, ce.env); ok {
				b.WriteString(v)
				changed = true
				i = i + 2 + end
				continue
			}
			b.WriteString(tok[i : i+3+end])
			i = i + 2 + end
			continue
		}
		if isNameByte(tok[i+1]) {
			j := i + 1
			for j < len(tok) && isNameByte(tok[j]) {
				j++
			}
			name := tok[i+1 : j]
			if name == "HOME" {
				b.WriteString(tok[i:j])
				i = j - 1
				continue
			}
			if v, ok := lookupVar(name, ce.env); ok {
				b.WriteString(v)
				changed = true
				i = j - 1
				continue
			}
			b.WriteString(tok[i:j])
			i = j - 1
			continue
		}
		b.WriteByte(tok[i])
	}
	if !changed {
		return "", false
	}
	return b.String(), true
}

func lookupVar(name string, env []string) (string, bool) {
	for i := len(env) - 1; i >= 0; i-- {
		k, v, ok := strings.Cut(env[i], "=")
		if ok && k == name {
			return v, true
		}
	}
	return os.LookupEnv(name)
}

// wordCritical checks one shell word. A non-literal word is judged from
// the literal text before the first substitution, glob, brace, or escape.
// A literal word is resolved as a path and is not matched by string prefix.
func wordCritical(raw, cwd string, crit []string, ce critEnv) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if nonLiteralCritical(raw, cwd, crit, ce) {
		return true
	}
	return tokenCritical(stripShellQuotes(raw), cwd, crit, ce)
}

func nonLiteralCritical(raw, cwd string, crit []string, ce critEnv) bool {
	prefix, ok := splitLiteralPrefix(raw)
	if !ok {
		return false
	}
	for _, cand := range resolvePrefix(prefix, cwd, ce) {
		if pathRelationCritical(cand, crit) || partialPrefixCritical(cand, crit) {
			return true
		}
		if real := resolveExistingPrefix(cand); real != "" && real != cand && (pathRelationCritical(real, crit) || partialPrefixCritical(real, crit)) {
			return true
		}
	}
	return false
}

// splitLiteralPrefix returns the text before the first non-literal
// construct. Single quotes are literal. Double quotes still expand
// parameters, substitutions, and backslash escapes. An empty prefix with
// ok true means the construct is at the start of the word.
func splitLiteralPrefix(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				b.WriteString(s[i+1:])
				return b.String(), false
			}
			b.WriteString(s[i+1 : i+1+j])
			i += 1 + j
		case '"':
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' || s[i] == '$' || s[i] == '`' {
					return b.String(), true
				}
				b.WriteByte(s[i])
				i++
			}
		case '\\', '$', '`', '*', '?', '[':
			return b.String(), true
		case '{':
			if braceExpandAt(s, i) {
				return b.String(), true
			}
			b.WriteByte('{')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), false
}

func braceExpandAt(s string, i int) bool {
	end := strings.IndexByte(s[i:], '}')
	if end <= 1 {
		return false
	}
	body := s[i+1 : i+end]
	return strings.Contains(body, ",") || strings.Contains(body, "..")
}

func resolvePrefix(prefix, cwd string, ce critEnv) []string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		if filepath.IsAbs(cwd) {
			return []string{filepath.Clean(cwd)}
		}
		return nil
	}
	seeds := []string{prefix}
	seeds = append(seeds, expandCandidates(prefix, ce)...)
	var out []string
	seen := map[string]bool{}
	add := func(c string) {
		if c == "" || c == "." || seen[c] {
			return
		}
		seen[c] = true
		out = append(out, c)
	}
	for _, s := range seeds {
		s = stripShellQuotes(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		var c string
		if filepath.IsAbs(s) {
			c = filepath.Clean(s)
		} else if filepath.IsAbs(cwd) {
			c = joinCwd(cwd, s)
		} else {
			continue
		}
		add(c)
	}
	return out
}

// partialPrefixCritical matches a non-literal prefix that stops inside a
// path component, such as the text before a glob. Literal paths do not use it.
func partialPrefixCritical(cand string, crit []string) bool {
	if !filepath.IsAbs(cand) {
		return false
	}
	cand = filepath.Clean(cand)
	if cand == "" || cand == "." || cand == "/" {
		return false
	}
	for _, c := range crit {
		if c == "" || c == cand {
			continue
		}
		if strings.HasPrefix(c, cand) {
			return true
		}
	}
	return false
}

func commandBase(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return filepath.Base(args[0])
}

func cdDestination(args []string, cwd string, ce critEnv) string {
	operand, has := cdOperand(args)
	if !has {
		return homeDir(ce)
	}
	if operand == "-" {
		return cwd
	}
	return joinCwd(cwd, firstExpand(operand, ce))
}

// cdOperand skips POSIX cd flags. No operand means the home directory.
// "-" is the previous directory, which this tracker does not record.
func cdOperand(args []string) (string, bool) {
	i := 1
	for i < len(args) {
		switch args[i] {
		case "-L", "-P", "-e", "-@":
			i++
			continue
		case "--":
			i++
			if i < len(args) {
				return args[i], true
			}
			return "", false
		case "-":
			return "-", true
		default:
			return args[i], true
		}
	}
	return "", false
}

func homeDir(ce critEnv) string {
	h := firstExpand("~", ce)
	if h == "" || h == "~" {
		return ""
	}
	if !filepath.IsAbs(h) {
		return ""
	}
	return filepath.Clean(h)
}

// implicitCwd reports commands that read the working directory when they
// are given no path operand. "." is handled as a path, not here.
func implicitCwd(args []string) bool {
	base := commandBase(args)
	switch base {
	case "ls", "dir", "vdir", "du", "find":
	default:
		return false
	}
	return !hasPathOperand(base, args[1:])
}

func hasPathOperand(cmd string, args []string) bool {
	if cmd == "find" {
		return findHasPath(args)
	}
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			return i+1 < len(args)
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			if flagConsumesNext(cmd, a) {
				i += 2
				continue
			}
			i++
			continue
		}
		return true
	}
	return false
}

func findHasPath(args []string) bool {
	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "-H", "-L", "-P":
			i++
			continue
		case "-D":
			i += 2
			continue
		}
		if strings.HasPrefix(a, "-O") || a == "--" {
			if a == "--" {
				return i+1 < len(args)
			}
			i++
			continue
		}
		if strings.HasPrefix(a, "-") || a == "!" || a == "(" {
			return false
		}
		return true
	}
	return false
}

func flagConsumesNext(cmd, flag string) bool {
	if strings.Contains(flag, "=") || flag == "-" {
		return false
	}
	if strings.HasPrefix(flag, "--") {
		switch cmd {
		case "ls", "dir", "vdir":
			switch strings.TrimPrefix(flag, "--") {
			case "ignore", "hide", "width", "tabsize", "format", "quoting-style", "time", "time-style", "color", "block-size", "indicator-style", "sort", "hyperlink":
				return true
			}
		case "du":
			switch strings.TrimPrefix(flag, "--") {
			case "block-size", "exclude", "exclude-from", "max-depth", "threshold", "files0-from":
				return true
			}
		}
		return false
	}
	if !strings.HasPrefix(flag, "-") || len(flag) < 2 {
		return false
	}
	last := flag[len(flag)-1]
	switch cmd {
	case "ls", "dir", "vdir":
		return last == 'I' || last == 'w' || last == 'T'
	case "du":
		return last == 'd' || last == 'B' || last == 'X'
	default:
		return false
	}
}
