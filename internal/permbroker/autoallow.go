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
// A ceiling auto-approval does not use this choke.
func autoAllowOK(in inspected) bool {
	if autoAllowGOOS != "linux" {
		return false
	}
	if !in.Literal {
		return false
	}
	return true
}

// ceilingMatch is the per-bot auto-approval. It compares the final
// effective level. Callers pass the level from after policy raises,
// the classifier, and critical paths. A shipped-table level is not enough.
// The broker must be hook. A bot with no ceiling still asks.
// Parse errors, malformed commands, and ambiguous commands do not match.
// A hard ask or an ineligible request does not match unless the only
// reason is the critical level or a critical path. The ceiling still
// has to be exactly critical for that level. Every other reason asks,
// including at a critical ceiling. A git form that runs a command, a
// compound part with no known level, a git-risk, a policy path, an
// unresolved path, a git-directory write, and a client-config write do
// not match at any ceiling.
func (e *Engine) ceilingMatch(req Request, in inspected) (Level, bool) {
	if e == nil || e.brokerMode != "hook" {
		return "", false
	}
	ceiling, ok := e.lookupCeiling(req.BotID)
	if !ok || ceiling == "" {
		return "", false
	}
	if ceilingParseBlock(in.ParseReason) {
		return "", false
	}
	if ceilingGitExecutes(in) {
		return "", false
	}
	if ceilingCompoundUnclassified(in) {
		return "", false
	}
	if in.GitRisk != "" || in.GitReason != "" {
		return "", false
	}
	if e.policyPathBlocked(req, in) {
		return "", false
	}
	if ceilingProtectedRead(in) {
		return "", false
	}
	if ceilingPathUnresolved(req, in) {
		return "", false
	}
	if ceilingGitSensitiveWrite(req, in) {
		return "", false
	}
	if ceilingClientConfigWrite(req, in) {
		return "", false
	}
	if !e.ceilingRequestEligible(req, in) {
		return "", false
	}
	level := in.Level
	if !ceilingCovers(level, ceiling) {
		return "", false
	}
	return ceiling, true
}

// ceilingRequestEligible is the hard-ask and eligibility gate.
// A shell command whose only reason is the critical level or a critical
// path can still match. A non-shell tool uses the ceiling tool table.
func (e *Engine) ceilingRequestEligible(req Request, in inspected) bool {
	if isShellTool(req.ToolName) {
		return e.ceilingShellEligible(req, in)
	}
	return e.ceilingToolEligible(req, in)
}

func (e *Engine) ceilingShellEligible(req Request, in inspected) bool {
	if !in.HardAsk && in.Eligible && !in.Compound {
		return true
	}
	return e.ceilingCriticalSole(req, in)
}

// ceilingCriticalSole is true when a critical final level is the only
// reason the command is a hard ask or is not eligible. The check reparses
// the command with that critical override masked.
func (e *Engine) ceilingCriticalSole(req Request, in inspected) bool {
	if in.Level != LevelCritical {
		return false
	}
	parsed := ParseCommand(commandRaw(in))
	if ceilingHasCompound(parsed) {
		return false
	}
	if ceilingVoidOrCD(parsed) {
		return false
	}
	argv := soleArgv(parsed, in)
	if ceilingWrapperBlock(parsed, argv) {
		return false
	}
	if len(argv) == 0 || ceilingUnknownBinary(argv[0], e.resolver) {
		return false
	}
	ws := req.Workspace
	if ws == "" {
		ws = req.Cwd
	}
	if ceilingClassBlocks(argv, req.Cwd, ws, req.Repos, e.resolver) {
		return false
	}
	if ceilingOtherParse(parsed) {
		return false
	}
	return true
}

func commandRaw(in inspected) string {
	raw := strings.TrimSpace(in.Raw)
	if raw != "" {
		return raw
	}
	return strings.Join(in.Argv, " ")
}

// ceilingHasCompound refuses a reparsed compound that is not a leading cd
// or a void command. Those two have their own checks. The inspected
// compound flag stays with ceilingCompoundUnclassified.
func ceilingHasCompound(parsed Parse) bool {
	if parsed.LeadingCD != "" || parsed.Void || parsed.Reason == "state" {
		return false
	}
	return parsed.Compound || len(parsed.Parts) > 1
}

// ceilingVoidOrCD refuses a void command and any leading cd. A cd is not
// the critical-level reason, inside or outside the workspace.
func ceilingVoidOrCD(parsed Parse) bool {
	if parsed.Void || parsed.Reason == "state" || parsed.LeadingCD != "" {
		return true
	}
	return false
}

// ceilingWrapperBlock refuses an interpreter or wrapper argv. Unknown
// binaries and the class check do not own this case.
func ceilingWrapperBlock(parsed Parse, argv []string) bool {
	if parsed.Reason == "wrapper" || wrapperArgv(argv) {
		return true
	}
	for _, p := range parsed.Parts {
		if wrapperArgv(p.Argv) {
			return true
		}
	}
	return false
}

// ceilingUnknownBinary refuses a program that is not an allowlisted
// resolved binary. Wrapper names are left to ceilingWrapperBlock.
func ceilingUnknownBinary(argv0 string, resolve func(string) (string, bool)) bool {
	if argv0 == "" {
		return true
	}
	if wrapperArgv([]string{argv0}) {
		return false
	}
	base := baseName(argv0)
	if !binaryAllowed(base) {
		return true
	}
	if resolve == nil {
		return true
	}
	_, ok := resolve(argv0)
	return !ok
}

// ceilingClassBlocks is classification with the critical level masked.
// A protected path is the critical-path reason and is not a block here.
// A path that is only outside the workspace still blocks.
func ceilingClassBlocks(argv []string, cwd, ws string, repos []string, resolve func(string) (string, bool)) bool {
	if len(argv) == 0 || wrapperArgv(argv) {
		return false
	}
	c := classifyArgv(argv, cwd, ws, repos, resolve)
	switch c.Reason {
	case "flag", "command", "repo", "binary", "empty":
		return true
	case "path":
		if protectedWrite(argv) || mentionsProtected(argv) {
			return false
		}
		return true
	}
	if c.Level == LevelCritical {
		return false
	}
	return c.Hard || !c.Eligible
}

// ceilingOtherParse refuses a parse reason that is not owned by the
// compound, void, or wrapper checks.
func ceilingOtherParse(parsed Parse) bool {
	switch parsed.Reason {
	case "", "state", "wrapper", "compound", "not eligible":
		return false
	default:
		return true
	}
}

func soleArgv(parsed Parse, in inspected) []string {
	if len(parsed.Argv) > 0 {
		return parsed.Argv
	}
	if len(parsed.Parts) > 0 {
		return parsed.Parts[len(parsed.Parts)-1].Argv
	}
	return in.Argv
}

// ceilingToolRule is one non-shell tool the ceiling may auto-approve.
// needPath is true when a path is required. write is a write tool.
type ceilingToolRule struct {
	level Level
	write bool
}

// ceilingToolRuleFor is the non-shell ceiling table.
// Read, Glob, and Grep are low. Write, Edit, MultiEdit, and NotebookEdit
// are medium. Anything else, including WebFetch, WebSearch, Task, and
// mcp tools, is absent and cannot auto-approve.
func ceilingToolRuleFor(tool string) (ceilingToolRule, bool) {
	switch normTool(tool) {
	case "read", "glob", "grep":
		return ceilingToolRule{level: LevelLow}, true
	case "write", "edit", "multiedit", "notebookedit":
		return ceilingToolRule{level: LevelMedium, write: true}, true
	default:
		return ceilingToolRule{}, false
	}
}

func (e *Engine) ceilingToolEligible(req Request, in inspected) bool {
	rule, ok := ceilingToolRuleFor(req.ToolName)
	if !ok {
		return false
	}
	if e.policyPathBlocked(req, in) {
		return false
	}
	paths := toolPaths(req.ToolInput)
	if normTool(req.ToolName) == "glob" {
		if p := globPatternPath(req.ToolInput); p != "" {
			paths = append(paths, p)
		}
	}
	ws := req.Workspace
	if ws == "" {
		ws = req.Cwd
	}
	if !ceilingPathsInside(paths, req.Cwd, ws) {
		return false
	}
	for _, p := range paths {
		if protectedPath(p) {
			return false
		}
	}
	switch rule.level {
	case LevelLow, LevelMedium:
	default:
		return false
	}
	if rule.write && (in.Level == LevelCritical || e.criticalTouched(req, in)) {
		return false
	}
	return true
}

// ceilingProtectedRead refuses an allowlisted read of a protected path.
// A protected write is the critical-path case and is left to the sole-reason
// check. A read is not that case.
func ceilingProtectedRead(in inspected) bool {
	lists := [][]string{in.Argv}
	for _, p := range in.Parts {
		lists = append(lists, p.Argv)
	}
	if len(lists) == 1 && len(lists[0]) == 0 {
		lists[0] = strings.Fields(in.Raw)
	}
	for _, argv := range lists {
		if len(argv) == 0 || !mentionsProtected(argv) || protectedWrite(argv) {
			continue
		}
		return true
	}
	return false
}

func ceilingPathsInside(paths []string, cwd, ws string) bool {
	if strings.TrimSpace(ws) == "" || len(paths) == 0 {
		return false
	}
	for _, p := range paths {
		if strings.TrimSpace(p) == "" || !resolvesInside(p, cwd, ws) {
			return false
		}
	}
	return true
}

func (e *Engine) criticalTouched(req Request, in inspected) bool {
	if e == nil || len(e.critical) == 0 {
		return false
	}
	return hitsCriticalWith(req, in, e.critical, e.critEnvLocked(req.BotID))
}

// ceilingCompoundUnclassified refuses a compound whose parts are not all
// a known level. The joining operators are ; && || | and a newline.
// A classified part does not hide an unclassified one.
func ceilingCompoundUnclassified(in inspected) bool {
	if !ceilingCompoundShape(in) {
		return false
	}
	if len(in.Parts) == 0 {
		return false
	}
	for _, p := range in.Parts {
		switch p.Level {
		case LevelLow, LevelMedium, LevelHigh, LevelCritical:
		default:
			return true
		}
	}
	return false
}

func ceilingCompoundShape(in inspected) bool {
	if in.Compound {
		return true
	}
	for _, op := range in.Operators {
		switch op {
		case ";", "&&", "||", "|", "|&":
			return true
		}
	}
	return strings.Contains(in.Raw, "\n")
}

// policyPathBlocked refuses a call that names a policy file.
// The path and its parent directories are resolved the same way a
// critical path is resolved, so a link to a policy file is refused.
// Critical paths already raise the level. This also refuses the call
// when the ceiling is critical.
func (e *Engine) policyPathBlocked(req Request, in inspected) bool {
	if e == nil || len(e.policyPaths) == 0 {
		return false
	}
	return hitsCriticalWith(req, in, e.policyPaths, e.critEnvLocked(req.BotID))
}

// ceilingGitExecutes refuses git argv that takes or runs a command.
// The shipped classifier is unchanged: marking these hard would change
// rule and grant eligibility for calls that have no ceiling.
func ceilingGitExecutes(in inspected) bool {
	if ceilingGitArgv(in.Argv) {
		return true
	}
	for _, p := range in.Parts {
		if ceilingGitArgv(p.Argv) {
			return true
		}
	}
	if len(in.Argv) == 0 && len(in.Parts) == 0 {
		return ceilingGitArgv(strings.Fields(in.Raw))
	}
	return false
}

func ceilingGitArgv(argv []string) bool {
	if len(argv) == 0 || baseName(argv[0]) != "git" {
		return false
	}
	if gitInlineConfigRuns(argv) || gitPackOption(argv) {
		return true
	}
	switch gitCommandName(argv) {
	case "submodule":
		return submoduleCeiling(argv)
	case "rebase":
		return rebaseExec(argv)
	case "bisect":
		return hasGitToken(argv, "run")
	case "filter-branch", "difftool", "mergetool", "alias", "upload-pack", "receive-pack":
		return true
	case "config":
		return gitConfigArgvRuns(argv)
	default:
		return false
	}
}

// gitCommandName is the git subcommand. Global options that take a value
// are skipped. An option after the subcommand does not hide that name,
// so rebase -x still names rebase.
func gitCommandName(argv []string) string {
	args := argv[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(a, "-") {
			if gitOptionSkipsNext(a) {
				i++
			}
			continue
		}
		return a
	}
	return ""
}

func gitOptionSkipsNext(a string) bool {
	switch a {
	case "-c", "-C", "--config", "--git-dir", "--work-tree", "--namespace",
		"--super-prefix", "--exec-path", "--upload-pack", "--receive-pack", "--config-env":
		return true
	default:
		return false
	}
}

func submoduleCeiling(argv []string) bool {
	switch submoduleVerb(argv) {
	case "", "status", "init":
		return false
	case "update":
		return submoduleUpdateCommand(argv)
	default:
		return true
	}
}

func submoduleVerb(argv []string) string {
	idx := -1
	for i, a := range argv {
		if a == "submodule" {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ""
	}
	for _, a := range argv[idx+1:] {
		if a == "--" {
			return ""
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

func submoduleUpdateCommand(argv []string) bool {
	for _, a := range argv {
		if a == "--command" || strings.HasPrefix(a, "--command=") || strings.HasPrefix(a, "!") {
			return true
		}
	}
	return false
}

func rebaseExec(argv []string) bool {
	for _, a := range argv {
		low := strings.ToLower(a)
		if low == "-x" || low == "--exec" || strings.HasPrefix(low, "--exec=") {
			return true
		}
	}
	return false
}

func hasGitToken(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}

func gitPackOption(argv []string) bool {
	for _, a := range argv {
		low := strings.ToLower(a)
		if low == "--upload-pack" || low == "--receive-pack" ||
			strings.HasPrefix(low, "--upload-pack=") || strings.HasPrefix(low, "--receive-pack=") {
			return true
		}
	}
	return false
}

func gitInlineConfigRuns(argv []string) bool {
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "-C" || (strings.HasPrefix(a, "-C") && !strings.HasPrefix(a, "-c")) {
			if a == "-C" {
				i++
			}
			continue
		}
		if a == "-c" || a == "--config" {
			if i+1 < len(argv) && configValueRunsCommand(argv[i+1]) {
				return true
			}
			continue
		}
		if strings.HasPrefix(a, "--config=") && configValueRunsCommand(strings.TrimPrefix(a, "--config=")) {
			return true
		}
		if strings.HasPrefix(a, "-c") && len(a) > 2 && configValueRunsCommand(a[2:]) {
			return true
		}
	}
	return false
}

func gitConfigArgvRuns(argv []string) bool {
	for _, a := range argv[1:] {
		if configValueRunsCommand(a) {
			return true
		}
	}
	return false
}

// configValueRunsCommand reports a git config assignment that runs a
// command or selects a command helper. core.*, alias.*, protocol.*,
// credential.helper, and a submodule update command are included.
func configValueRunsCommand(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "-") {
		return false
	}
	key := raw
	val := ""
	if i := strings.IndexAny(raw, "= "); i >= 0 {
		key = strings.TrimSpace(raw[:i])
		val = strings.TrimSpace(raw[i+1:])
	}
	low := strings.ToLower(key)
	if low == "" {
		return false
	}
	if riskyFlat(low, val) != "" {
		return true
	}
	if strings.HasPrefix(low, "core.") || strings.HasPrefix(low, "alias.") || strings.HasPrefix(low, "protocol.") {
		return true
	}
	if strings.HasPrefix(low, "submodule.") && strings.HasSuffix(low, ".update") {
		return true
	}
	if strings.Contains(low, "sshcommand") {
		return true
	}
	return low == "credential.helper" || strings.HasPrefix(low, "credential.helper.")
}

func (e *Engine) lookupCeiling(bot string) (Level, bool) {
	if len(e.ceilings) == 0 {
		return "", false
	}
	if ceiling, ok := e.ceilings[bot]; ok {
		return ceiling, true
	}
	ceiling, ok := e.ceilings[strings.ToLower(strings.TrimSpace(bot))]
	return ceiling, ok
}

// ceilingParseBlock is a command the ceiling must not approve.
// parse is a parse error. The other reasons are malformed or ambiguous.
func ceilingParseBlock(reason string) bool {
	switch reason {
	case "parse", "unsupported syntax", "shell dialect", "comment", "empty",
		"not a literal", "assignment", "redirect":
		return true
	default:
		return false
	}
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
