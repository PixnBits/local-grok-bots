package permission

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// Class is the static, deterministic label for one command or pattern.
// AutoAllow is true only for a low-risk read-only call the hard floor permits
// a user rule to allow. Anything else fails closed.
type Class struct {
	ReadOnly    bool   `json:"read_only"`
	Kind        string `json:"kind"`
	Sensitivity string `json:"sensitivity"`
	Risk        string `json:"risk"`
	Reason      string `json:"reason"`
	AutoAllow   bool   `json:"auto_allow"`
}

// SuggestAfter is how many similar logged requests create a suggestion
// without an explicit analyze call.
const SuggestAfter = 3

var (
	// gitStatusOpts are the only git options auto-allow accepts. The broker
	// does not run git: it answers allow and the CLI runs the original
	// command, so a safe git wrapper cannot be applied on that path.
	// diff, log, and show can still invoke an external diff, textconv, or pager.
	gitStatusOpt = map[string]bool{
		"-s": true, "--short": true, "-b": true, "--branch": true, "--porcelain": true,
	}
	gitIrreversible = map[string]bool{
		"push": true, "reset": true, "clean": true,
	}
	fileReadOnly = map[string]bool{
		"cat": true, "ls": true, "head": true, "tail": true, "wc": true,
		"pwd": true, "stat": true, "file": true, "grep": true, "rg": true, "find": true,
	}
	networkBins = map[string]bool{
		"curl": true, "wget": true, "ssh": true, "scp": true, "sftp": true,
		"nc": true, "ncat": true, "netcat": true, "ping": true, "dig": true,
		"nslookup": true, "npm": true, "npx": true, "yarn": true, "pnpm": true,
		"pip": true, "pip3": true, "gem": true, "apt": true, "apt-get": true,
		"brew": true, "docker": true, "kubectl": true, "helm": true,
		"aws": true, "gcloud": true, "az": true, "rsync": true, "ftp": true,
		"telnet": true, "socat": true,
	}
	irreversibleBins = map[string]bool{
		"rm": true, "rmdir": true, "dd": true, "mkfs": true, "shred": true,
		"sudo": true, "doas": true, "su": true,
	}
	writeBins = map[string]bool{
		"tee": true, "mv": true, "cp": true, "install": true, "mkdir": true,
		"touch": true, "truncate": true, "ln": true, "chmod": true, "chown": true,
		"chgrp": true, "sed": true, "tar": true,
	}
)

// ClassifyCall labels one concrete tool call. workspace is the bot directory;
// empty means relative paths are treated as project-local only when they do
// not escape, and absolute paths are not auto-allowed.
func ClassifyCall(tool string, args map[string]any, workspace string) Class {
	name := strings.ToLower(strings.TrimSpace(tool))
	switch name {
	case "read", "ls":
		return classifyReadTool(argText(args), workspace)
	case "glob":
		return classifyGlobTool(args, workspace)
	case "grep":
		return classifyGrepTool(args, workspace)
	case "edit", "write", "multiedit", "notebookedit":
		return blocked("write", pathLabel(argText(args), workspace), "high", "file write")
	case "webfetch", "websearch":
		return blocked("network", "unknown", "high", "network tool")
	case "bash":
		return classifyBash(argText(args), workspace)
	default:
		return blocked("unknown", "unknown", "high", "tool is not a known read-only command")
	}
}

// CheckUserRule accepts a durable pattern. Allow is stored only when the
// pattern is a known low-risk read-only shape. Ask and deny are stricter and
// are always accepted when the shape is well formed. Concrete calls are
// classified again at decision time, so a glob cannot auto-allow a write.
func CheckUserRule(effect, pattern, workspace string) (Class, error) {
	effect, pattern, err := normalizeRule(effect, pattern)
	if err != nil {
		return Class{}, err
	}
	if effect != "allow" {
		return Class{
			Kind: "stricter", Sensitivity: "project",
			Reason: "ask and deny rules only narrow what a managed allow would permit",
		}, nil
	}
	return eligibleAllow(pattern, workspace)
}

func normalizeRule(effect, pattern string) (string, string, error) {
	effect = strings.ToLower(strings.TrimSpace(effect))
	pattern = strings.TrimSpace(pattern)
	switch effect {
	case "allow", "ask", "deny":
	default:
		return "", "", fmt.Errorf("effect must be allow, ask, or deny")
	}
	if pattern == "" || len(pattern) > 400 || strings.ContainsAny(pattern, "\r\n") {
		return "", "", fmt.Errorf("invalid pattern")
	}
	name, _, _ := splitRule(pattern)
	if strings.TrimSpace(name) == "" || strings.ContainsAny(name, " \t") {
		return "", "", fmt.Errorf("invalid pattern")
	}
	return effect, pattern, nil
}

func eligibleAllow(pattern, workspace string) (Class, error) {
	name, glob, scoped := splitRule(pattern)
	if !scoped {
		return Class{}, fmt.Errorf("auto-allow refused: an allow pattern must name the tool and an argument glob")
	}
	switch strings.ToLower(name) {
	case "bash":
		return eligibleBash(glob, workspace)
	case "read", "grep", "glob", "ls":
		return eligibleRead(glob, workspace)
	default:
		return Class{}, fmt.Errorf("auto-allow refused: %s is not a known read-only tool", name)
	}
}

func eligibleBash(glob, workspace string) (Class, error) {
	if nonPrintableASCII(glob) {
		return Class{}, fmt.Errorf("auto-allow refused: pattern contains a non-printable byte")
	}
	cmd, ok := literalCommand(glob)
	if !ok {
		return Class{}, fmt.Errorf("auto-allow refused: wildcard must be a trailing glob on a read-only command")
	}
	// The trailing * and ? are the rule glob. Shell expansion is checked on
	// the literal command, and again on each later call.
	if shellComposed(cmd) {
		return Class{}, fmt.Errorf("auto-allow refused: pattern contains shell composition, redirection, or expansion")
	}
	id, ok := readOnlyIdentity(cmd)
	if !ok || id == "" {
		c := classifyBash(cmd, workspace)
		if c.Reason == "" {
			c.Reason = "command is not a known read-only prefix"
		}
		return c, fmt.Errorf("auto-allow refused: %s", c.Reason)
	}
	c := classifyBash(cmd, workspace)
	if !c.AutoAllow {
		if c.Reason == "" {
			c.Reason = "command is not low-risk read-only"
		}
		return c, fmt.Errorf("auto-allow refused: %s", c.Reason)
	}
	c.Reason = "low-risk read-only " + id + "; each later call is rechecked, and shell composition still asks"
	return c, nil
}

func eligibleRead(glob, workspace string) (Class, error) {
	if credentialPath(glob) {
		return Class{}, fmt.Errorf("auto-allow refused: pattern names a credential path")
	}
	lit, ok := literalCommand(glob)
	if !ok {
		return Class{}, fmt.Errorf("auto-allow refused: wildcard must be a trailing glob")
	}
	if strings.TrimSpace(lit) == "" {
		return Class{}, fmt.Errorf("auto-allow refused: path glob needs a project prefix")
	}
	c := classifyReadTool(lit, workspace)
	if !c.AutoAllow {
		if c.Reason == "" {
			c.Reason = "path is not project-local"
		}
		return c, fmt.Errorf("auto-allow refused: %s", c.Reason)
	}
	c.Reason = "read-only path under the workspace; each later call is rechecked"
	return c, nil
}

// literalCommand returns the text before a trailing * or ? glob.
// A wildcard anywhere earlier is rejected.
func literalCommand(glob string) (string, bool) {
	i := strings.IndexAny(glob, "*?")
	if i < 0 {
		return strings.TrimSpace(glob), strings.TrimSpace(glob) != ""
	}
	for _, r := range glob[i:] {
		if r != '*' && r != '?' && !unicode.IsSpace(r) {
			return "", false
		}
	}
	cmd := strings.TrimSpace(glob[:i])
	if cmd == "" {
		return "", false
	}
	return cmd, true
}

func classifyBash(cmd, workspace string) Class {
	// Checked before trim and split. Trim would drop a trailing control byte.
	if nonPrintableASCII(cmd) {
		return blocked("mixed", "unknown", "high", "command contains a non-printable byte")
	}
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return blocked("unknown", "unknown", "high", "empty command")
	}
	if shellComposed(cmd) {
		return blocked("mixed", "unknown", "high", "shell composition, redirection, or expansion; classification refused auto-allow")
	}
	toks := splitCmd(cmd)
	if len(toks) == 0 {
		return blocked("unknown", "unknown", "high", "empty command")
	}
	bin := toks[0]
	if credentialAnywhere(toks) {
		return blocked("credential", "credential", "high", "command touches a credential path")
	}
	if networkBins[bin] {
		return blocked("network", "unknown", "high", bin+" is a network command")
	}
	if irreversibleBins[bin] {
		return blocked("irreversible", "unknown", "high", bin+" is irreversible")
	}
	if writeBins[bin] {
		return blocked("write", "unknown", "high", bin+" writes")
	}
	switch bin {
	case "git":
		return classifyGit(toks, workspace)
	case "gh":
		return blocked("network", "unknown", "high", "gh is a network command")
	default:
		if fileReadOnly[bin] {
			return classifyFileRead(toks, workspace)
		}
	}
	return blocked("unknown", "unknown", "high", "command is not a known read-only prefix")
}

func classifyGit(toks []string, workspace string) Class {
	if why := gitForbiddenReason(toks); why != "" {
		return blocked("unknown", "unknown", "high", why)
	}
	sub := gitSubcommand(toks)
	if sub == "" {
		return blocked("unknown", "unknown", "high", "git subcommand is not statically read-only")
	}
	if gitIrreversible[sub] {
		return blocked("irreversible", "unknown", "high", "git "+sub+" is irreversible")
	}
	if sub == "fetch" || sub == "pull" || sub == "clone" || sub == "ls-remote" {
		return blocked("network", "unknown", "high", "git "+sub+" uses the network")
	}
	if sub == "diff" || sub == "log" || sub == "show" {
		return blocked("unknown", "unknown", "high", "git "+sub+" can invoke an external diff, textconv, or pager")
	}
	if sub != "status" {
		return blocked("unknown", "unknown", "high", "git "+sub+" is not auto-allowed")
	}
	for _, t := range toks {
		if t == "--output" || strings.HasPrefix(t, "--output=") {
			return blocked("write", "unknown", "high", "git status --output writes a file")
		}
	}
	if prob := gitStatusArgs(toks, workspace, true); prob != nil {
		return blocked(prob.kind, prob.sens, "high", prob.reason)
	}
	return allowLow("read-only git status")
}

func classifyFileRead(toks []string, workspace string) Class {
	if toks[0] == "find" && findWrites(toks) {
		return blocked("write", "unknown", "high", "find would write or execute")
	}
	if prob := checkFileArgs(toks, workspace, true); prob != nil {
		return blocked(prob.kind, prob.sens, "high", prob.reason)
	}
	return allowLow("read-only " + toks[0])
}

func classifyGlobTool(args map[string]any, workspace string) Class {
	pattern, _ := stringArg(args, "pattern")
	if strings.TrimSpace(pattern) == "" {
		return blocked("unknown", "unknown", "high", "glob tool has no pattern")
	}
	if why := globPathRefused(pattern); why != "" {
		return blocked("unknown", "unknown", "high", why)
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return classifyReadTool(pattern, workspace)
	}
	return allowLow("read-only glob pattern inside the workspace")
}

func classifyGrepTool(args map[string]any, workspace string) Class {
	if g, ok := stringArg(args, "glob"); ok && strings.TrimSpace(g) != "" {
		if why := globPathRefused(g); why != "" {
			return blocked("unknown", "unknown", "high", why)
		}
	}
	path, _ := stringArg(args, "path")
	if strings.TrimSpace(path) == "" {
		path, _ = stringArg(args, "file_path")
	}
	if strings.TrimSpace(path) == "" {
		path, _ = stringArg(args, "filePath")
	}
	if strings.TrimSpace(path) == "" {
		return allowLow("read-only grep in the workspace")
	}
	if why := globPathRefused(path); why != "" {
		return blocked("unknown", "unknown", "high", why)
	}
	return classifyReadTool(path, workspace)
}

func stringArg(args map[string]any, key string) (string, bool) {
	if args == nil {
		return "", false
	}
	s, ok := args[key].(string)
	return s, ok
}

func classifyReadTool(p, workspace string) Class {
	p = strings.TrimSpace(p)
	if p == "" {
		return blocked("unknown", "unknown", "high", "read tool has no path")
	}
	if prob := pathProblem(p, workspace, true); prob != nil {
		return blocked(prob.kind, prob.sens, "high", prob.reason)
	}
	return allowLow("read-only path inside the workspace")
}

func allowLow(reason string) Class {
	return Class{
		ReadOnly: true, Kind: "read_only", Sensitivity: "project",
		Risk: "low", Reason: reason, AutoAllow: true,
	}
}

func blocked(kind, sens, risk, reason string) Class {
	if sens == "" {
		sens = "unknown"
	}
	return Class{Kind: kind, Sensitivity: sens, Risk: risk, Reason: reason}
}

func gitSubcommand(toks []string) string {
	for i := 1; i < len(toks); i++ {
		t := toks[i]
		if t == "--" {
			return ""
		}
		if strings.HasPrefix(t, "-") {
			return ""
		}
		return t
	}
	return ""
}

func gitForbiddenReason(toks []string) string {
	for i := 1; i < len(toks); i++ {
		t := toks[i]
		if t == "--" {
			return ""
		}
		if gitOptForbidden(t) {
			return "git option is not permitted"
		}
	}
	return ""
}

func gitOptForbidden(t string) bool {
	switch t {
	case "-C", "-c", "--git-dir", "--work-tree", "--ext-diff", "--textconv", "--no-index":
		return true
	}
	if strings.HasPrefix(t, "--git-dir=") || strings.HasPrefix(t, "--work-tree=") ||
		strings.HasPrefix(t, "--ext-diff=") || strings.HasPrefix(t, "--textconv=") {
		return true
	}
	// -c with an attached value. Short status flags are only s and b.
	if strings.HasPrefix(t, "-c") && !strings.HasPrefix(t, "--") {
		return true
	}
	return false
}

func gitStatusArgs(toks []string, workspace string, resolve bool) *argProblem {
	subAt := -1
	for i := 1; i < len(toks); i++ {
		if !strings.HasPrefix(toks[i], "-") {
			subAt = i
			break
		}
	}
	if subAt < 0 {
		return &argProblem{kind: "unknown", sens: "unknown", reason: "git subcommand is not statically read-only"}
	}
	files := false
	for _, t := range toks[subAt+1:] {
		if !files {
			if t == "--" {
				files = true
				continue
			}
			if strings.HasPrefix(t, "-") {
				if !gitStatusOptOK(t) {
					return &argProblem{kind: "unknown", sens: "unknown", reason: "git status option is not permitted"}
				}
				continue
			}
			return &argProblem{kind: "unknown", sens: "unknown", reason: "file operand requires --"}
		}
		if prob := pathProblem(t, workspace, resolve); prob != nil {
			return prob
		}
	}
	return nil
}

func gitStatusOptOK(t string) bool {
	if gitStatusOpt[t] {
		return true
	}
	if len(t) > 1 && t[0] == '-' && t[1] != '-' {
		for _, c := range t[1:] {
			if c != 's' && c != 'b' {
				return false
			}
		}
		return true
	}
	return false
}

func findWrites(toks []string) bool {
	for _, t := range toks[1:] {
		switch t {
		case "-delete", "-exec", "-execdir", "-ok", "-okdir", "-fls", "-fprint", "-fprintf", "-fprint0":
			return true
		}
	}
	return false
}

func readOnlyIdentity(cmd string) (string, bool) {
	if shellComposed(cmd) {
		return "", false
	}
	toks := splitCmd(cmd)
	if len(toks) == 0 {
		return "", false
	}
	switch toks[0] {
	case "git":
		if gitForbiddenReason(toks) != "" {
			return "", false
		}
		if gitSubcommand(toks) != "status" {
			return "", false
		}
		if gitStatusArgs(toks, "", false) != nil {
			return "", false
		}
		return "git status", true
	case "gh":
		return "", false
	default:
		if fileReadOnly[toks[0]] && !(toks[0] == "find" && findWrites(toks)) && checkFileArgs(toks, "", false) == nil {
			return toks[0], true
		}
	}
	return "", false
}

// shellComposed is true when an unquoted metacharacter, or an expansion
// inside double quotes, could change what the command does.
func shellComposed(s string) bool {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			}
			continue
		}
		if quote == '"' {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '"' {
				quote = 0
				continue
			}
			if c == '$' || c == '`' || c == '\n' || c == '\r' {
				return true
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '\\', ';', '|', '&', '<', '>', '`', '$', '\n', '\r', '{', '}', '*', '?', '[':
			return true
		}
	}
	return quote != 0
}

func splitCmd(s string) []string {
	var out []string
	var b strings.Builder
	var quote byte
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
				continue
			}
			b.WriteByte(c)
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if unicode.IsSpace(rune(c)) {
			flush()
			continue
		}
		b.WriteByte(c)
	}
	flush()
	return out
}

func credentialAnywhere(toks []string) bool {
	for _, t := range toks {
		if credentialPath(t) {
			return true
		}
	}
	return false
}

func credentialPath(p string) bool {
	for _, s := range splitSegs(p) {
		s = strings.ToLower(s)
		switch s {
		case ".ssh", ".aws", ".gnupg", ".netrc", ".kube", ".azure", ".docker", ".grok",
			"credentials", "credentials.json", "id_rsa", "id_ed25519", "id_ecdsa",
			"auth.json", "admin-token", "policy.toml", ".git-credentials", ".npmrc",
			".pypirc", "cookies", "user-permissions.json", "grok-permission-rules":
			return true
		}
		if s == ".env" || strings.HasPrefix(s, ".env.") || s == "state.db" || strings.HasPrefix(s, "state.db-") {
			return true
		}
		if strings.HasSuffix(s, ".pem") || strings.HasSuffix(s, ".key") {
			return true
		}
	}
	return false
}

func splitSegs(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool {
		return r == '/' || r == '\\' || r == ':'
	})
}

// argProblem is why one command or path is not auto-allowed.
type argProblem struct {
	kind, sens, reason string
}

func nonPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			return true
		}
	}
	return false
}

// globPathRefused reports an absolute path, a .. segment, or a ~ segment.
// Glob patterns and grep globs are not filesystem lookups.
func globPathRefused(p string) string {
	p = strings.Trim(strings.TrimSpace(p), `"'`)
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, "~") || filepath.IsAbs(p) {
		return "path is absolute or escapes the workspace"
	}
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." || seg == "~" || strings.HasPrefix(seg, "~") {
			return "path is absolute or escapes the workspace"
		}
	}
	return ""
}

type optKind int

const (
	optFlag optKind = iota
	optRaw
	optPath
)

// readOpts is the allowlist of options for each read-only command.
// A token that starts with - and is not listed is refused.
var readOpts = map[string]map[string]optKind{
	"cat": flagSet(
		"-n", "--number", "-b", "--number-nonblank", "-A", "--show-all",
		"-E", "--show-ends", "-T", "--show-tabs", "-v", "--show-nonprinting",
		"-s", "--squeeze-blank", "-e", "-t", "-u",
	),
	"ls": flagSet(
		"-a", "-A", "-C", "-d", "-F", "-h", "-i", "-l", "-n", "-r", "-R", "-s", "-S", "-t", "-1", "-g", "-o", "-G",
		"--all", "--almost-all", "--classify", "--human-readable", "--inode",
		"--numeric-uid-gid", "--reverse", "--recursive", "--size", "--directory",
	),
	"head": mergeOpts(flagSet("-q", "--quiet", "--silent", "-v", "--verbose"), rawSet("-n", "--lines", "-c", "--bytes")),
	"tail": mergeOpts(flagSet("-q", "--quiet", "--silent", "-v", "--verbose"), rawSet("-n", "--lines", "-c", "--bytes")),
	"wc": flagSet(
		"-c", "-l", "-m", "-w", "-L",
		"--bytes", "--chars", "--lines", "--words", "--max-line-length",
	),
	"pwd":  flagSet("-L", "-P", "--logical", "--physical"),
	"stat": mergeOpts(flagSet("-t", "--terse"), rawSet("-c", "--format", "--printf")),
	"file": flagSet(
		"-b", "--brief", "-i", "--mime", "--mime-type", "--mime-encoding",
		"-h", "--no-dereference", "-N", "--no-pad",
	),
	"grep": mergeOpts(flagSet(
		"-n", "--line-number", "-H", "--with-filename", "-h", "--no-filename",
		"-i", "--ignore-case", "-E", "--extended-regexp", "-F", "--fixed-strings",
		"-w", "--word-regexp", "-x", "--line-regexp", "-o", "--only-matching",
		"-v", "--invert-match", "-c", "--count", "-l", "--files-with-matches",
		"-L", "--files-without-match", "-a", "--text", "-I", "-s", "--no-messages",
		"-q", "--quiet", "--silent", "-r", "--recursive",
	), rawSet(
		"-m", "--max-count", "-A", "--after-context", "-B", "--before-context",
		"-C", "--context", "-e", "--regexp", "--include", "--exclude", "--exclude-dir",
	)),
	"rg": mergeOpts(flagSet(
		"-n", "--line-number", "-i", "--ignore-case", "-w", "--word-regexp",
		"-l", "--files-with-matches", "-c", "--count", "-H", "--with-filename",
		"--no-filename", "-o", "--only-matching", "-v", "--invert-match",
		"-s", "--case-sensitive", "-S", "--smart-case", "-F", "--fixed-strings",
		"-a", "--text", "--heading", "--no-heading", "--column",
	), rawSet(
		"-g", "--glob", "-t", "--type", "-T", "--type-not", "-m", "--max-count",
		"-A", "--after-context", "-B", "--before-context", "-C", "--context",
		"-e", "--regexp", "-d", "--max-depth",
	)),
	"find": mergeOpts(flagSet(
		"-print", "-print0", "-o", "-or", "-a", "-and", "-not",
		"-true", "-false", "-prune", "-depth", "-xdev", "-mount", "-noleaf",
		"-empty", "-readable", "-nouser", "-nogroup", "-P", "-quit",
	), mergeOpts(rawSet(
		"-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename",
		"-regex", "-iregex", "-maxdepth", "-mindepth", "-type", "-size",
		"-mtime", "-mmin", "-ctime", "-cmin", "-group", "-user", "-perm", "-links",
	), pathSet("-newer"))),
}

func flagSet(names ...string) map[string]optKind {
	out := map[string]optKind{}
	for _, n := range names {
		out[n] = optFlag
	}
	return out
}

func rawSet(names ...string) map[string]optKind {
	out := map[string]optKind{}
	for _, n := range names {
		out[n] = optRaw
	}
	return out
}

func pathSet(names ...string) map[string]optKind {
	out := map[string]optKind{}
	for _, n := range names {
		out[n] = optPath
	}
	return out
}

func mergeOpts(parts ...map[string]optKind) map[string]optKind {
	out := map[string]optKind{}
	for _, p := range parts {
		for k, v := range p {
			out[k] = v
		}
	}
	return out
}

func supportsEndOfOptions(bin string) bool {
	switch bin {
	case "cat", "ls", "head", "tail", "wc", "stat", "file", "grep", "rg", "find":
		return true
	default:
		return false
	}
}

func checkFileArgs(toks []string, workspace string, resolve bool) *argProblem {
	if len(toks) == 0 {
		return &argProblem{kind: "unknown", sens: "unknown", reason: "empty command"}
	}
	bin := toks[0]
	table := readOpts[bin]
	if table == nil {
		return &argProblem{kind: "unknown", sens: "unknown", reason: "command is not a known read-only prefix"}
	}
	files := false
	expr := false
	hasPattern := false
	needsPattern := bin == "grep" || bin == "rg"
	for i := 1; i < len(toks); i++ {
		t := toks[i]
		if !files && t == "--" {
			if !supportsEndOfOptions(bin) {
				return &argProblem{kind: "unknown", sens: "unknown", reason: "operand starts with -"}
			}
			files = true
			continue
		}
		if files && bin == "find" && (expr || findExprStart(t)) {
			expr = true
		}
		if !files || expr {
			kind, attached, hasAttached, ok := lookupOpt(bin, t)
			if ok {
				if needsPattern && (optName(t) == "-e" || optName(t) == "--regexp") {
					hasPattern = true
				}
				if kind != optFlag && !hasAttached {
					i++
					if i >= len(toks) {
						return &argProblem{kind: "unknown", sens: "unknown", reason: "option is not permitted"}
					}
					attached = toks[i]
					hasAttached = true
				}
				if kind == optPath && hasAttached {
					if prob := pathProblem(attached, workspace, resolve); prob != nil {
						return prob
					}
				}
				continue
			}
		}
		if !files {
			if needsPattern && !hasPattern && !strings.HasPrefix(t, "-") {
				hasPattern = true
				continue
			}
			if strings.HasPrefix(t, "-") {
				if !supportsEndOfOptions(bin) {
					return &argProblem{kind: "unknown", sens: "unknown", reason: "operand starts with -"}
				}
				return &argProblem{kind: "unknown", sens: "unknown", reason: "option is not permitted"}
			}
			if supportsEndOfOptions(bin) {
				// A path that is already outside is reported as such. A path
				// that would be inside still needs -- before the operand.
				if prob := pathProblem(t, workspace, resolve); prob != nil {
					return prob
				}
				return &argProblem{kind: "unknown", sens: "unknown", reason: "file operand requires --"}
			}
		}
		if bin == "pwd" {
			return &argProblem{kind: "unknown", sens: "unknown", reason: "pwd does not take a path"}
		}
		if prob := pathProblem(t, workspace, resolve); prob != nil {
			return prob
		}
	}
	if needsPattern && !hasPattern {
		return &argProblem{kind: "unknown", sens: "unknown", reason: "command is not a known read-only prefix"}
	}
	return nil
}

func findExprStart(t string) bool {
	if t == "!" || t == "(" || t == ")" {
		return true
	}
	_, ok := readOpts["find"][t]
	return ok
}

func optName(token string) string {
	if name, _, ok := strings.Cut(token, "="); ok && strings.HasPrefix(token, "--") {
		return name
	}
	if strings.HasPrefix(token, "-") && !strings.HasPrefix(token, "--") && len(token) > 2 {
		return token[:2]
	}
	return token
}

func lookupOpt(bin, token string) (kind optKind, attached string, hasAttached, ok bool) {
	table := readOpts[bin]
	if table == nil {
		return 0, "", false, false
	}
	if k, found := table[token]; found {
		return k, "", false, true
	}
	if strings.HasPrefix(token, "--") {
		name, val, has := strings.Cut(token, "=")
		if !has {
			return 0, "", false, false
		}
		k, found := table[name]
		if !found || k == optFlag {
			return 0, "", false, false
		}
		return k, val, true, true
	}
	if (bin == "head" || bin == "tail") && numericShort(token) {
		return optFlag, "", false, true
	}
	if strings.HasPrefix(token, "-") && len(token) > 2 {
		letter := token[:2]
		if k, found := table[letter]; found && k != optFlag {
			return k, token[2:], true, true
		}
		for i := 1; i < len(token); i++ {
			k, found := table["-"+token[i:i+1]]
			if !found || k != optFlag {
				return 0, "", false, false
			}
		}
		return optFlag, "", false, true
	}
	return 0, "", false, false
}

func numericShort(token string) bool {
	if len(token) < 2 || token[0] != '-' {
		return false
	}
	for _, c := range token[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func pathLabel(p, workspace string) string {
	p = strings.Trim(strings.TrimSpace(p), `"'`)
	if p == "" {
		return "unknown"
	}
	if credentialPath(p) {
		return "credential"
	}
	if isHome(p) && !withinWorkspace(p, workspace) {
		return "home"
	}
	if isSystem(p) && !withinWorkspace(p, workspace) {
		return "system"
	}
	if withinWorkspace(p, workspace) || (strings.TrimSpace(workspace) == "" && !filepath.IsAbs(p) && !strings.Contains(p, "..") && !isHome(p)) {
		return "project"
	}
	if isSystem(p) {
		return "system"
	}
	if isHome(p) {
		return "home"
	}
	return "unknown"
}

func pathProblem(p, workspace string, resolve bool) *argProblem {
	if !resolve {
		return nil
	}
	p = strings.Trim(strings.TrimSpace(p), `"'`)
	if p == "" {
		return &argProblem{kind: "unknown", sens: "unknown", reason: "path is outside the workspace"}
	}
	if credentialPath(p) {
		return &argProblem{kind: "credential", sens: "credential", reason: "path is a credential path"}
	}
	if isHome(p) && !withinWorkspace(p, workspace) {
		return &argProblem{kind: "home", sens: "home", reason: "path is outside the workspace"}
	}
	if isSystem(p) && !withinWorkspace(p, workspace) {
		return &argProblem{kind: "system", sens: "system", reason: "path is outside the workspace"}
	}
	lexicalInside := withinWorkspace(p, workspace)
	if !lexicalInside {
		if strings.TrimSpace(workspace) == "" && !filepath.IsAbs(p) && !strings.Contains(p, "..") && !isHome(p) {
			return nil
		}
		if isSystem(p) {
			return &argProblem{kind: "system", sens: "system", reason: "path is outside the workspace"}
		}
		if isHome(p) {
			return &argProblem{kind: "home", sens: "home", reason: "path is outside the workspace"}
		}
		return &argProblem{kind: "unknown", sens: "unknown", reason: "path is outside the workspace"}
	}
	if !resolve || strings.TrimSpace(workspace) == "" {
		return nil
	}
	// Symlink resolution runs at decision time, before the tool. A path can
	// change between this check and the run. Sandbox read limits are the
	// backstop for that gap.
	inside, missing, cred := resolvesInside(p, workspace)
	if cred {
		return &argProblem{kind: "credential", sens: "credential", reason: "path is a credential path"}
	}
	if inside {
		return nil
	}
	if missing {
		return &argProblem{kind: "unknown", sens: "unknown", reason: "path parent is missing"}
	}
	return &argProblem{kind: "unknown", sens: "unknown", reason: "path resolves outside the workspace"}
}

// resolvesInside evaluates symlinks. The final component may be absent when
// its parent exists and stays inside the workspace. A missing parent is refused.
func resolvesInside(p, workspace string) (inside, missingParent, credential bool) {
	root, err := resolvedDir(workspace)
	if err != nil {
		return false, true, false
	}
	candidate := p
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	} else if abs, absErr := filepath.Abs(candidate); absErr == nil {
		candidate = abs
	}
	candidate = filepath.Clean(candidate)
	if resolved, err := filepath.EvalSymlinks(candidate); err == nil {
		resolved = filepath.Clean(resolved)
		if credentialPath(resolved) {
			return false, false, true
		}
		return insideRoot(resolved, root), false, false
	}
	if st, statErr := os.Lstat(candidate); statErr == nil && st != nil {
		return false, false, false
	}
	parent := filepath.Dir(candidate)
	if _, err := os.Lstat(parent); err != nil {
		return false, true, false
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return false, false, false
	}
	resolvedParent = filepath.Clean(resolvedParent)
	full := filepath.Join(resolvedParent, filepath.Base(candidate))
	if credentialPath(full) {
		return false, false, true
	}
	return insideRoot(full, root), false, false
}

func resolvedDir(path string) (string, error) {
	clean := filepath.Clean(path)
	if abs, err := filepath.Abs(clean); err == nil {
		clean = abs
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func insideRoot(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

func withinWorkspace(p, workspace string) bool {
	if strings.TrimSpace(workspace) == "" || strings.HasPrefix(p, "~") {
		return false
	}
	ws := filepath.Clean(workspace)
	if abs, err := filepath.Abs(ws); err == nil {
		ws = abs
	}
	candidate := p
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(ws, candidate)
	} else if abs, err := filepath.Abs(candidate); err == nil {
		candidate = abs
	}
	candidate = filepath.Clean(candidate)
	return candidate == ws || strings.HasPrefix(candidate, ws+string(filepath.Separator))
}

func isHome(p string) bool {
	if strings.HasPrefix(p, "~") {
		return true
	}
	clean := filepath.Clean(p)
	return strings.HasPrefix(clean, "/home/") || strings.HasPrefix(clean, "/Users/") || clean == "/root" || strings.HasPrefix(clean, "/root/")
}

func isSystem(p string) bool {
	if !filepath.IsAbs(p) {
		return false
	}
	clean := filepath.Clean(p)
	for _, pre := range []string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/proc", "/sys", "/dev", "/boot", "/System", "/private", "/var/log", "/var/run"} {
		if clean == pre || strings.HasPrefix(clean, pre+"/") {
			return true
		}
	}
	return false
}
