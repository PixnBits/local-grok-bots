package permbroker

import "strings"

// ceilingGitRule is one row of the ceiling git allowlist. The slice
// ceilingGitAllow is the only table. A subcommand that is not a row asks.
// alwaysAsk rows write the work tree from content and ask at every ceiling.
// The shipped classifier table is a different list and is not this one.
type ceilingGitRule struct {
	sub       string
	alwaysAsk bool
	level     Level
	bools     string
	vals      string
	nums      bool
	kind      string
}

// ceilingGitAllow is the ceiling git allowlist. Safe rows name the flag
// shapes that may auto-approve. alwaysAsk rows are the content writers.
var ceilingGitAllow = []ceilingGitRule{
	{sub: "apply", alwaysAsk: true},
	{sub: "am", alwaysAsk: true},
	{sub: "checkout", alwaysAsk: true},
	{sub: "switch", alwaysAsk: true},
	{sub: "restore", alwaysAsk: true},
	{sub: "merge", alwaysAsk: true},
	{sub: "pull", alwaysAsk: true},
	{sub: "rebase", alwaysAsk: true},
	{sub: "cherry-pick", alwaysAsk: true},
	{sub: "revert", alwaysAsk: true},
	{sub: "reset", alwaysAsk: true},
	{sub: "stash", alwaysAsk: true},
	{sub: "mv", alwaysAsk: true},
	{sub: "read-tree", alwaysAsk: true},
	{sub: "worktree", alwaysAsk: true},
	{sub: "clone", alwaysAsk: true},
	{sub: "submodule", alwaysAsk: true},
	{sub: "checkout-index", alwaysAsk: true},
	{sub: "sparse-checkout", alwaysAsk: true},

	{sub: "status", level: LevelLow, kind: "status",
		bools: "-s --short -b --branch --porcelain -z --long --ahead-behind --no-ahead-behind --renames --no-renames -sb",
		vals:  "--untracked-files -u --ignored --find-renames"},
	{sub: "log", level: LevelLow, kind: "log", nums: true,
		bools: "--oneline --stat --name-only --name-status --graph --decorate --all --branches --tags --remotes --no-ext-diff --no-textconv",
		vals:  "-n --max-count --pretty --format"},
	{sub: "diff", level: LevelLow, kind: "diff",
		bools: "--stat --name-only --name-status --numstat --shortstat --cached --staged --no-ext-diff --no-textconv",
		vals:  ""},
	{sub: "show", level: LevelLow, kind: "show", nums: true,
		bools: "--stat --name-only --name-status --no-patch -s --no-ext-diff --no-textconv",
		vals:  "-n --max-count --pretty --format"},
	{sub: "rev-parse", level: LevelLow, kind: "rev",
		bools: "--abbrev-ref --verify --short --show-toplevel --is-inside-work-tree --quiet"},
	{sub: "ls-files", level: LevelLow, kind: "names",
		bools: "-s -m -o -d -u -z --stage --modified --others --deleted --unmerged"},
	{sub: "blame", level: LevelLow, kind: "blame",
		bools: "-p --porcelain -e --show-email",
		vals:  "-L"},
	{sub: "describe", level: LevelLow, kind: "rev",
		bools: "--tags --always --dirty --long",
		vals:  "--match --abbrev"},
	{sub: "branch", level: LevelLow, kind: "branch",
		bools: "--list -l -a --all -v -vv --verbose -r --remotes"},
	{sub: "tag", level: LevelLow, kind: "tag",
		bools: "--list -l"},
	{sub: "remote", level: LevelLow, kind: "remote"},
	{sub: "add", level: LevelMedium, kind: "add",
		bools: "-n --dry-run -v --verbose"},
	{sub: "commit", level: LevelMedium, kind: "commit"},
}

func ceilingGitLookup(sub string) (ceilingGitRule, bool) {
	for _, rule := range ceilingGitAllow {
		if rule.sub == sub {
			return rule, true
		}
	}
	return ceilingGitRule{}, false
}

// ceilingGitAlwaysAsk reports a work-tree content writer. Tests pin the
// row so removing the name from the table is visible.
func ceilingGitAlwaysAsk(sub string) bool {
	rule, ok := ceilingGitLookup(sub)
	return ok && rule.alwaysAsk
}

func ceilingGitInvocation(in inspected) bool {
	return len(gitArgvsOf(in)) > 0
}

func gitArgvsOf(in inspected) [][]string {
	var out [][]string
	if len(in.Argv) > 0 && baseName(in.Argv[0]) == "git" {
		out = append(out, in.Argv)
	}
	for _, p := range in.Parts {
		if len(p.Argv) > 0 && baseName(p.Argv[0]) == "git" {
			// A single command stores argv and not parts. A compound
			// stores parts. Skip a part that is the same slice.
			if len(in.Argv) > 0 && sameArgv(in.Argv, p.Argv) {
				continue
			}
			out = append(out, p.Argv)
		}
	}
	return out
}

func sameArgv(a, b []string) bool {
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

// ceilingGitPermitted is true when every git argv is an allowlist row
// whose flag shape matches and the command does not read a secret.
func ceilingGitPermitted(in inspected) bool {
	argvs := gitArgvsOf(in)
	if len(argvs) == 0 {
		return false
	}
	for _, argv := range argvs {
		if !ceilingGitPermit(argv) || gitSecretRead(argv) {
			return false
		}
	}
	return true
}

func ceilingGitPermit(argv []string) bool {
	sub, rest, ok := splitGit(argv)
	if !ok || sub == "" {
		return false
	}
	rule, found := ceilingGitLookup(sub)
	if !found || rule.alwaysAsk {
		return false
	}
	return ceilingGitShape(rule, rest)
}

func ceilingGitAllowLevel(argv []string) Level {
	sub, _, ok := splitGit(argv)
	if !ok {
		return ""
	}
	rule, found := ceilingGitLookup(sub)
	if !found || rule.alwaysAsk {
		return ""
	}
	return rule.level
}

// ceilingDecisionLevel is the level the ceiling compares for an allowlisted
// git command. A policy or classifier raise above the shipped level is kept.
// git remote is critical in the shipped table. The list form is low here.
func ceilingDecisionLevel(in inspected) Level {
	if len(in.Argv) == 0 || baseName(in.Argv[0]) != "git" || !ceilingGitPermit(in.Argv) {
		return in.Level
	}
	allow := ceilingGitAllowLevel(in.Argv)
	if allow == "" {
		return in.Level
	}
	shipped := classifyArgv(in.Argv, "", "", nil, nil).Level
	if Rank(in.Level) > Rank(shipped) {
		return in.Level
	}
	return allow
}

func isRemoteList(argv []string) bool {
	sub, rest, ok := splitGit(argv)
	if !ok || sub != "remote" {
		return false
	}
	return remoteListOK(rest)
}

func ceilingGitShape(rule ceilingGitRule, rest []string) bool {
	switch rule.kind {
	case "status", "names":
		_, ok := parseAllowFlags(rest, rule.bools, rule.vals, rule.nums)
		return ok
	case "log":
		return logShape(rest, rule)
	case "diff":
		return diffShape(rest, rule)
	case "show":
		return showShape(rest, rule)
	case "rev":
		return revShape(rest, rule)
	case "blame":
		return blameShape(rest, rule)
	case "branch":
		return branchListOK(rest, rule)
	case "tag":
		return tagListOK(rest, rule)
	case "remote":
		return remoteListOK(rest)
	case "add":
		return addShape(rest, rule)
	case "commit":
		return commitShape(rest)
	default:
		return false
	}
}

func parseAllowFlags(rest []string, bools, vals string, nums bool) ([]string, bool) {
	f := fs(bools, vals)
	f.nums = nums
	return f.ok(rest)
}

func logShape(rest []string, rule ceilingGitRule) bool {
	pos, ok := parseAllowFlags(rest, rule.bools, rule.vals, rule.nums)
	if !ok {
		return false
	}
	for _, p := range pos {
		if strings.Contains(p, ":") {
			return false
		}
	}
	return true
}

func diffShape(rest []string, rule ceilingGitRule) bool {
	pos, ok := parseAllowFlags(rest, rule.bools, rule.vals, rule.nums)
	if !ok || !diffFormat(rest) {
		return false
	}
	for _, p := range pos {
		if strings.Contains(p, ":") || gitSecretReadPath(p) {
			return false
		}
	}
	return true
}

func diffFormat(rest []string) bool {
	for _, a := range rest {
		if a == "--" {
			break
		}
		switch a {
		case "--stat", "--name-only", "--name-status", "--numstat", "--shortstat":
			return true
		}
	}
	return false
}

func showShape(rest []string, rule ceilingGitRule) bool {
	pos, ok := parseAllowFlags(rest, rule.bools, rule.vals, rule.nums)
	if !ok || !showFormat(rest) {
		return false
	}
	for _, p := range pos {
		if strings.Contains(p, ":") || gitSecretReadPath(p) {
			return false
		}
	}
	return true
}

func showFormat(rest []string) bool {
	for _, a := range rest {
		if a == "--" {
			break
		}
		switch a {
		case "--stat", "--name-only", "--name-status", "--no-patch", "-s":
			return true
		}
	}
	return false
}

func revShape(rest []string, rule ceilingGitRule) bool {
	pos, ok := parseAllowFlags(rest, rule.bools, rule.vals, rule.nums)
	if !ok {
		return false
	}
	for _, p := range pos {
		if strings.Contains(p, ":") || gitSecretReadPath(p) {
			return false
		}
	}
	return true
}

func blameShape(rest []string, rule ceilingGitRule) bool {
	pos, ok := parseAllowFlags(rest, rule.bools, rule.vals, rule.nums)
	if !ok || len(pos) == 0 {
		return false
	}
	for _, p := range pos {
		if strings.Contains(p, ":") || gitSecretReadPath(p) {
			return false
		}
	}
	return true
}

func branchListOK(rest []string, rule ceilingGitRule) bool {
	pos, ok := parseAllowFlags(rest, rule.bools, rule.vals, rule.nums)
	if !ok {
		return false
	}
	if len(pos) == 0 {
		return true
	}
	for _, a := range rest {
		if a == "--" {
			break
		}
		switch a {
		case "--list", "-l", "-a", "--all", "-v", "-vv", "--verbose", "-r", "--remotes":
			return true
		}
	}
	return false
}

func tagListOK(rest []string, rule ceilingGitRule) bool {
	pos, ok := parseAllowFlags(rest, rule.bools, rule.vals, rule.nums)
	if !ok {
		return false
	}
	if len(pos) == 0 {
		return true
	}
	for _, a := range rest {
		if a == "--" {
			break
		}
		if a == "--list" || a == "-l" {
			return true
		}
	}
	return false
}

func remoteListOK(rest []string) bool {
	if len(rest) == 0 {
		return true
	}
	return len(rest) == 1 && (rest[0] == "-v" || rest[0] == "--verbose")
}

func addShape(rest []string, rule ceilingGitRule) bool {
	pos, ok := parseAllowFlags(rest, rule.bools, rule.vals, rule.nums)
	if !ok || len(pos) == 0 {
		return false
	}
	for _, p := range pos {
		if p == "." || p == "./" || p == ".." {
			return false
		}
	}
	return true
}

// commitShape is -m or --message, repeated, plus optional pathspecs.
// --amend, -F, --no-verify, and -a are not in the shape.
func commitShape(rest []string) bool {
	saw := false
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if a == "--" {
			for _, p := range rest[i+1:] {
				if p == "." || p == "./" {
					return false
				}
			}
			return saw
		}
		if a == "-m" || a == "--message" {
			if i+1 >= len(rest) {
				return false
			}
			i++
			saw = true
			continue
		}
		if strings.HasPrefix(a, "--message=") && len(a) > len("--message=") {
			saw = true
			continue
		}
		if strings.HasPrefix(a, "-m") && len(a) > 2 && !strings.HasPrefix(a, "--") {
			saw = true
			continue
		}
		if strings.HasPrefix(a, "-") {
			return false
		}
	}
	return saw
}

// gitSecretRead is a git read of file content the ceiling must not
// auto-approve. cat-file always matches. grep matches with no pathspec
// and when a path is sensitive. show matches rev:path. diff and log -p
// match a sensitive path.
func gitSecretRead(argv []string) bool {
	if len(argv) == 0 || baseName(argv[0]) != "git" {
		return false
	}
	sub, rest, ok := splitGit(argv)
	if !ok {
		sub = recoverGitSub(argv)
		rest = argsAfterSub(argv, sub)
	}
	switch sub {
	case "cat-file":
		return true
	case "grep":
		return gitGrepAsks(rest)
	case "show":
		return showReadsContent(rest)
	case "diff":
		return diffReadsSecret(rest)
	case "log":
		return logPatchSecret(rest)
	case "blame":
		return pathsSecret(rest)
	default:
		return false
	}
}

func argsAfterSub(argv []string, sub string) []string {
	for i, a := range argv {
		if a == sub && i+1 <= len(argv) {
			return append([]string(nil), argv[i+1:]...)
		}
	}
	return nil
}

func gitGrepAsks(rest []string) bool {
	pos := gitGrepPaths(rest)
	if len(pos) == 0 {
		return true
	}
	for _, p := range pos {
		if gitSecretReadPath(p) {
			return true
		}
	}
	return false
}

func gitGrepPaths(rest []string) []string {
	var pos []string
	seenDash := false
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if a == "--" {
			seenDash = true
			pos = append(pos, rest[i+1:]...)
			break
		}
		if !seenDash && strings.HasPrefix(a, "-") {
			name, _, has := splitFlag(a)
			if !has && (name == "-e" || name == "--regexp") && i+1 < len(rest) {
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	if len(pos) == 0 {
		return nil
	}
	// The first positional is the pattern unless -- separated it.
	if !seenDash {
		return pos[1:]
	}
	return pos
}

func showReadsContent(rest []string) bool {
	for _, p := range positionalsOf(rest) {
		if strings.Contains(p, ":") || gitSecretReadPath(p) {
			return true
		}
	}
	return false
}

func diffReadsSecret(rest []string) bool {
	if !diffFormat(rest) {
		return true
	}
	for _, p := range positionalsOf(rest) {
		if strings.Contains(p, ":") || gitSecretReadPath(p) {
			return true
		}
	}
	return false
}

func logPatchSecret(rest []string) bool {
	patch := false
	for _, a := range rest {
		if a == "--" {
			break
		}
		switch a {
		case "-p", "--patch", "-u", "--unified":
			patch = true
		}
		if strings.HasPrefix(a, "-U") || strings.HasPrefix(a, "--unified=") {
			patch = true
		}
	}
	if !patch {
		return false
	}
	pos := positionalsOf(rest)
	if len(pos) == 0 {
		return true
	}
	for _, p := range pos {
		if gitSecretReadPath(p) {
			return true
		}
	}
	return true
}

func pathsSecret(rest []string) bool {
	for _, p := range positionalsOf(rest) {
		if gitSecretReadPath(p) {
			return true
		}
	}
	return false
}

func positionalsOf(rest []string) []string {
	var pos []string
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if a == "--" {
			pos = append(pos, rest[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			name, _, has := splitFlag(a)
			if !has && flagConsumesValue(name) && i+1 < len(rest) {
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	return pos
}

func flagConsumesValue(name string) bool {
	switch name {
	case "-m", "--message", "-F", "--file", "-n", "--max-count", "-L",
		"--pretty", "--format", "-e", "--regexp", "--author", "--date",
		"-c", "-C", "--git-dir", "--work-tree", "--output", "--exec-path",
		"--template", "--separate-git-dir", "--namespace", "--super-prefix",
		"--config-env", "--upload-pack", "--config", "--match", "--abbrev":
		return true
	default:
		return gitPathValueFlag(name)
	}
}

// gitSecretReadPath is a path whose contents a git read must not print.
// .env* includes example and sample. *.pem and *.key are included.
// id_* is a key name with no dot. Token files and .git/config are included.
func gitSecretReadPath(p string) bool {
	if p == "" || p == "-" {
		return false
	}
	if i := strings.LastIndex(p, ":"); i >= 0 && i+1 < len(p) {
		if gitSecretReadPath(p[i+1:]) {
			return true
		}
	}
	base := strings.ToLower(pathBase(p))
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}
	if strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") {
		return true
	}
	if strings.HasPrefix(base, "id_") && !strings.Contains(base, ".") {
		return true
	}
	if ceilingTokenFile(p) {
		return true
	}
	low := strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	if hookPathToken(low) {
		return true
	}
	return strings.HasSuffix(low, ".git/config") || strings.Contains(low, ".git/config/")
}

// gitPathValueFlag is a path-valued git flag. The value is checked the
// same way when it is attached with '=' or passed as the next argument.
func gitPathValueFlag(name string) bool {
	switch name {
	case "--separate-git-dir", "--template", "--reference", "--reference-if-able",
		"--git-dir", "--work-tree", "--output", "--exec-path", "-C":
		return true
	default:
		return false
	}
}

func gitPathFlagCreates(name string) bool {
	switch name {
	case "--separate-git-dir", "--template", "--git-dir", "--work-tree", "--exec-path", "-C":
		return true
	default:
		return false
	}
}

// gitFlagPath is one path taken from a path-valued git flag.
type gitFlagPath struct {
	value   string
	created bool
}

// messageValueIndexes marks the words after -m and --message so a
// commit message is not a path and not a hooksPath key.
func messageValueIndexes(argv []string) map[int]bool {
	out := map[int]bool{}
	if len(argv) == 0 || baseName(argv[0]) != "git" {
		return out
	}
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			break
		}
		name, _, has := splitFlag(a)
		if has || (name != "-m" && name != "--message") {
			continue
		}
		if i+1 < len(argv) {
			out[i+1] = true
			i++
		}
	}
	return out
}

func gitPathFlagPaths(argv []string) []gitFlagPath {
	var out []gitFlagPath
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			break
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			continue
		}
		name, val, has := splitFlag(a)
		if !gitPathValueFlag(name) {
			continue
		}
		if has {
			if val != "" {
				out = append(out, gitFlagPath{value: val, created: gitPathFlagCreates(name)})
			}
			continue
		}
		if i+1 < len(argv) {
			out = append(out, gitFlagPath{value: argv[i+1], created: gitPathFlagCreates(name)})
			i++
		}
	}
	return out
}
