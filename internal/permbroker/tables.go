package permbroker

import "strings"

// TableVersion is the shipped risk table. Policy may raise a level.
// It is stored on every audit row.
const TableVersion = "builtin-2026-10-29.2"

// allowedBinaries are the basenames a rule may name. The daemon still
// resolves argv0 to an absolute path on the pinned PATH.
var allowedBinaries = map[string]struct{}{
	"git": {}, "gh": {},
	"head": {}, "tail": {}, "wc": {}, "sort": {},
	"uniq": {}, "cut": {}, "grep": {}, "jq": {},
}

func binaryAllowed(base string) bool {
	_, ok := allowedBinaries[base]
	return ok
}

type flagSet struct {
	bools map[string]struct{}
	vals  map[string]struct{}
	nums  bool
}

func (f flagSet) ok(args []string) ([]string, bool) {
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			rest = append(rest, args[i+1:]...)
			return rest, positionalOK(args[i+1:])
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			rest = append(rest, a)
			continue
		}
		// A listed token such as -sb or --rebase=false is one flag.
		// Dangerous tokens are rejected even when a table names them.
		if _, listed := f.bools[a]; listed && !dangerousGitToken(a) {
			continue
		}
		name, val, has := splitFlag(a)
		if dangerousGitToken(a) || dangerousGitToken(name) {
			return nil, false
		}
		if has {
			if _, ok := f.vals[name]; !ok {
				return nil, false
			}
			if dangerousGitToken(val) || strings.HasPrefix(val, "-") && val != "-" {
				return nil, false
			}
			continue
		}
		if _, ok := f.bools[name]; ok {
			continue
		}
		if _, ok := f.vals[name]; ok {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
			}
			continue
		}
		if f.nums && numFlag(name) {
			continue
		}
		return nil, false
	}
	return rest, positionalOK(rest)
}

func positionalOK(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "-") && a != "-" {
			return false
		}
	}
	return true
}

func splitFlag(a string) (name, val string, has bool) {
	if strings.HasPrefix(a, "--") {
		if n, v, ok := strings.Cut(a, "="); ok {
			return n, v, true
		}
		return a, "", false
	}
	if strings.HasPrefix(a, "-") && len(a) > 2 && a != "--" {
		// -Cpath and -n5 stay attached. Callers that take a value
		// also accept the separate-argument form.
		return a[:2], a[2:], true
	}
	return a, "", false
}

func numFlag(name string) bool {
	if len(name) < 2 || name[0] != '-' || name[1] == '-' {
		return false
	}
	for _, r := range name[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func dangerousGitToken(tok string) bool {
	switch tok {
	case "-c", "--config-env", "--exec-path", "--git-dir", "--work-tree",
		"--ext-diff", "--textconv", "--open-files-in-pager", "--upload-pack",
		"--super-prefix", "--namespace", "--bare", "--config":
		return true
	}
	for _, p := range []string{
		"--config-env=", "--exec-path=", "--git-dir=", "--work-tree=",
		"--output=", "--upload-pack=", "--open-files-in-pager=",
		"--super-prefix=", "--namespace=",
	} {
		if strings.HasPrefix(tok, p) {
			return true
		}
	}
	if strings.HasPrefix(tok, "-c") && !strings.HasPrefix(tok, "-C") {
		return true
	}
	return false
}

func fs(bools, vals string) flagSet {
	f := flagSet{bools: map[string]struct{}{}, vals: map[string]struct{}{}}
	for _, s := range strings.Fields(bools) {
		f.bools[s] = struct{}{}
	}
	for _, s := range strings.Fields(vals) {
		f.vals[s] = struct{}{}
	}
	return f
}

var gitGlobal = func() flagSet {
	f := fs(
		"--no-pager --literal-pathspecs --no-optional-locks --no-replace-objects",
		"-C",
	)
	return f
}()

type gitCmd struct {
	level    Level
	flags    flagSet
	write    bool
	read     bool
	critical bool
	hard     bool
	sub      map[string]gitCmd
}

func gitTable() map[string]gitCmd {
	logFlags := fs("--oneline --stat --name-only --name-status --graph --decorate --all --branches --tags --remotes --no-ext-diff --no-textconv --patch", "-n --max-count --pretty --format")
	logFlags.nums = true
	diffFlags := fs("--stat --name-only --name-status --numstat --shortstat --cached --staged --no-ext-diff --no-textconv --patch", "")
	showFlags := fs("--stat --name-only --name-status --oneline --no-ext-diff --no-textconv --patch", "-n --max-count --pretty --format")
	showFlags.nums = true
	statusFlags := fs("-s --short -b --branch --porcelain -z --long --ahead-behind --no-ahead-behind --renames --no-renames -sb", "--untracked-files -u --ignored --find-renames")
	return map[string]gitCmd{
		"status":      {level: LevelLow, flags: statusFlags, read: true},
		"log":         {level: LevelLow, flags: logFlags, read: true},
		"diff":        {level: LevelLow, flags: diffFlags, read: true},
		"show":        {level: LevelLow, flags: showFlags, read: true},
		"rev-parse":   {level: LevelLow, flags: fs("--abbrev-ref --verify --short --show-toplevel --is-inside-work-tree --quiet", ""), read: true},
		"ls-files":    {level: LevelLow, flags: fs("-s -m -o -d -u -z --stage --modified --others --deleted --unmerged", ""), read: true},
		"blame":       {level: LevelLow, flags: fs("-p --porcelain -e --show-email", "-L"), read: true},
		"describe":    {level: LevelLow, flags: fs("--tags --always --dirty --long", "--match --abbrev"), read: true},
		"shortlog":    {level: LevelLow, flags: fs("-s -n -e --summary --numbered --email", ""), read: true},
		"name-rev":    {level: LevelLow, flags: fs("--name-only --tags --always", ""), read: true},
		"rev-list":    {level: LevelLow, flags: fs("--count --oneline --all --max-count", "-n"), read: true},
		"grep":        {level: LevelLow, flags: fs("-n -i -I -w --line-number --ignore-case", "-e --regexp"), read: true},
		"version":     {level: LevelLow, flags: fs("", ""), read: true},
		"help":        {level: LevelLow, flags: fs("-a --all", ""), read: true},
		"add":         {level: LevelMedium, flags: fs("-A --all -u --update -n --dry-run -v --verbose", ""), write: true},
		"restore":     {level: LevelMedium, flags: fs("--staged --worktree --source --ours --theirs", ""), write: true},
		"checkout":    {level: LevelMedium, flags: fs("-b -B --orphan", ""), write: true},
		"switch":      {level: LevelMedium, flags: fs("-c -C --create --orphan --detach", ""), write: true},
		"commit":      {level: LevelMedium, flags: fs("-a --all --amend --allow-empty --dry-run", "-m --message"), write: true},
		"branch":      {level: LevelMedium, flags: fs("-d -D -m -M -a -v -vv --list --show-current --all", ""), write: true},
		"tag":         {level: LevelMedium, flags: fs("-a -d -l --list --annotate --delete", "-m --message"), write: true},
		"fetch":       {level: LevelMedium, flags: fs("--dry-run --prune --tags --all", ""), write: true},
		"pull":        {level: LevelMedium, flags: fs("--ff-only --no-rebase --dry-run --rebase=false", ""), write: true},
		"clone":       {level: LevelMedium, flags: fs("--bare", "--depth --branch"), write: true},
		"init":        {level: LevelMedium, flags: fs("-q --quiet --bare", "-b --initial-branch"), write: true},
		"merge":       {level: LevelMedium, flags: fs("--ff-only --no-ff --squash --abort", "-m --message"), write: true},
		"rebase":      {level: LevelMedium, flags: fs("--continue --abort --skip", ""), write: true},
		"reset":       {level: LevelMedium, flags: fs("--soft --mixed --hard", ""), write: true},
		"rm":          {level: LevelMedium, flags: fs("-r -f --cached --dry-run", ""), write: true},
		"mv":          {level: LevelMedium, flags: fs("-f -n --dry-run", ""), write: true},
		"cherry-pick": {level: LevelMedium, flags: fs("--continue --abort --skip -n --no-commit", ""), write: true},
		"revert":      {level: LevelMedium, flags: fs("--continue --abort --skip -n --no-commit", ""), write: true},
		"clean":       {level: LevelMedium, flags: fs("-n -d -f -fd -nd --dry-run", ""), write: true},
		"apply":       {level: LevelMedium, flags: fs("--check --index --cached --reverse", ""), write: true},
		"stash": {
			level: LevelMedium, write: true,
			flags: fs("list show pop push drop apply clear", ""),
			sub: map[string]gitCmd{
				"list":  {level: LevelLow, flags: fs("", ""), read: true},
				"show":  {level: LevelLow, flags: fs("--stat", ""), read: true},
				"push":  {level: LevelMedium, flags: fs("-u --include-untracked -a --all -m", "--message"), write: true},
				"pop":   {level: LevelMedium, flags: fs("", ""), write: true},
				"apply": {level: LevelMedium, flags: fs("", ""), write: true},
				"drop":  {level: LevelMedium, flags: fs("", ""), write: true},
				"clear": {level: LevelMedium, flags: fs("", ""), write: true},
			},
		},
		"ls-remote": {level: LevelMedium, flags: fs("--heads --tags --refs", ""), read: true},
		"submodule": {level: LevelMedium, flags: fs("status update init", ""), write: true},
		"push":      {level: LevelHigh, flags: fs("--dry-run -n --porcelain --tags -u --set-upstream", ""), write: true},
		"config":    {level: LevelCritical, critical: true, hard: true},
		"remote":    {level: LevelCritical, critical: true, hard: true},
	}
}

func gitSubcommand(argv []string) string {
	sub, _, _ := splitGit(argv)
	return sub
}

func splitGit(argv []string) (sub string, rest []string, ok bool) {
	if len(argv) == 0 || baseName(argv[0]) != "git" {
		return "", nil, false
	}
	args := argv[1:]
	for len(args) > 0 {
		a := args[0]
		if a == "--" {
			args = args[1:]
			break
		}
		if !strings.HasPrefix(a, "-") {
			break
		}
		if dangerousGitToken(a) {
			return "", nil, false
		}
		name, _, has := splitFlag(a)
		if _, isBool := gitGlobal.bools[name]; isBool && !has {
			args = args[1:]
			continue
		}
		if _, isVal := gitGlobal.vals[name]; isVal {
			if has {
				args = args[1:]
				continue
			}
			if len(args) < 2 {
				return "", nil, false
			}
			args = args[2:]
			continue
		}
		return "", nil, false
	}
	if len(args) == 0 {
		return "", nil, false
	}
	return args[0], args[1:], true
}

func gitPaths(argv []string) []string {
	sub, rest, ok := splitGit(argv)
	if !ok {
		return nil
	}
	cmd, known := gitTable()[sub]
	if !known {
		return nil
	}
	if len(cmd.sub) > 0 && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		if nested, ok := cmd.sub[rest[0]]; ok {
			cmd = nested
			rest = rest[1:]
		}
	}
	pos, good := cmd.flags.ok(rest)
	if !good {
		return nil
	}
	var paths []string
	paths = append(paths, gitDashC(argv)...)
	paths = append(paths, pathTokens(pos)...)
	return paths
}

func gitDashC(argv []string) []string {
	var out []string
	args := argv[1:]
	for len(args) > 0 {
		a := args[0]
		if a == "--" || !strings.HasPrefix(a, "-") {
			break
		}
		name, val, has := splitFlag(a)
		if name == "-C" {
			if has {
				out = append(out, val)
			} else if len(args) > 1 {
				out = append(out, args[1])
			}
		}
		if _, isVal := gitGlobal.vals[name]; isVal && !has {
			if len(args) < 2 {
				break
			}
			args = args[2:]
			continue
		}
		args = args[1:]
	}
	return out
}

type ghCmd struct {
	level    Level
	flags    flagSet
	read     bool
	write    bool
	critical bool
	hard     bool
	sub      map[string]ghCmd
}

func ghTable() map[string]ghCmd {
	view := fs("--comments --json --web", "--jq --template")
	// --web is rejected before the flag set is consulted.
	_ = view
	common := fs("--comments --json", "--jq --template")
	return map[string]ghCmd{
		"pr": {sub: map[string]ghCmd{
			"view":     {level: LevelLow, flags: common, read: true},
			"list":     {level: LevelLow, flags: fs("--state --json --limit", "--search"), read: true},
			"status":   {level: LevelLow, flags: fs("--json", ""), read: true},
			"diff":     {level: LevelLow, flags: fs("--color=never --name-only", ""), read: true},
			"checks":   {level: LevelLow, flags: fs("--watch=false", ""), read: true},
			"comment":  {level: LevelMedium, flags: fs("", "--body -b"), write: true},
			"create":   {level: LevelMedium, flags: fs("--draft --fill", "--title --body -t -b --base --head"), write: true},
			"merge":    {level: LevelHigh, flags: fs("--merge --squash --rebase", ""), write: true},
			"close":    {level: LevelMedium, flags: fs("", ""), write: true},
			"reopen":   {level: LevelMedium, flags: fs("", ""), write: true},
			"ready":    {level: LevelMedium, flags: fs("", ""), write: true},
			"review":   {level: LevelMedium, flags: fs("--approve --comment --request-changes", "--body"), write: true},
			"checkout": {level: LevelMedium, flags: fs("--detach", "-b"), write: true},
			"edit":     {level: LevelMedium, flags: fs("", "--title --body"), write: true},
		}},
		"issue": {sub: map[string]ghCmd{
			"view":    {level: LevelLow, flags: common, read: true},
			"list":    {level: LevelLow, flags: fs("--state --json --limit", "--search"), read: true},
			"status":  {level: LevelLow, flags: fs("", ""), read: true},
			"create":  {level: LevelMedium, flags: fs("", "--title --body -t -b"), write: true},
			"comment": {level: LevelMedium, flags: fs("", "--body -b"), write: true},
			"close":   {level: LevelMedium, flags: fs("", ""), write: true},
			"reopen":  {level: LevelMedium, flags: fs("", ""), write: true},
		}},
		"repo": {sub: map[string]ghCmd{
			"view":  {level: LevelLow, flags: fs("--json", ""), read: true},
			"list":  {level: LevelLow, flags: fs("--limit --json", ""), read: true},
			"clone": {level: LevelMedium, flags: fs("", ""), write: true},
		}},
		"run": {sub: map[string]ghCmd{
			"list": {level: LevelLow, flags: fs("--limit --json", ""), read: true},
			"view": {level: LevelLow, flags: fs("--json --log", ""), read: true},
		}},
		"release": {sub: map[string]ghCmd{
			"list": {level: LevelLow, flags: fs("--limit --json", ""), read: true},
			"view": {level: LevelLow, flags: fs("--json", ""), read: true},
		}},
		"search": {sub: map[string]ghCmd{
			"issues": {level: LevelLow, flags: fs("--limit --json", ""), read: true},
			"prs":    {level: LevelLow, flags: fs("--limit --json", ""), read: true},
			"repos":  {level: LevelLow, flags: fs("--limit --json", ""), read: true},
		}},
		"status":    {level: LevelLow, flags: fs("", ""), read: true},
		"api":       {level: LevelHigh, hard: true},
		"alias":     {level: LevelHigh, hard: true},
		"extension": {level: LevelHigh, hard: true},
		"config":    {level: LevelHigh, hard: true},
		"variable":  {level: LevelHigh, hard: true},
		"auth":      {level: LevelCritical, critical: true, hard: true},
		"secret":    {level: LevelCritical, critical: true, hard: true},
		"ssh-key":   {level: LevelCritical, critical: true, hard: true},
		"gpg-key":   {level: LevelHigh, hard: true},
		"browse":    {level: LevelHigh, hard: true},
	}
}

func ghWeb(argv []string) bool {
	for _, a := range argv {
		if a == "--web" {
			return true
		}
	}
	return false
}

func ghRepos(argv []string) (repos []string, ok bool) {
	if len(argv) == 0 || baseName(argv[0]) != "gh" {
		return nil, false
	}
	args := argv[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, has := splitFlag(a)
		if name == "-R" || name == "--repo" {
			if has {
				repos = append(repos, val)
				continue
			}
			if i+1 >= len(args) {
				return nil, false
			}
			i++
			repos = append(repos, args[i])
		}
	}
	return repos, true
}

func filterArgv(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	rest := argv[1:]
	switch baseName(argv[0]) {
	case "head":
		return headTailOK(rest)
	case "tail":
		return headTailOK(rest)
	case "wc":
		_, ok := fs("-l -w -c -m -L --lines --words --bytes --chars --max-line-length", "").ok(rest)
		return ok && len(pathTokens(rest)) == 0
	case "sort":
		f := fs("-u -r -n -h -V -s --stable -z --zero-terminated -b --ignore-leading-blanks", "-k --key -t --field-separator")
		pos, ok := f.ok(rest)
		return ok && len(pathTokens(pos)) == 0
	case "uniq":
		pos, ok := fs("-c -d -u -i -z", "-w --check-chars -f --skip-fields -s --skip-chars").ok(rest)
		return ok && len(pathTokens(pos)) == 0
	case "cut":
		pos, ok := fs("-s --only-delimited", "-f --fields -d --delimiter -c --characters -b --bytes").ok(rest)
		return ok && len(pathTokens(pos)) == 0
	case "grep":
		return grepFlagsOK(rest)
	case "jq":
		return jqFlagsOK(rest)
	default:
		return false
	}
}

func headTailOK(rest []string) bool {
	f := fs("-q --quiet -z --zero-terminated", "-n --lines -c --bytes")
	f.nums = true
	for _, a := range rest {
		if a == "-f" || a == "--follow" || strings.HasPrefix(a, "--follow") {
			return false
		}
	}
	pos, ok := f.ok(rest)
	return ok && len(pathTokens(pos)) == 0
}

func grepFlagsOK(rest []string) bool {
	for _, a := range rest {
		name, _, _ := splitFlag(a)
		switch name {
		case "-f", "--file", "-R", "-r", "--recursive", "--include", "--exclude", "--exclude-dir":
			return false
		}
	}
	pos, ok := fs("-n -i -E -F -w -x -v -c -l -o -H -h --line-number --ignore-case --extended-regexp --fixed-strings --word-regexp --line-regexp --invert-match --count --files-with-matches --only-matching", "-e --regexp -m --max-count").ok(rest)
	if !ok {
		return false
	}
	// A pattern is not a path. Extra positionals that look like paths are rejected.
	for _, p := range pos {
		if looksPath(p) {
			return false
		}
	}
	return true
}

func jqFlagsOK(rest []string) bool {
	for _, a := range rest {
		name, _, _ := splitFlag(a)
		switch name {
		case "-f", "--from-file", "--rawfile", "--slurpfile", "-L":
			return false
		}
	}
	got, good := fs("-r -c -e -n -M -a -s -S --raw-output --compact-output --exit-status --null-input --monochrome-output --ascii-output --slurp --sort-keys", "").ok(rest)
	if !good {
		return false
	}
	for _, p := range got {
		if looksPath(p) {
			return false
		}
	}
	return true
}

func pathTokens(args []string) []string {
	var out []string
	for _, a := range args {
		if looksPath(a) {
			out = append(out, a)
		}
	}
	return out
}

func looksPath(tok string) bool {
	if tok == "" || tok == "-" {
		return false
	}
	if strings.ContainsAny(tok, `/\`) || tok == "." || tok == ".." || strings.HasPrefix(tok, ".") && strings.Contains(tok, "/") {
		return true
	}
	return protectedBase(pathBase(tok))
}

func pathBase(tok string) string {
	tok = strings.ReplaceAll(tok, `\`, "/")
	if i := strings.LastIndex(tok, "/"); i >= 0 {
		return tok[i+1:]
	}
	return tok
}

func protectedBase(base string) bool {
	switch base {
	case ".mcp.json", ".gitattributes", ".envrc", ".bashrc", ".bash_profile",
		".bash_login", ".profile", ".zshrc", ".zshenv", ".zprofile", ".zlogin",
		".kshrc", ".cshrc", ".tcshrc", ".inputrc", ".gitconfig", ".netrc", ".pgpass",
		".env", ".credentials", "credentials.json", "id_rsa", "id_ed25519", "known_hosts":
		return true
	}
	if strings.HasPrefix(base, ".env") {
		return true
	}
	return false
}

func protectedPath(tok string) bool {
	t := strings.ReplaceAll(tok, `\`, "/")
	if protectedBase(pathBase(t)) {
		return true
	}
	if t == ".claude" || strings.HasPrefix(t, ".claude/") || strings.Contains(t, "/.claude/") {
		return true
	}
	if t == ".ssh" || strings.HasPrefix(t, ".ssh/") || strings.Contains(t, "/.ssh/") {
		return true
	}
	if strings.Contains(t, ".git/hooks/") || strings.HasSuffix(t, ".git/hooks") {
		return true
	}
	if strings.HasSuffix(t, ".git/config") {
		return true
	}
	if strings.Contains(t, ".config/gh/") || strings.HasSuffix(t, ".config/gh") {
		return true
	}
	if strings.Contains(t, ".claude/.credentials") {
		return true
	}
	return false
}
