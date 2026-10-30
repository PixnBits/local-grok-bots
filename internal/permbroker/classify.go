package permbroker

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// argvClass is the shipped classification of one normalized argv.
// Eligible means a bot or global rule may name it. Hard means a task
// grant may not cover it. Level is friction only: it never allows.
type argvClass struct {
	Level    Level
	Eligible bool
	Hard     bool
	Reason   string
}

// builtinLevel is the shipped floor for a policy row. Policy may raise
// it. A lower value is a startup error. Resolution and the workspace
// are not required: path classes that are visible in the words still count.
func builtinLevel(tool string, argv []string) Level {
	if normTool(tool) == ToolShell {
		if len(argv) == 0 {
			return LevelUnclassified
		}
		return classifyArgv(argv, "", "", nil, nil).Level
	}
	return otherBuiltin(normTool(tool), argv)
}

func classifyArgv(argv []string, cwd, workspace string, repos []string, resolve func(string) (string, bool)) argvClass {
	if len(argv) == 0 {
		return argvClass{Level: LevelUnclassified, Hard: true, Reason: "empty"}
	}
	if cwd == "" {
		cwd = workspace
	}
	base := baseName(argv[0])
	var c argvClass
	switch base {
	case "git":
		c = classifyGit(argv, cwd, workspace)
	case "gh":
		c = classifyGH(argv, repos)
	default:
		c = classifyOtherBin(argv, cwd, workspace)
	}
	if protectedWrite(argv) {
		c.Level = LevelCritical
		c.Hard = true
		c.Eligible = false
		c.Reason = "path"
	}
	return applyResolve(c, argv, resolve)
}

func applyResolve(c argvClass, argv []string, resolve func(string) (string, bool)) argvClass {
	if c.Level == LevelCritical {
		c.Hard = true
		c.Eligible = false
	}
	if resolve == nil {
		c.Eligible = false
		return c
	}
	if _, ok := resolve(argv[0]); !ok {
		c.Eligible = false
		c.Hard = true
		if c.Reason == "" {
			c.Reason = "binary"
		}
		return c
	}
	if !c.Hard && c.Level != LevelCritical {
		c.Eligible = true
	}
	return c
}

func classifyGit(argv []string, cwd, workspace string) argvClass {
	sub, rest, ok := splitGit(argv)
	if !ok {
		sub = recoverGitSub(argv)
		lvl := LevelUnclassified
		if cmd, known := gitTable()[sub]; known {
			lvl = cmd.level
			if cmd.critical {
				lvl = LevelCritical
			}
		}
		return argvClass{Level: lvl, Hard: true, Reason: "flag"}
	}
	cmd, known := gitTable()[sub]
	if !known {
		c := argvClass{Level: LevelUnclassified, Hard: true, Reason: "command"}
		if workspace != "" && pathsLeave(argv[1:], cwd, workspace) {
			c.Reason = "path"
		}
		return c
	}
	if len(cmd.sub) > 0 && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		if nested, ok := cmd.sub[rest[0]]; ok {
			cmd = nested
			rest = rest[1:]
		}
	}
	hard := cmd.hard || cmd.critical
	reason := ""
	pos, flagsOK := cmd.flags.ok(rest)
	if !flagsOK {
		hard = true
		reason = "flag"
		pos = nil
	}
	if gitUpstream(sub, rest) {
		hard = true
		reason = "flag"
	}
	paths := append([]string{}, gitDashC(argv)...)
	if flagsOK {
		paths = append(paths, pathTokens(pos)...)
	} else {
		paths = append(paths, pathTokens(rest)...)
	}
	if workspace != "" {
		for _, p := range paths {
			if !resolvesInside(p, cwd, workspace) {
				hard = true
				reason = "path"
			}
		}
	}
	lvl := cmd.level
	if cmd.critical {
		lvl = LevelCritical
	}
	return argvClass{Level: lvl, Hard: hard, Reason: reason}
}

func gitUpstream(sub string, rest []string) bool {
	if sub != "fetch" && sub != "ls-remote" {
		return false
	}
	for _, a := range rest {
		if a == "-u" || a == "--upload-pack" || strings.HasPrefix(a, "--upload-pack=") {
			return true
		}
	}
	return false
}

func recoverGitSub(argv []string) string {
	args := argv[1:]
	for len(args) > 0 {
		a := args[0]
		if a == "--" {
			if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
				return args[1]
			}
			return ""
		}
		if !strings.HasPrefix(a, "-") {
			return a
		}
		name, _, has := splitFlag(a)
		if !has && gitValueFlag(name) {
			if len(args) < 2 {
				return ""
			}
			args = args[2:]
			continue
		}
		args = args[1:]
	}
	return ""
}

func gitValueFlag(name string) bool {
	switch name {
	case "-c", "-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix",
		"--config-env", "--exec-path", "--upload-pack", "--config":
		return true
	default:
		return false
	}
}

func classifyGH(argv []string, repos []string) argvClass {
	if ghWeb(argv) {
		return argvClass{Level: ghLevel(argv), Hard: true, Reason: "flag"}
	}
	tail, found, ok := stripRepoFlags(argv[1:])
	if !ok || len(tail) == 0 {
		return argvClass{Level: LevelUnclassified, Hard: true, Reason: "command"}
	}
	if !reposAllowed(found, repos) {
		return argvClass{Level: ghCommandLevel(tail), Hard: true, Reason: "repo"}
	}
	return ghCommand(tail)
}

func ghLevel(argv []string) Level {
	tail, _, ok := stripRepoFlags(argv[1:])
	if !ok || len(tail) == 0 {
		return LevelHigh
	}
	return ghCommandLevel(tail)
}

func ghCommand(tail []string) argvClass {
	name := tail[0]
	rest := tail[1:]
	top, known := ghTable()[name]
	if !known {
		return argvClass{Level: LevelUnclassified, Hard: true, Reason: "command"}
	}
	cmd := top
	if len(top.sub) > 0 {
		if len(rest) == 0 {
			return argvClass{Level: LevelUnclassified, Hard: true, Reason: "command"}
		}
		nested, ok := top.sub[rest[0]]
		if !ok {
			return argvClass{Level: LevelUnclassified, Hard: true, Reason: "command"}
		}
		cmd = nested
		rest = rest[1:]
	}
	hard := cmd.hard || cmd.critical
	reason := ""
	if _, flagsOK := cmd.flags.ok(rest); !flagsOK {
		hard = true
		reason = "flag"
	}
	lvl := cmd.level
	if cmd.critical {
		lvl = LevelCritical
	}
	if lvl == "" {
		lvl = LevelUnclassified
	}
	return argvClass{Level: lvl, Hard: hard, Reason: reason}
}

func ghCommandLevel(tail []string) Level {
	c := ghCommand(tail)
	if c.Level == "" {
		return LevelUnclassified
	}
	return c.Level
}

func stripRepoFlags(args []string) (rest, repos []string, ok bool) {
	for i := 0; i < len(args); i++ {
		name, val, has := splitFlag(args[i])
		if name != "-R" && name != "--repo" {
			rest = append(rest, args[i])
			continue
		}
		if has {
			if val == "" {
				return nil, nil, false
			}
			repos = append(repos, val)
			continue
		}
		if i+1 >= len(args) {
			return nil, nil, false
		}
		i++
		repos = append(repos, args[i])
	}
	return rest, repos, true
}

func reposAllowed(found, configured []string) bool {
	if len(found) == 0 {
		return true
	}
	if len(configured) == 0 {
		return false
	}
	for _, r := range found {
		if !repoListed(r, configured) {
			return false
		}
	}
	return true
}

func repoListed(repo string, configured []string) bool {
	repo = strings.TrimSpace(repo)
	for _, c := range configured {
		if repo == strings.TrimSpace(c) {
			return true
		}
	}
	return false
}

func classifyOtherBin(argv []string, cwd, workspace string) argvClass {
	base := baseName(argv[0])
	if !filterArgv(argv) && !binaryAllowed(base) {
		c := argvClass{Level: LevelUnclassified, Hard: true, Reason: "command"}
		if workspace != "" && pathsLeave(argv[1:], cwd, workspace) {
			c.Reason = "path"
		}
		return c
	}
	if base == "grep" && !grepFlagsOK(argv[1:]) {
		return argvClass{Level: LevelLow, Hard: true, Reason: "flag"}
	}
	if base == "jq" && !jqFlagsOK(argv[1:]) {
		return argvClass{Level: LevelLow, Hard: true, Reason: "flag"}
	}
	if binaryAllowed(base) && !filterArgv(argv) && base != "git" && base != "gh" && base != "grep" && base != "jq" {
		// A producer uses the filter list only when it is a filter.
		// git and gh are handled above. Other allowlisted names that
		// fail filterArgv are not eligible.
		if !isFilter(base) {
			return argvClass{Level: LevelUnclassified, Hard: true, Reason: "command"}
		}
		return argvClass{Level: LevelLow, Hard: true, Reason: "flag"}
	}
	c := argvClass{Level: LevelLow}
	if workspace != "" && pathsLeave(argv[1:], cwd, workspace) {
		c.Hard = true
		c.Reason = "path"
	}
	return c
}

func isFilter(base string) bool {
	switch base {
	case "head", "tail", "wc", "sort", "uniq", "cut", "grep", "jq":
		return true
	default:
		return false
	}
}

func protectedWrite(argv []string) bool {
	if len(argv) == 0 || !mentionsProtected(argv) {
		return false
	}
	if readOnlyArgv(argv) {
		return false
	}
	return true
}

func readOnlyArgv(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	switch baseName(argv[0]) {
	case "git":
		sub, rest, ok := splitGit(argv)
		if !ok {
			sub = recoverGitSub(argv)
		}
		cmd, known := gitTable()[sub]
		if !known {
			return false
		}
		if len(cmd.sub) > 0 && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			if nested, ok := cmd.sub[rest[0]]; ok {
				cmd = nested
			}
		}
		return cmd.read && !cmd.write
	case "gh":
		tail, _, ok := stripRepoFlags(argv[1:])
		if !ok || len(tail) == 0 {
			return false
		}
		top, known := ghTable()[tail[0]]
		if !known {
			return false
		}
		cmd := top
		if len(top.sub) > 0 {
			if len(tail) < 2 {
				return false
			}
			nested, ok := top.sub[tail[1]]
			if !ok {
				return false
			}
			cmd = nested
		}
		return cmd.read && !cmd.write
	case "head", "tail", "wc", "sort", "uniq", "cut", "grep", "jq":
		return true
	default:
		return false
	}
}

func mentionsProtected(argv []string) bool {
	for _, a := range argv {
		if protectedPath(a) {
			return true
		}
	}
	return false
}

func pathsLeave(args []string, cwd, workspace string) bool {
	for _, a := range args {
		if !looksPath(a) {
			continue
		}
		if !resolvesInside(a, cwd, workspace) {
			return true
		}
	}
	return false
}

func resolvesInside(path, cwd, workspace string) bool {
	if path == "" || strings.ContainsRune(path, 0) || workspace == "" {
		return false
	}
	abs := path
	if !filepath.IsAbs(path) {
		base := cwd
		if base == "" {
			base = workspace
		}
		abs = filepath.Join(base, path)
	}
	abs = filepath.Clean(abs)
	if !lexicalInside(abs, workspace) {
		return false
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return lexicalInside(real, workspace)
	}
	parent := filepath.Dir(abs)
	realParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return true
	}
	return lexicalInside(filepath.Join(realParent, filepath.Base(abs)), workspace)
}

func lexicalInside(abs, workspace string) bool {
	ws := filepath.Clean(workspace)
	abs = filepath.Clean(abs)
	if abs == ws {
		return true
	}
	rel, err := filepath.Rel(ws, abs)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func otherBuiltin(tool string, argv []string) Level {
	lvl, known := toolKindLevel(tool)
	if !known {
		return LevelUnclassified
	}
	if writeTool(tool) {
		for _, p := range argv {
			if protectedPath(p) {
				return LevelCritical
			}
		}
	}
	return lvl
}

func toolKindLevel(tool string) (Level, bool) {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "read", "glob", "grep":
		return LevelLow, true
	case "write", "edit", "multiedit", "notebookedit":
		return LevelMedium, true
	case "webfetch", "websearch", "task":
		return LevelHigh, true
	default:
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(tool)), "mcp__") {
			return LevelHigh, true
		}
		return "", false
	}
}

func writeTool(tool string) bool {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "write", "edit", "multiedit", "notebookedit":
		return true
	default:
		return false
	}
}

// pinnedDirs are the only directories a daemon-run shell may resolve
// argv0 from. Each one must be owned by uid 0.
func pinnedDirs() []string {
	candidates := []string{
		"/usr/local/sbin",
		"/usr/local/bin",
		"/usr/sbin",
		"/usr/bin",
		"/sbin",
		"/bin",
	}
	var dirs []string
	for _, dir := range candidates {
		if rootOwnedDir(dir) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

func rootOwnedDir(dir string) bool {
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return false
	}
	return sys.Uid == 0
}

func resolvePinned(argv0 string) (string, bool) {
	if argv0 == "" || strings.ContainsRune(argv0, 0) {
		return "", false
	}
	base := baseName(argv0)
	if !binaryAllowed(base) {
		return "", false
	}
	if filepath.IsAbs(argv0) {
		if filepath.Base(argv0) != base || !rootOwnedDir(filepath.Dir(argv0)) {
			return "", false
		}
		st, err := os.Stat(argv0)
		if err != nil || st.IsDir() {
			return "", false
		}
		return argv0, true
	}
	if strings.ContainsAny(argv0, `/\`) {
		return "", false
	}
	for _, dir := range pinnedDirs() {
		cand := filepath.Join(dir, argv0)
		st, err := os.Stat(cand)
		if err != nil || st.IsDir() {
			continue
		}
		return cand, true
	}
	return "", false
}
