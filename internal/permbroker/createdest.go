package permbroker

import "strings"

// createdDirIndexes marks arguments that name a directory the command
// creates. git clone and git init are the eligible forms. mkdir, install
// -d, and a recursive cp are included so the same class check applies.
func createdDirIndexes(argv []string) map[int]bool {
	out := map[int]bool{}
	if len(argv) == 0 {
		return out
	}
	switch baseName(argv[0]) {
	case "git":
		markGitCreated(argv, out)
	case "mkdir":
		markPlainCreated(argv, mkdirValueFlags, out)
	case "install":
		if installCreatesDir(argv) {
			markPlainCreated(argv, installValueFlags, out)
		}
		markCopyDest(argv, installValueFlags, out)
	case "cp", "mv", "ln", "rsync":
		markCopyDest(argv, shellCopyFlags, out)
	}
	return out
}

func createdDirRefused(spelled, resolved string) bool {
	if clientDirPath(spelled) || clientDirPath(resolved) {
		return true
	}
	return gitSensitivePath(spelled) || gitSensitivePath(resolved)
}

func markGitCreated(argv []string, out map[int]bool) {
	sub, idx, ok := gitSubArgs(argv)
	if !ok {
		return
	}
	switch sub {
	case "clone":
		pos := positionalIdx(argv, idx, cloneValueFlags)
		if len(pos) >= 2 {
			out[pos[len(pos)-1]] = true
		}
	case "init":
		for _, i := range positionalIdx(argv, idx, nil) {
			out[i] = true
		}
	case "worktree":
		pos := positionalIdx(argv, idx, worktreeValueFlags)
		if len(pos) >= 2 && argv[pos[0]] == "add" {
			for _, i := range pos[1:] {
				out[i] = true
			}
		}
	case "mv":
		pos := positionalIdx(argv, idx, flagNameSet("-k"))
		if len(pos) >= 2 {
			out[pos[len(pos)-1]] = true
		}
	}
}

// impliedCloneDest is the directory name git uses when clone has one
// positional argument. The basename is checked as a created directory.
func impliedCloneDest(argv []string) string {
	sub, idx, ok := gitSubArgs(argv)
	if !ok || sub != "clone" {
		return ""
	}
	pos := positionalIdx(argv, idx, cloneValueFlags)
	if len(pos) != 1 {
		return ""
	}
	base := pathBase(argv[pos[0]])
	if base == "" || base == "." || base == ".." || base == "/" {
		return ""
	}
	if strings.HasSuffix(strings.ToLower(base), ".git") && len(base) > len(".git") {
		base = base[:len(base)-len(".git")]
	}
	if base == "" || base == "." || base == ".." {
		return ""
	}
	return base
}

func gitSubArgs(argv []string) (sub string, idx []int, ok bool) {
	if len(argv) == 0 || baseName(argv[0]) != "git" {
		return "", nil, false
	}
	i := 1
	for i < len(argv) {
		a := argv[i]
		if a == "--" {
			i++
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
			i++
			continue
		}
		if _, isVal := gitGlobal.vals[name]; isVal {
			if has {
				i++
				continue
			}
			if i+1 >= len(argv) {
				return "", nil, false
			}
			i += 2
			continue
		}
		return "", nil, false
	}
	if i >= len(argv) {
		return "", nil, false
	}
	sub = argv[i]
	for i = i + 1; i < len(argv); i++ {
		idx = append(idx, i)
	}
	return sub, idx, true
}

func positionalIdx(argv []string, idx []int, valueFlags map[string]bool) []int {
	var pos []int
	for n := 0; n < len(idx); {
		i := idx[n]
		a := argv[i]
		if a == "--" {
			pos = append(pos, idx[n+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			name, _, has := splitFlag(a)
			n++
			if !has && valueFlags[name] && n < len(idx) {
				n++
			}
			continue
		}
		pos = append(pos, i)
		n++
	}
	return pos
}

var cloneValueFlags = flagNameSet(
	"--template", "--reference", "--reference-if-able", "--origin", "--branch",
	"--depth", "--filter", "--server-option", "--jobs", "--config",
	"--upload-pack", "--separate-git-dir", "--bundle-uri",
	"-b", "-o", "-u", "-c", "-j",
)

var worktreeValueFlags = flagNameSet("-b", "-B", "--reason")

var mkdirValueFlags = flagNameSet("-m", "--mode")

var installValueFlags = flagNameSet("-m", "--mode", "-o", "--owner", "-g", "--group", "-t", "--target-directory")

var shellCopyFlags = flagNameSet("-t", "--target-directory", "-S", "--suffix")

func markCopyDest(argv []string, valueFlags map[string]bool, out map[int]bool) {
	if i := lastPlain(argv, valueFlags); i > 0 {
		out[i] = true
	}
	for _, name := range []string{"-t", "--target-directory"} {
		markNamedFlag(argv, name, out)
	}
}

func markNamedFlag(argv []string, flag string, out map[int]bool) {
	for i := 1; i < len(argv); i++ {
		name, _, has := splitFlag(argv[i])
		if name != flag {
			continue
		}
		if has {
			continue
		}
		if i+1 < len(argv) {
			out[i+1] = true
		}
	}
}

func flagNameSet(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

func markPlainCreated(argv []string, valueFlags map[string]bool, out map[int]bool) {
	for _, i := range positionalIdx(argv, indexFrom(argv, 1), valueFlags) {
		out[i] = true
	}
}

func lastPlain(argv []string, valueFlags map[string]bool) int {
	pos := positionalIdx(argv, indexFrom(argv, 1), valueFlags)
	if len(pos) == 0 {
		return 0
	}
	return pos[len(pos)-1]
}

func indexFrom(argv []string, start int) []int {
	var idx []int
	for i := start; i < len(argv); i++ {
		idx = append(idx, i)
	}
	return idx
}

func installCreatesDir(argv []string) bool {
	for _, a := range argv[1:] {
		if a == "-d" || a == "--directory" {
			return true
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsRune(a, 'd') {
			return true
		}
	}
	return false
}

func cpRecursive(argv []string) bool {
	for _, a := range argv[1:] {
		switch a {
		case "-r", "-R", "-a", "--recursive", "--archive":
			return true
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsAny(a, "rRa") {
			return true
		}
	}
	return false
}
