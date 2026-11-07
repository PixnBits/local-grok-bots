package permbroker

import (
	"os"
	"path/filepath"
	"strings"
)

// clientConfigPath is true for a write target that a client may treat as
// config that runs commands:
//
//	.grok/ (including settings.json)
//	.claude/
//	.vscode/tasks.json, .vscode/settings.json, .vscode/launch.json
//	.idea/runConfigurations/, .idea/workspace.xml
//	.envrc and .env loader files
//	.devcontainer/
func clientConfigPath(tok string) bool {
	t := strings.ReplaceAll(strings.TrimSpace(tok), `\`, "/")
	if t == "" {
		return false
	}
	segs := strings.Split(t, "/")
	for i, s := range segs {
		switch s {
		case ".grok", ".claude", ".devcontainer":
			return true
		case ".vscode":
			if i+1 >= len(segs) {
				continue
			}
			switch segs[i+1] {
			case "tasks.json", "settings.json", "launch.json":
				return true
			}
		case ".idea":
			if i+1 >= len(segs) {
				continue
			}
			if segs[i+1] == "runConfigurations" || segs[i+1] == "workspace.xml" {
				return true
			}
		case ".envrc", ".env":
			return true
		}
		if strings.HasPrefix(s, ".env.") || strings.HasPrefix(s, ".envrc.") {
			return true
		}
	}
	return false
}

func gitPathComponent(tok string) bool {
	t := strings.ReplaceAll(strings.TrimSpace(tok), `\`, "/")
	if t == "" {
		return false
	}
	for _, s := range strings.Split(t, "/") {
		if strings.EqualFold(s, ".git") {
			return true
		}
	}
	return false
}

func gitSensitivePath(tok, cwd, ws string) bool {
	if gitPathComponent(tok) {
		return true
	}
	return gitdirLookalike(tok, cwd, ws)
}

func gitdirLookalike(tok, cwd, ws string) bool {
	abs := absPath(tok, cwd, ws)
	if abs == "" {
		return false
	}
	base := filepath.Base(abs)
	dir := filepath.Dir(abs)
	parent := filepath.Base(dir)
	gitFile := base == "HEAD" || base == "config" || base == "packed-refs" ||
		base == "commondir" || base == "config.worktree" || base == "gitdir"
	underHooks := parent == "hooks"
	slash := filepath.ToSlash(abs)
	underObjects := strings.Contains(slash, "/objects/")
	if !gitFile && !underHooks && !underObjects {
		return false
	}
	check := dir
	if underHooks {
		check = filepath.Dir(dir)
		return dirLooksLikeGit(check)
	}
	if underObjects {
		cur := dir
		for i := 0; i < 4; i++ {
			if dirLooksLikeGit(cur) {
				return true
			}
			next := filepath.Dir(cur)
			if next == cur {
				break
			}
			cur = next
		}
		return false
	}
	return dirLooksLikeGit(check)
}

func dirLooksLikeGit(dir string) bool {
	if dir == "" || dir == "." || dir == string(filepath.Separator) {
		return false
	}
	if _, err := os.Lstat(filepath.Join(dir, "HEAD")); err == nil {
		return true
	}
	if st, err := os.Lstat(filepath.Join(dir, "objects")); err == nil && st.IsDir() {
		return true
	}
	if st, err := os.Lstat(filepath.Join(dir, "refs")); err == nil && st.IsDir() {
		return true
	}
	return false
}

func hookPathToken(tok string) bool {
	t := strings.ReplaceAll(tok, `\`, "/")
	return strings.Contains(t, ".git/hooks/") || strings.HasSuffix(t, ".git/hooks")
}

func ceilingGitSensitiveWrite(req Request, in inspected) bool {
	cwd, ws := req.Cwd, req.Workspace
	if ws == "" {
		ws = cwd
	}
	return ceilingWriteMatch(req, in, func(p string) bool {
		if !gitSensitivePath(p, cwd, ws) {
			return false
		}
		return !hookPathToken(p)
	})
}

func ceilingClientConfigWrite(req Request, in inspected) bool {
	return ceilingWriteMatch(req, in, clientConfigPath)
}

func ceilingWriteMatch(req Request, in inspected, match func(string) bool) bool {
	if isShellTool(req.ToolName) {
		lists := [][]string{in.Argv}
		for _, p := range in.Parts {
			lists = append(lists, p.Argv)
		}
		if len(in.Argv) == 0 && len(in.Parts) == 0 {
			lists = [][]string{strings.Fields(in.Raw)}
		}
		for _, argv := range lists {
			if len(argv) == 0 || readOnlyArgv(argv) {
				continue
			}
			for _, a := range argv {
				if match(a) {
					return true
				}
			}
		}
		return false
	}
	rule, ok := ceilingToolRuleFor(req.ToolName)
	if !ok || !rule.write {
		return false
	}
	for _, p := range toolPaths(req.ToolInput) {
		if match(p) {
			return true
		}
	}
	return false
}

func ceilingPathUnresolved(req Request, in inspected) bool {
	cwd := req.Cwd
	ws := req.Workspace
	if ws == "" {
		ws = cwd
	}
	var paths []string
	paths = append(paths, toolPaths(req.ToolInput)...)
	if glob := globPatternPath(req.ToolInput); glob != "" && normTool(req.ToolName) == "glob" {
		paths = append(paths, glob)
	}
	if isShellTool(req.ToolName) {
		for _, a := range in.Argv {
			if looksPath(a) {
				paths = append(paths, a)
			}
		}
		for _, p := range in.Parts {
			for _, a := range p.Argv {
				if looksPath(a) {
					paths = append(paths, a)
				}
			}
		}
	}
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		abs := absPath(p, cwd, ws)
		if abs == "" {
			continue
		}
		if _, ok := resolvePathTarget(abs); !ok {
			return true
		}
	}
	return false
}
