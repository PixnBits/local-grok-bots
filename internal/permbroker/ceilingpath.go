package permbroker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// clientConfigPath is true for a write or read target that a client may
// treat as config that runs commands. Segment compares are case-folded.
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
		switch {
		case strings.EqualFold(s, ".grok"), strings.EqualFold(s, ".claude"), strings.EqualFold(s, ".devcontainer"):
			return true
		case strings.EqualFold(s, ".vscode"):
			if i+1 >= len(segs) {
				continue
			}
			switch {
			case strings.EqualFold(segs[i+1], "tasks.json"), strings.EqualFold(segs[i+1], "settings.json"), strings.EqualFold(segs[i+1], "launch.json"):
				return true
			}
		case strings.EqualFold(s, ".idea"):
			if i+1 >= len(segs) {
				continue
			}
			if strings.EqualFold(segs[i+1], "runConfigurations") || strings.EqualFold(segs[i+1], "workspace.xml") {
				return true
			}
		case strings.EqualFold(s, ".envrc"), strings.EqualFold(s, ".env"):
			return true
		}
		if hasPrefixFold(s, ".env.") || hasPrefixFold(s, ".envrc.") {
			return true
		}
	}
	return false
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
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

// gitdirSignal is a path that can plant a git directory, whether or not
// the directory already contains HEAD, objects, or refs. Names are case-folded.
func gitdirSignal(tok string) bool {
	t := strings.ReplaceAll(strings.TrimSpace(tok), `\`, "/")
	if t == "" {
		return false
	}
	segs := strings.Split(t, "/")
	for _, s := range segs {
		switch strings.ToLower(s) {
		case "objects", "refs", "hooks", "modules":
			return true
		}
	}
	switch strings.ToLower(segs[len(segs)-1]) {
	case "head", "config", "packed-refs", "commondir", "config.worktree", "gitdir", "attributes":
		return true
	default:
		return false
	}
}

func gitSensitivePath(tok string) bool {
	if gitPathComponent(tok) {
		return true
	}
	return gitdirSignal(tok)
}

func hookPathToken(tok string) bool {
	t := strings.ReplaceAll(tok, `\`, "/")
	return strings.Contains(t, ".git/hooks/") || strings.HasSuffix(t, ".git/hooks")
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

func ceilingProtected(tok string) bool {
	if protectedPath(tok) {
		return true
	}
	folded := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(tok), `\`, "/"))
	if folded == "" || folded == tok {
		return false
	}
	return protectedPath(folded)
}

// ceilingClass is the sensitive-path result for one spelled string and
// its resolved target. outside is true when either side leaves the workspace.
type ceilingClass struct {
	outside   bool
	protected bool
	critical  bool
	policy    bool
	git       bool
	client    bool
}

func ceilingClassify(spelled, resolved, spelledAbs, ws, realWS string, critical, policy []string, write bool) ceilingClass {
	var c ceilingClass
	if !ceilingInside(spelledAbs, resolved, ws, realWS) {
		c.outside = true
	}
	if ceilingProtected(spelled) || ceilingProtected(resolved) {
		c.protected = true
	}
	if write && (ceilingOnList(spelledAbs, critical) || ceilingOnList(resolved, critical) || ceilingOnList(spelled, critical)) {
		c.critical = true
	}
	if ceilingOnList(spelledAbs, policy) || ceilingOnList(resolved, policy) || ceilingOnList(spelled, policy) {
		c.policy = true
	}
	if gitSensitivePath(spelled) || gitSensitivePath(resolved) {
		c.git = true
	}
	if clientConfigPath(spelled) || clientConfigPath(resolved) {
		c.client = true
	}
	return c
}

func ceilingInside(spelledAbs, resolved, ws, realWS string) bool {
	if strings.TrimSpace(resolved) == "" || strings.TrimSpace(ws) == "" {
		return false
	}
	if !ceilingUnder(resolved, ws, realWS) {
		return false
	}
	if spelledAbs != "" && filepath.IsAbs(spelledAbs) && !ceilingUnder(spelledAbs, ws, realWS) {
		return false
	}
	return true
}

func ceilingUnder(path, ws, realWS string) bool {
	if lexicalInside(path, filepath.Clean(ws)) {
		return true
	}
	if realWS != "" && lexicalInside(path, realWS) {
		return true
	}
	return false
}

func ceilingOnList(path string, list []string) bool {
	if strings.TrimSpace(path) == "" || len(list) == 0 {
		return false
	}
	cand := path
	if !filepath.IsAbs(cand) {
		return false
	}
	return pathRelationCritical(filepath.Clean(cand), normalizeCritical(list))
}

func (c ceilingClass) refused(hook bool) bool {
	if c.outside || c.policy || c.client {
		return true
	}
	if hook {
		return false
	}
	return c.protected || c.critical || c.git
}

// ceilingPathsRefuse is the only ceiling path decision. A walk error, a
// glob escape, a git -C or --git-dir, a git cwd other than the workspace
// root, or a sensitive class on the spelled path or the resolved target
// refuses auto-approval.
func (e *Engine) ceilingPathsRefuse(req Request, in inspected) bool {
	if e == nil {
		return true
	}
	ws := req.Workspace
	if strings.TrimSpace(ws) == "" {
		ws = req.Cwd
	}
	cwd := req.Cwd
	if strings.TrimSpace(cwd) == "" {
		cwd = ws
	}
	if normTool(req.ToolName) == "glob" {
		if pat, ok := globPatternRaw(req.ToolInput); ok && globPatternRefused(pat) {
			return true
		}
	}
	lists := shellArgvLists(in)
	if ceilingGitPlaceRefused(lists, cwd, ws) {
		return true
	}
	cands := ceilingCandidates(req, in, lists)
	if !isShellTool(req.ToolName) {
		if _, ok := ceilingToolRuleFor(req.ToolName); ok && len(toolPaths(req.ToolInput)) == 0 {
			return true
		}
	}
	realWS := ""
	if strings.TrimSpace(ws) != "" && filepath.IsAbs(ws) {
		if got, err := resolvePath(ws); err == nil {
			realWS = got
		}
	}
	for _, c := range cands {
		if ceilingCandRefused(e, c, cwd, ws, realWS) {
			return true
		}
	}
	for _, word := range redirectTargets(in.Raw) {
		c := ceilingCand{spelled: word, write: true, argv: nil}
		if ceilingCandRefused(e, c, cwd, ws, realWS) {
			return true
		}
	}
	return false
}

type ceilingCand struct {
	spelled string
	write   bool
	argv    []string
}

func ceilingCandRefused(e *Engine, c ceilingCand, cwd, ws, realWS string) bool {
	spelled := strings.TrimSpace(c.spelled)
	if spelled == "" || strings.ContainsRune(spelled, 0) {
		return true
	}
	resolved, err := ceilingResolveSpelled(spelled, cwd, ws)
	if err != nil {
		return true
	}
	spelledAbs := lexicalAbs(spelled, cwd, ws)
	hook := c.write && len(c.argv) > 0 && baseName(c.argv[0]) == "git" &&
		hookPathToken(spelled) && hookPathToken(resolved)
	class := ceilingClassify(spelled, resolved, spelledAbs, ws, realWS, e.critical, e.policyPaths, c.write)
	return class.refused(hook)
}

func ceilingResolveSpelled(spelled, cwd, ws string) (string, error) {
	if filepath.IsAbs(spelled) {
		return resolvePath(spelled)
	}
	base := cwd
	if strings.TrimSpace(base) == "" {
		base = ws
	}
	if strings.TrimSpace(base) == "" || !filepath.IsAbs(base) {
		return "", errPathUnresolved
	}
	return resolveFrom(base, spelled)
}

func lexicalAbs(spelled, cwd, ws string) string {
	if filepath.IsAbs(spelled) {
		return filepath.Clean(spelled)
	}
	base := cwd
	if strings.TrimSpace(base) == "" {
		base = ws
	}
	if strings.TrimSpace(base) == "" {
		return ""
	}
	return filepath.Clean(filepath.Join(base, spelled))
}

func ceilingCandidates(req Request, in inspected, lists [][]string) []ceilingCand {
	var out []ceilingCand
	if isShellTool(req.ToolName) {
		for _, argv := range lists {
			if len(argv) == 0 {
				continue
			}
			write := !readOnlyArgv(argv)
			for i, a := range argv {
				if i == 0 || strings.TrimSpace(a) == "" {
					continue
				}
				if strings.HasPrefix(a, "-") && a != "-" && !looksPath(a) {
					continue
				}
				if !write && !looksPath(a) {
					continue
				}
				out = append(out, ceilingCand{spelled: a, write: write, argv: argv})
			}
		}
		return out
	}
	write := false
	if rule, ok := ceilingToolRuleFor(req.ToolName); ok {
		write = rule.write
	} else {
		write = writeTool(req.ToolName)
	}
	for _, p := range toolPaths(req.ToolInput) {
		out = append(out, ceilingCand{spelled: p, write: write})
	}
	return out
}

func shellArgvLists(in inspected) [][]string {
	var lists [][]string
	if len(in.Argv) > 0 {
		lists = append(lists, in.Argv)
	}
	for _, p := range in.Parts {
		if len(p.Argv) > 0 {
			lists = append(lists, p.Argv)
		}
	}
	if len(lists) == 0 {
		if fields := strings.Fields(in.Raw); len(fields) > 0 {
			lists = append(lists, fields)
		}
	}
	return lists
}

// ceilingGitPlaceRefused refuses git -C, --git-dir, and git whose cwd is
// not the workspace root. The same spelling is the same root even when the
// directory is absent. A symlink cwd is accepted only when it resolves to
// that root.
func ceilingGitPlaceRefused(lists [][]string, cwd, ws string) bool {
	saw := false
	for _, argv := range lists {
		if len(argv) == 0 || baseName(argv[0]) != "git" {
			continue
		}
		saw = true
		if gitInvocationBlocked(argv) {
			return true
		}
	}
	if !saw {
		return false
	}
	if strings.TrimSpace(ws) == "" {
		ws = cwd
	}
	if strings.TrimSpace(cwd) == "" || strings.TrimSpace(ws) == "" {
		return true
	}
	if filepath.Clean(cwd) == filepath.Clean(ws) {
		return false
	}
	if !filepath.IsAbs(cwd) || !filepath.IsAbs(ws) {
		return true
	}
	rc, errC := resolvePath(cwd)
	rw, errW := resolvePath(ws)
	if errC != nil || errW != nil {
		return true
	}
	return filepath.Clean(rc) != filepath.Clean(rw)
}

func gitInvocationBlocked(argv []string) bool {
	args := argv[1:]
	for _, a := range args {
		if a == "--" {
			break
		}
		name, _, _ := splitFlag(a)
		if name == "-C" || name == "--git-dir" {
			return true
		}
	}
	return false
}

func globPatternRaw(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "", false
	}
	s, ok := obj["pattern"].(string)
	s = strings.TrimSpace(s)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// globPatternRefused is true for a Glob pattern that can reach outside the
// workspace if the tool expands it. The pattern is not resolved.
func globPatternRefused(pattern string) bool {
	s := strings.TrimSpace(pattern)
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "~") {
		return true
	}
	if strings.Contains(s, "..") || strings.Contains(s, "{") {
		return true
	}
	if filepath.IsAbs(s) || strings.HasPrefix(s, "/") || strings.HasPrefix(s, `\`) {
		return true
	}
	if len(s) >= 2 && s[1] == ':' {
		c := s[0]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			return true
		}
	}
	return false
}

func redirectTargets(src string) []string {
	src = strings.TrimSpace(src)
	if src == "" || badShellSource(src) {
		return nil
	}
	f, err := parseLang(src, syntax.LangBash)
	if err != nil || f == nil {
		return nil
	}
	var out []string
	syntax.Walk(f, func(n syntax.Node) bool {
		r, ok := n.(*syntax.Redirect)
		if !ok || r == nil || r.Word == nil {
			return true
		}
		switch r.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.ClbOut, syntax.RdrInOut, syntax.RdrIn:
		default:
			return true
		}
		word, ok := literalWord(r.Word)
		if !ok {
			out = append(out, "\x00")
			return true
		}
		word = strings.TrimSpace(word)
		if word == "" || word == "/dev/null" {
			return true
		}
		out = append(out, word)
		return true
	})
	return out
}
