package permbroker

import (
	"context"
	"path/filepath"
	"strings"
)

// evalSnap is the engine state one evaluate may read without the lock.
// repos nil is preserved: an empty slice is a different answer.
type evalSnap struct {
	table      table
	resolver   func(string) (string, bool)
	classifier Classifier
	ws         string
	repos      []string
	snapSet    bool
	snapWS     string
	snapGit    []byte
	snapGitOK  bool
	snapAttr   []byte
	snapAttrOK bool
	critical   []string
	hook       func(context.Context, Request)
}

func (e *Engine) capture(req Request) evalSnap {
	e.mu.Lock()
	defer e.mu.Unlock()
	extra := make([]RiskEntry, len(e.table.extra))
	for i, row := range e.table.extra {
		row.Argv = append([]string(nil), row.Argv...)
		extra[i] = row
	}
	snap := evalSnap{
		table:      table{extra: extra},
		resolver:   e.resolver,
		classifier: e.classifier,
		snapSet:    e.snapSet,
		snapWS:     e.snapWS,
		snapGit:    append([]byte(nil), e.snapGit...),
		snapGitOK:  e.snapGitOK,
		snapAttr:   append([]byte(nil), e.snapAttr...),
		snapAttrOK: e.snapAttrOK,
		critical:   append([]string(nil), e.critical...),
		hook:       e.inspectHook,
	}
	ws := req.Workspace
	var repos []string
	if b, ok := e.bots[req.BotID]; ok {
		if ws == "" {
			ws = b.Workspace
		}
		if req.Repos == nil {
			repos = b.Repos
		}
	}
	if req.Repos != nil {
		repos = append([]string(nil), req.Repos...)
	}
	if ws == "" {
		ws = req.Cwd
	}
	if repos != nil {
		repos = append([]string(nil), repos...)
	}
	snap.ws = ws
	snap.repos = repos
	return snap
}

func (e *Engine) failClosed(req Request) Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.finish(req, inspected{ClassNote: "none"}, VerdictDeny, "denied", "", "fail-closed", "")
}

func (e *Engine) raiseToCurrent(req Request, in inspected) inspected {
	if isShellTool(req.ToolName) {
		if len(in.Argv) > 0 {
			if lvl := e.table.level(ToolShell, in.Argv); Rank(lvl) > Rank(in.Level) {
				in.Level = lvl
			}
		}
		for _, p := range in.Parts {
			if lvl := e.table.level(ToolShell, p.Argv); Rank(lvl) > Rank(in.Level) {
				in.Level = lvl
			}
		}
	} else if lvl := e.table.level(req.ToolName, toolPaths(req.ToolInput)); Rank(lvl) > Rank(in.Level) {
		in.Level = lvl
	}
	if hitsCritical(req, in, e.critical) {
		in.Level = LevelCritical
	}
	if in.Level == LevelCritical {
		in.Eligible = false
		in.HardAsk = true
	}
	return in
}

func inspectSnap(ctx context.Context, req Request, snap evalSnap) inspected {
	in := inspected{}
	ws, repos := snap.ws, snap.repos
	if isShellTool(req.ToolName) {
		raw, _ := commandOf(req.ToolInput)
		in.Raw = raw
		parsed := ParseCommand(raw)
		in.Compound = parsed.Compound
		in.Argv = append([]string(nil), parsed.Argv...)
		cwd := req.Cwd
		grantable := parsed.Grantable
		if parsed.LeadingCD != "" {
			if !resolvesInside(parsed.LeadingCD, cwd, ws) {
				grantable = false
			} else if cwd != "" {
				cwd = filepath.Join(cwd, parsed.LeadingCD)
			}
		}
		parts := parsed.Parts
		if parsed.LeadingCD != "" && len(parts) > 0 && len(parts[0].Argv) > 0 && baseName(parts[0].Argv[0]) == "cd" {
			parts = parts[1:]
		}
		max := LevelUnclassified
		for _, p := range parts {
			cls := classifyArgv(p.Argv, cwd, ws, repos, snap.resolver)
			lvl := maxLevel(snap.table.level(ToolShell, p.Argv), cls.Level)
			if Rank(lvl) > Rank(max) {
				max = lvl
			}
			p.Hash = hashParts(ToolShell, p.Argv)
			in.Parts = append(in.Parts, p)
			if cls.Hard || !cls.Eligible || lvl == LevelCritical {
				grantable = false
			}
		}
		if parsed.Eligible && len(parsed.Argv) > 0 {
			cls := classifyArgv(parsed.Argv, cwd, ws, repos, snap.resolver)
			in.Level = maxLevel(snap.table.level(ToolShell, parsed.Argv), cls.Level)
			in.Eligible = cls.Eligible && !cls.Hard && in.Level != LevelCritical
			in.HardAsk = !in.Eligible
			in.Hash = hashParts(ToolShell, parsed.Argv)
		} else if len(in.Parts) > 0 {
			if Rank(max) < Rank(LevelMedium) {
				max = LevelMedium
			}
			in.Level = max
			in.Eligible = false
			in.HardAsk = !grantable || in.Level == LevelCritical
			in.Hash = hashRaw(req.ToolName, raw)
		} else {
			in.Eligible = false
			in.HardAsk = true
			in.Level = LevelUnclassified
			if len(parsed.Argv) > 0 {
				cls := classifyArgv(parsed.Argv, cwd, ws, repos, snap.resolver)
				in.Level = maxLevel(snap.table.level(ToolShell, parsed.Argv), cls.Level)
			}
			in.Hash = hashRaw(req.ToolName, raw)
		}
		if in.Level == LevelCritical {
			in.Eligible = false
			in.HardAsk = true
		}
		if gitDriftSnap(snap, req, ws, parsed) {
			in.Eligible = false
			in.HardAsk = true
		}
	} else {
		canon, ok := canonicalJSON(req.ToolInput)
		if !ok {
			canon = string(req.ToolInput)
		}
		in.Raw = canon
		in.Hash = hashRaw(req.ToolName, canon)
		paths := toolPaths(req.ToolInput)
		in.Level = maxLevel(snap.table.level(req.ToolName, paths), otherBuiltin(req.ToolName, paths))
		in.Eligible = false
		in.HardAsk = false
		for _, p := range paths {
			if ws != "" && !resolvesInside(p, req.Cwd, ws) {
				if Rank(in.Level) < Rank(LevelHigh) {
					in.Level = LevelHigh
				}
				in.HardAsk = true
			}
		}
		if in.Level == LevelCritical {
			in.HardAsk = true
		}
	}
	if ctx.Err() != nil {
		return in
	}
	classifier := snap.classifier
	if classifier == nil {
		classifier = NopClassifier{}
	}
	raised, why := classifier.Escalate(ctx, ClassInput{
		Tool: req.ToolName, Argv: in.Argv, Raw: in.Raw, Cwd: req.Cwd,
		Eligible: in.Eligible, Compound: in.Compound, Level: in.Level,
	})
	if Rank(raised) > Rank(in.Level) {
		in.Level = raised
		if why == "" {
			why = "escalated"
		}
		in.ClassNote = why
	}
	if in.ClassNote == "" {
		in.ClassNote = "none"
	}
	if hitsCritical(req, in, snap.critical) {
		in.Level = LevelCritical
	}
	if in.Level == LevelCritical {
		in.Eligible = false
		in.HardAsk = true
	}
	return in
}

func gitDriftSnap(snap evalSnap, req Request, ws string, parsed Parse) bool {
	if !snap.snapSet || !claudeBash(req.ToolName) || !commandUsesGit(parsed) {
		return false
	}
	if ws == "" {
		return true
	}
	gitData, gitOK := readGitBaseline(ws)
	if baselineDrift(snap.snapGit, snap.snapGitOK, gitData, gitOK) {
		return true
	}
	attr, attrOK := readBaselineFile(filepath.Join(ws, ".gitattributes"))
	if baselineDrift(snap.snapAttr, snap.snapAttrOK, attr, attrOK) {
		return true
	}
	return subdirGit(req.Cwd, ws)
}

func hitsCritical(req Request, in inspected, crit []string) bool {
	crit = normalizeCritical(crit)
	if len(crit) == 0 {
		return false
	}
	cwd := ""
	if filepath.IsAbs(req.Cwd) {
		cwd = filepath.Clean(req.Cwd)
	}
	texts := []string{in.Raw, req.Cwd, req.Workspace}
	texts = append(texts, in.Argv...)
	texts = append(texts, toolPaths(req.ToolInput)...)
	for _, text := range texts {
		if pathTouches(text, cwd, crit) {
			return true
		}
	}
	return false
}

// BrokerCriticalPaths is the set the daemon marks critical: the hook
// binary, DATA_DIR/permbroker, the settings file, and its directory.
func BrokerCriticalPaths(dataDir, hook, settings, settingsDir string) []string {
	dir := ""
	if strings.TrimSpace(dataDir) != "" {
		dir = filepath.Join(dataDir, "permbroker")
	}
	return mergeCritical(nil, []string{hook, dir, settings, settingsDir})
}

func normalizeCritical(in []string) []string {
	return mergeCritical(nil, in)
}

func mergeCritical(base, add []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range append(append([]string{}, base...), add...) {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		p = filepath.Clean(p)
		if p == "" || p == "." || p == "/" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// pathTouches reports whether text names a critical path.
// An absolute path is compared directly. A relative path-like token is
// joined to cwd when cwd is absolute. A bare word is left relative so it
// is not treated as a path. Text that contains an absolute critical path,
// such as a flag value, still matches.
func pathTouches(text, cwd string, crit []string) bool {
	text = strings.TrimSpace(text)
	if text == "" {
		return false
	}
	probe := text
	switch {
	case filepath.IsAbs(text):
		probe = filepath.Clean(text)
	case looksPath(text) && !strings.ContainsAny(text, " \t\n\r") && filepath.IsAbs(cwd):
		probe = filepath.Clean(filepath.Join(cwd, text))
	}
	for _, c := range crit {
		if c == "" || c == "/" || c == "." {
			continue
		}
		if probe == c || underRoot(probe, c) || mentionsPath(text, c) {
			return true
		}
	}
	return false
}

func mentionsPath(text, path string) bool {
	if path == "" || path == "/" || path == "." {
		return false
	}
	rest := text
	for {
		i := strings.Index(rest, path)
		if i < 0 {
			return false
		}
		end := i + len(path)
		before := i == 0 || isPathBoundary(rest[i-1])
		after := end == len(rest) || isPathBoundary(rest[end]) || rest[end] == '/'
		if before && after {
			return true
		}
		rest = rest[i+1:]
	}
}

func isPathBoundary(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '"', '\'', '=', ';', '|', '&', '<', '>', '(', ')':
		return true
	default:
		return false
	}
}
