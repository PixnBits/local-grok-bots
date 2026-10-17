package permission

import (
	"path/filepath"
	"strings"
)

func isPathTool(tool string) bool {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "read", "grep", "glob", "ls":
		return true
	default:
		return false
	}
}

func matchValues(req Request, text string) []string {
	if isPathTool(req.Tool) {
		return pathMatchValues(pathMatchArg(req), req.Workspace)
	}
	if strings.TrimSpace(text) == "" {
		return nil
	}
	return []string{text}
}

func pathMatchArg(req Request) string {
	name := strings.ToLower(strings.TrimSpace(req.Tool))
	switch name {
	case "grep", "glob":
		p := firstNonEmptyArg(req.Args, "path", "file_path", "filePath")
		if strings.TrimSpace(p) == "" {
			return "."
		}
		return p
	}
	p := firstNonEmptyArg(req.Args, "file_path", "filePath", "path")
	if p != "" {
		return p
	}
	return argText(req.Args)
}

// pathMatchValues lists equivalent in-workspace forms of p so a stored glob
// such as ./** matches a.txt, ./a.txt, and an absolute path inside the
// workspace. A path that is not inside the workspace is left as the original
// string, so ./** does not match it.
func pathMatchValues(p, workspace string) []string {
	p = strings.Trim(strings.TrimSpace(p), `"'`)
	if p == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	add(p)

	if !filepath.IsAbs(p) && !strings.HasPrefix(p, "~") && !strings.Contains(p, "..") && globPathRefused(p) == "" {
		addRelativeForms(add, p)
	}
	if strings.TrimSpace(workspace) == "" || !withinWorkspace(p, workspace) {
		return out
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
	add(filepath.ToSlash(candidate))
	rel, err := filepath.Rel(ws, candidate)
	if err != nil {
		return out
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return out
	}
	addRelativeForms(add, rel)
	return out
}

func addRelativeForms(add func(string), p string) {
	clean := filepath.ToSlash(filepath.Clean(p))
	clean = strings.TrimPrefix(clean, "./")
	if clean == "." || clean == "" {
		add(".")
		add("./")
		return
	}
	add(clean)
	add("./" + clean)
	add(clean + "/")
	add("./" + clean + "/")
}
