package permbroker

import (
	"os"
	"path/filepath"
	"strings"
)

// riskyPathspecLexical is the spelling check. It does not look at the
// workspace. An absolute path asks. Magic, globs, and a clean root or
// parent ask.
func riskyPathspecLexical(p string) bool {
	if p == "" || strings.HasPrefix(p, ":") || strings.ContainsAny(p, "*?[") {
		return true
	}
	if filepath.IsAbs(p) {
		return true
	}
	c := filepath.Clean(p)
	if c == "." || c == ".." || c == string(filepath.Separator) {
		return true
	}
	return strings.HasPrefix(c, ".."+string(filepath.Separator))
}

// riskyPathspec is a pathspec the ceiling must not auto-approve.
// strict asks when a directory cannot be inspected. Callers without a
// workspace still treat absolute pathspecs as risky and do not walk.
func riskyPathspec(p, cwd, ws string, strict bool) bool {
	if riskyPathspecLexical(p) {
		return true
	}
	root := workRoot(cwd, ws)
	if root == "" {
		return false
	}
	abs := lexicalAbs(p, cwd, ws)
	if abs == "" {
		return strict
	}
	abs = filepath.Clean(abs)
	if abs == root || pathIsAncestor(abs, root) || !lexicalInside(abs, root) {
		return true
	}
	st, err := os.Lstat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		return strict
	}
	if st.Mode()&os.ModeSymlink != 0 {
		tgt, ok := linkTarget(abs)
		if !ok || tgt == root || pathIsAncestor(tgt, root) || !lexicalInside(tgt, root) {
			return true
		}
		st, err = os.Lstat(tgt)
		if err != nil {
			return strict
		}
		if !st.IsDir() {
			rel, relErr := filepath.Rel(root, tgt)
			return relErr != nil || pathspecEntrySensitive(rel)
		}
		abs = tgt
	}
	if !st.IsDir() {
		return false
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true
	}
	if pathspecEntrySensitive(rel) {
		return true
	}
	return dirHasSensitive(abs, root, strict)
}

func workRoot(cwd, ws string) string {
	root := strings.TrimSpace(ws)
	if root == "" {
		root = strings.TrimSpace(cwd)
	}
	if root == "" || !filepath.IsAbs(root) {
		return ""
	}
	return filepath.Clean(root)
}

// pathIsAncestor reports whether ancestor contains child and is not child.
func pathIsAncestor(ancestor, child string) bool {
	ancestor = filepath.Clean(ancestor)
	child = filepath.Clean(child)
	if ancestor == child {
		return false
	}
	rel, err := filepath.Rel(ancestor, child)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func linkTarget(path string) (string, bool) {
	tgt, err := os.Readlink(path)
	if err != nil || tgt == "" {
		return "", false
	}
	if !filepath.IsAbs(tgt) {
		tgt = filepath.Join(filepath.Dir(path), tgt)
	}
	return filepath.Clean(tgt), true
}

// dirHasSensitive asks when a directory holds a credential or client-config
// file, or when strict is set and the directory cannot be listed without
// leaving the workspace. Symlinks are not followed. A link that leaves the
// workspace asks.
func dirHasSensitive(dir, root string, strict bool) bool {
	return walkSensitive(dir, root, strict, 0, map[string]bool{})
}

func walkSensitive(dir, root string, strict bool, depth int, seen map[string]bool) bool {
	if depth > 64 {
		return true
	}
	dir = filepath.Clean(dir)
	if seen[dir] {
		return false
	}
	seen[dir] = true
	if dir != root && !lexicalInside(dir, root) {
		return true
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return strict
	}
	for _, ent := range ents {
		path := filepath.Join(dir, ent.Name())
		if !lexicalInside(path, root) {
			return true
		}
		st, err := os.Lstat(path)
		if err != nil {
			return strict
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
		if pathspecEntrySensitive(rel) {
			return true
		}
		if st.Mode()&os.ModeSymlink != 0 {
			tgt, ok := linkTarget(path)
			if !ok || tgt == root || pathIsAncestor(tgt, root) || !lexicalInside(tgt, root) {
				return true
			}
			if relT, rerr := filepath.Rel(root, tgt); rerr != nil || pathspecEntrySensitive(relT) {
				return true
			}
			st, err = os.Lstat(tgt)
			if err != nil {
				return strict
			}
			if st.Mode()&os.ModeSymlink != 0 {
				return true
			}
			if st.IsDir() && walkSensitive(tgt, root, strict, depth+1, seen) {
				return true
			}
			continue
		}
		if st.IsDir() && walkSensitive(path, root, strict, depth+1, seen) {
			return true
		}
	}
	return false
}

// pathspecEntrySensitive is a path under a directory pathspec that the
// ceiling must not stage or list without asking. The credential list and
// the client-config class both count. .mcp.json and .github/workflows
// count with that class.
func pathspecEntrySensitive(rel string) bool {
	rel = filepath.ToSlash(strings.TrimSpace(rel))
	if rel == "" || rel == "." {
		return false
	}
	if pathIsCredential(rel, "", "") || gitSecretReadPath(rel) || clientConfigPath(rel) {
		return true
	}
	base := strings.ToLower(pathBase(rel))
	if base == ".mcp.json" {
		return true
	}
	low := strings.ToLower(rel)
	return low == ".github/workflows" || strings.HasPrefix(low, ".github/workflows/") ||
		strings.HasSuffix(low, "/.github/workflows") || strings.Contains(low, "/.github/workflows/")
}
