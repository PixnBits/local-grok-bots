package permbroker

import (
	"os"
	"path/filepath"
	"strings"
)

// ShellCwdAfter is the session directory after command succeeds, starting
// from current. Both paths are inside workspace.
// reject means the command must not run: it would leave the workspace.
// update means a successful run should store next. A cd whose destination
// is missing does not update; the shell fails and the session stays put.
func ShellCwdAfter(workspace, current, command string) (next string, reject, update bool) {
	ws := filepath.Clean(workspace)
	cur := filepath.Clean(current)
	if ws == "" || ws == "." {
		return cur, true, false
	}
	if cur == "" || cur == "." {
		cur = ws
	}
	if !lexicalInside(cur, ws) {
		return ws, true, false
	}
	parsed := ParseCommand(command)
	switch parsed.Reason {
	case "empty", "parse", "unsupported syntax", "shell dialect", "comment":
		return cur, false, false
	}
	if parsed.Compound || len(parsed.Parts) > 0 {
		return cur, false, false
	}
	argv := parsed.Argv
	if len(argv) == 0 || filepath.Base(argv[0]) != "cd" {
		return cur, false, false
	}
	operand, has := cdOperand(argv)
	if !has {
		return ws, false, cur != ws
	}
	if operand == "-" || strings.ContainsRune(operand, 0) || strings.Contains(operand, "~") {
		return cur, true, false
	}
	dest := operand
	if !filepath.IsAbs(operand) {
		dest = filepath.Join(cur, operand)
	}
	dest = filepath.Clean(dest)
	if !lexicalInside(dest, ws) {
		return cur, true, false
	}
	real, exists, inside := resolveDir(ws, dest)
	if !inside {
		return cur, true, false
	}
	if !exists {
		return cur, false, false
	}
	if real == cur {
		return cur, false, false
	}
	return real, false, true
}

// resolveDir reports the real directory at dest.
// inside is false when dest or a parent symlink leaves workspace.
// exists is true only when dest is a directory inside workspace.
func resolveDir(workspace, dest string) (real string, exists, inside bool) {
	dest = filepath.Clean(dest)
	if !lexicalInside(dest, workspace) {
		return dest, false, false
	}
	if resolved, err := filepath.EvalSymlinks(dest); err == nil {
		resolved = filepath.Clean(resolved)
		if !lexicalInside(resolved, workspace) {
			return resolved, false, false
		}
		st, err := os.Stat(resolved)
		if err != nil || !st.IsDir() {
			return resolved, false, true
		}
		return resolved, true, true
	}
	parent := filepath.Dir(dest)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return dest, false, true
	}
	joined := filepath.Clean(filepath.Join(resolvedParent, filepath.Base(dest)))
	if !lexicalInside(joined, workspace) {
		return joined, false, false
	}
	return dest, false, true
}
