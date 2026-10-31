package daemon

import (
	"os"
	"path/filepath"
	"strings"
)

// resolveStoredCwd is the real directory of stored, which must be a
// directory inside workspace. rel is relative to that real workspace and
// is empty at the workspace root. On Linux the relative path is opened
// from the workspace directory with openat2 RESOLVE_BENEATH. ENOSYS, and
// every other OS, uses filepath.EvalSymlinks.
func resolveStoredCwd(workspace, stored string) (resolved, rel string, err error) {
	ws := filepath.Clean(workspace)
	if ws == "" || ws == "." {
		return "", "", errShellCwdReset
	}
	cur := filepath.Clean(stored)
	atRoot := cur == "" || cur == "." || cur == ws
	wsReal, err := filepath.EvalSymlinks(ws)
	if err != nil {
		// gateShell runs before shellWorkspace creates the bot directory.
		// A missing root is not a stored subdirectory that escaped.
		if atRoot && os.IsNotExist(err) {
			return ws, "", nil
		}
		return "", "", errShellCwdReset
	}
	wsReal = filepath.Clean(wsReal)
	info, err := os.Stat(wsReal)
	if err != nil || !info.IsDir() {
		return "", "", errShellCwdReset
	}
	if atRoot || cur == wsReal {
		return wsReal, "", nil
	}
	base := ""
	relLexical := ""
	if insideWorkspace(cur, ws) {
		base = ws
		relLexical, err = filepath.Rel(ws, cur)
	} else if insideWorkspace(cur, wsReal) {
		base = wsReal
		relLexical, err = filepath.Rel(wsReal, cur)
	}
	if base == "" || err != nil || !safeShellRel(relLexical) {
		return "", "", errShellCwdReset
	}
	if got, oerr, fallback := openShellDirBeneath(base, relLexical); !fallback {
		if oerr != nil {
			return "", "", errShellCwdReset
		}
		return finishResolvedCwd(wsReal, got)
	}
	return finishResolvedCwd(wsReal, cur)
}

func finishResolvedCwd(wsReal, candidate string) (resolved, rel string, err error) {
	real, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", "", errShellCwdReset
	}
	real = filepath.Clean(real)
	st, err := os.Stat(real)
	if err != nil || !st.IsDir() || !insideWorkspace(real, wsReal) {
		return "", "", errShellCwdReset
	}
	outRel, err := filepath.Rel(wsReal, real)
	if err != nil {
		return "", "", errShellCwdReset
	}
	if outRel == "." {
		return real, "", nil
	}
	if !safeShellRel(outRel) {
		return "", "", errShellCwdReset
	}
	return real, filepath.ToSlash(outRel), nil
}

func safeShellRel(rel string) bool {
	if rel == "" || rel == "." || filepath.IsAbs(rel) || strings.ContainsRune(rel, 0) {
		return false
	}
	sep := string(filepath.Separator)
	if rel == ".." || strings.HasPrefix(rel, ".."+sep) {
		return false
	}
	return filepath.Clean(rel) == rel
}
