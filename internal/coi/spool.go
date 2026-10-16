package coi

import (
	"os"
	"path/filepath"
	"strings"
)

// DirIdentity is the device and inode of a directory.
func DirIdentity(path string) (uint64, uint64, error) {
	st, err := os.Stat(path)
	if err != nil || !st.IsDir() {
		return 0, 0, ErrSandboxUnavailable
	}
	return dirIdentity(path)
}

// spoolMounts is the host path of the run spool directory, after symlink
// resolution, when it is still the directory dev/ino names and it sits inside
// the workspace. An empty spool hides nothing. dev and ino of zero skip the
// caller check and still require the path to be one directory.
func spoolMounts(workspace, spool string, dev, ino uint64) ([]string, error) {
	spool = filepath.Clean(strings.TrimSpace(spool))
	if spool == "" || spool == "." {
		return nil, nil
	}
	if !filepath.IsAbs(spool) {
		return nil, ErrSandboxUnavailable
	}
	ws := filepath.Clean(workspace)
	if !filepath.IsAbs(ws) {
		return nil, ErrSandboxUnavailable
	}
	wsReal, err := filepath.EvalSymlinks(ws)
	if err != nil {
		return nil, ErrSandboxUnavailable
	}
	wsReal = filepath.Clean(wsReal)
	resolved, err := filepath.EvalSymlinks(spool)
	if err != nil {
		return nil, ErrSandboxUnavailable
	}
	resolved = filepath.Clean(resolved)
	if resolved == wsReal || resolved == string(filepath.Separator) {
		return nil, ErrSandboxUnavailable
	}
	gotDev, gotIno, err := DirIdentity(resolved)
	if err != nil {
		return nil, ErrSandboxUnavailable
	}
	cfgDev, cfgIno, err := DirIdentity(spool)
	if err != nil || cfgDev != gotDev || cfgIno != gotIno {
		return nil, ErrSandboxUnavailable
	}
	if (dev != 0 || ino != 0) && (dev != gotDev || ino != gotIno) {
		return nil, ErrSandboxUnavailable
	}
	if !hasPathPrefix(wsReal, resolved) {
		return nil, ErrSandboxUnavailable
	}
	out := []string{resolved}
	if spool != resolved && spool != ws && hasPathPrefix(ws, spool) {
		out = append(out, spool)
	}
	return out, nil
}
