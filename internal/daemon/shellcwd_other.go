//go:build !linux

package daemon

// openShellDirBeneath has no openat2 here. The caller uses EvalSymlinks.
func openShellDirBeneath(root, rel string) (string, error, bool) {
	return "", nil, true
}
