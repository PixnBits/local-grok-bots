//go:build !linux

package sandbox

import "errors"

func openPidfd(pid int) (int, error) {
	return -1, errors.New("pidfd is not available")
}

func closePidfd(fd int) {}

// Trim is a no-op away from Linux, where the jail process tree is not walked.
func (g *ShellGuard) Trim() bool { return false }
