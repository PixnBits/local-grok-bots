//go:build !linux

package sandbox

// Trim is a no-op away from Linux, where the jail process tree is not walked.
func (g *ShellGuard) Trim() bool { return false }
