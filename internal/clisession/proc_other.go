//go:build !linux && !darwin

package clisession

import (
	"fmt"
	"os"
	"os/exec"
)

// prepareProc is the fallback where POSIX process groups are not used.
// Linux and macOS have their own files.
func prepareProc(cmd *exec.Cmd) {}

// killGroup falls back to the leader. There is no process group to signal.
func killGroup(p *os.Process) {
	if p == nil {
		return
	}
	_ = p.Kill()
}

// Identify cannot read a process start time on this OS, so a stored pid
// is never signaled later.
func Identify(pid int, marker, launchedExe string) (StoredCLI, error) {
	_ = pid
	_ = marker
	_ = launchedExe
	return StoredCLI{}, fmt.Errorf("cli process identity is not available on this OS")
}

// KillStoredCLI has no process group to signal on this OS.
func KillStoredCLI(stored StoredCLI) { _ = stored }
