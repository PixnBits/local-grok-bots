//go:build !linux && !darwin

package clisession

import (
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
