//go:build darwin

package clisession

import (
	"os"
	"os/exec"
	"syscall"
)

// prepareProc puts the CLI in its own process group. macOS has the same
// POSIX setpgid as Linux. Seatbelt does not provide a group-kill API.
func prepareProc(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killGroup sends SIGKILL to the process group, the same signal Linux uses.
// If that group signal is rejected, the fallback is SIGKILL of the leader only.
func killGroup(p *os.Process) {
	if p == nil || p.Pid <= 0 {
		return
	}
	if err := syscall.Kill(-p.Pid, syscall.SIGKILL); err != nil {
		_ = p.Kill()
	}
}
