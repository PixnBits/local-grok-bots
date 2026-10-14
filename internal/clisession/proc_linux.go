//go:build linux

package clisession

import (
	"os"
	"os/exec"
	"syscall"
)

// prepareProc puts the CLI in its own process group so a later kill reaches
// the CLI and the children it starts. Linux signals that group.
func prepareProc(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killGroup sends SIGKILL to the process group. The leader is signaled again
// so a child that never joined the group still dies.
func killGroup(p *os.Process) {
	if p == nil || p.Pid <= 0 {
		return
	}
	_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
	_ = p.Kill()
}
