//go:build unix

package coi

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killTree(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
	_ = cmd.Process.Kill()
}
