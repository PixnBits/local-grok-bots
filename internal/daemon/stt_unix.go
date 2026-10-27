//go:build unix

package daemon

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func configureWhisperProc(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return killWhisperGroupOS(cmd.Process.Pid)
	}
}

func killWhisperGroupOS(pid int) error {
	if pid <= 1 {
		return nil
	}
	err := syscall.Kill(-pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}
