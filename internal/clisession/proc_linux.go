//go:build linux

package clisession

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
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

// KillStoredCLI signals a CLI left behind by a crashed daemon.
// It does nothing unless the pid still looks like claude or grok, so a reused
// pid is left alone. Linux reads /proc; the signal is the same process-group kill.
func KillStoredCLI(pid int) {
	if pid <= 1 || pid == os.Getpid() || !looksLikeCLI(pid) {
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil || proc == nil {
		return
	}
	killGroup(proc)
}

func looksLikeCLI(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(b) == 0 {
		return false
	}
	text := strings.ToLower(string(bytes.ReplaceAll(b, []byte{0}, []byte{' '})))
	return strings.Contains(text, "claude") || strings.Contains(text, "grok")
}
