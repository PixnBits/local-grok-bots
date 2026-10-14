//go:build darwin

package clisession

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
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

// KillStoredCLI signals a CLI left behind by a crashed daemon.
// It does nothing unless ps still shows claude or grok, so a reused pid is
// left alone. The signal is the same process-group kill as Linux, including
// the leader fallback when the group signal is rejected.
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
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil {
		return false
	}
	text := strings.ToLower(string(out))
	return strings.Contains(text, "claude") || strings.Contains(text, "grok")
}
