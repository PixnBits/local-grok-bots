//go:build darwin

package clisession

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// markerRequired is false: another process's environment is not readable
// here. Start time and process group are the check. The marker is still
// set on the child and stored.
const markerRequired = false

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

// Identify reads the live process after spawn. Start time comes from
// `ps -o lstart` under LC_ALL=C (the same string boot reads back).
// The executable is the path the daemon launched when `ps` still shows
// that path; otherwise it is the full command line, compared exactly later.
func Identify(pid int, marker, launchedExe string) (StoredCLI, error) {
	if !validMarker(marker) {
		return StoredCLI{}, fmt.Errorf("cli marker is empty")
	}
	live, ok := inspectCLI(pid, marker)
	if !ok {
		return StoredCLI{}, fmt.Errorf("cli pid %d is not the process this daemon just started", pid)
	}
	if refuseOwn(live.PID, live.PGID) {
		return StoredCLI{}, fmt.Errorf("cli pid %d is in this daemon's process group", pid)
	}
	exe := live.Exe
	if launchedExe != "" && commandMatchesExe(live.Exe, launchedExe) {
		exe = launchedExe
	}
	return StoredCLI{PID: live.PID, PGID: live.PGID, Start: live.Start, Exe: exe, Marker: marker}, nil
}

func inspectCLI(pid int, marker string) (liveCLI, bool) {
	_ = marker
	if pid <= 1 {
		return liveCLI{}, false
	}
	pgid, err := syscall.Getpgid(pid)
	if err != nil || pgid <= 1 {
		return liveCLI{}, false
	}
	start, err := psField(pid, "lstart")
	if err != nil {
		return liveCLI{}, false
	}
	command, err := psField(pid, "command")
	if err != nil {
		return liveCLI{}, false
	}
	return liveCLI{PID: pid, PGID: pgid, Start: start, Exe: command}, true
}

// psField reads one `ps -o` column. LC_ALL=C keeps lstart in one English form
// so the stored string matches the string read on the next boot.
func psField(pid int, field string) (string, error) {
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", field+"=")
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(out))
	if s == "" || s == "-" {
		return "", fmt.Errorf("ps %s empty", field)
	}
	return s, nil
}
