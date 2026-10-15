//go:build linux

package clisession

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// markerRequired is true because /proc/<pid>/environ is readable for a
// process this user started.
const markerRequired = true

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

// Identify reads the live process after spawn. launchedExe is unused on
// Linux: the executable is read from /proc/<pid>/exe. The marker must
// already be in the process environment.
func Identify(pid int, marker, launchedExe string) (StoredCLI, error) {
	_ = launchedExe
	if !validMarker(marker) {
		return StoredCLI{}, fmt.Errorf("cli marker is empty")
	}
	live, ok := inspectCLI(pid, marker)
	if !ok || !live.MarkerOK {
		return StoredCLI{}, fmt.Errorf("cli pid %d is not the process this daemon just started", pid)
	}
	if refuseOwn(live.PID, live.PGID) {
		return StoredCLI{}, fmt.Errorf("cli pid %d is in this daemon's process group", pid)
	}
	return StoredCLI{PID: live.PID, PGID: live.PGID, Start: live.Start, Exe: live.Exe, Marker: marker}, nil
}

func inspectCLI(pid int, marker string) (liveCLI, bool) {
	if pid <= 1 {
		return liveCLI{}, false
	}
	pgid, start, err := readProcStat(pid)
	if err != nil {
		return liveCLI{}, false
	}
	got, err := syscall.Getpgid(pid)
	if err != nil || got != pgid || got <= 1 {
		return liveCLI{}, false
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || exe == "" {
		return liveCLI{}, false
	}
	return liveCLI{
		PID: pid, PGID: got, Start: start, Exe: exe,
		MarkerOK: environHasMarker(pid, marker),
	}, true
}

func readProcStat(pid int) (pgid int, start string, err error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, "", err
	}
	return parseProcStat(b)
}

// parseProcStat reads pgrp (field 5) and starttime (field 22) from
// /proc/<pid>/stat. comm sits in parentheses and may contain spaces
// and parentheses, so the fields after the last ')' are the stable tail.
func parseProcStat(b []byte) (pgid int, start string, err error) {
	i := bytes.LastIndexByte(b, ')')
	if i < 0 || i+2 >= len(b) {
		return 0, "", fmt.Errorf("proc stat has no comm")
	}
	fields := strings.Fields(string(b[i+1:]))
	// field 3 is index 0, so field 5 is index 2 and field 22 is index 19.
	if len(fields) < 20 {
		return 0, "", fmt.Errorf("proc stat is short")
	}
	pgid, err = strconv.Atoi(fields[2])
	if err != nil || pgid <= 1 {
		return 0, "", fmt.Errorf("proc stat pgrp")
	}
	start = fields[19]
	if start == "" || strings.Trim(start, "0123456789") != "" {
		return 0, "", fmt.Errorf("proc stat starttime")
	}
	return pgid, start, nil
}

func environHasMarker(pid int, marker string) bool {
	if !validMarker(marker) {
		return false
	}
	want := SessionMarkerEnv + "=" + marker
	// Right after exec, /proc/<pid>/environ can read back empty for a few
	// milliseconds. A process that really has no environment stays empty.
	for attempt := 0; attempt < 25; attempt++ {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if err != nil {
			return false
		}
		if len(b) == 0 {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		for _, ent := range bytes.Split(b, []byte{0}) {
			if string(ent) == want {
				return true
			}
		}
		return false
	}
	return false
}
