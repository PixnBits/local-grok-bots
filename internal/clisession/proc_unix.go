//go:build linux || darwin

package clisession

import (
	"os"
	"syscall"
)

// refuseOwn reports a pid or process group that belongs to this daemon.
func refuseOwn(pid, pgid int) bool {
	self := os.Getpid()
	if pid == self {
		return true
	}
	selfPG, err := syscall.Getpgid(self)
	return err != nil || pgid == selfPG || pgid <= 1
}

// KillStoredCLI signals one CLI left behind by a crashed daemon.
// It does nothing unless the live process still has the start time and
// process group captured at spawn. On Linux the session marker must also
// still be in the process environment. The command line is not consulted
// for a "claude" or "grok" substring. Our own pid and process group are
// never signaled.
func KillStoredCLI(stored StoredCLI) {
	self := os.Getpid()
	selfPG, err := syscall.Getpgid(self)
	if err != nil || selfPG <= 0 {
		return
	}
	if stored.PID == self || stored.PGID == selfPG {
		return
	}
	live, ok := inspectCLI(stored.PID, stored.Marker)
	if !ok || !maySignal(self, selfPG, stored, live, markerRequired) {
		return
	}
	// Read again so a pid recycled between the two checks is not signaled.
	live, ok = inspectCLI(stored.PID, stored.Marker)
	if !ok || !maySignal(self, selfPG, stored, live, markerRequired) {
		return
	}
	proc, err := os.FindProcess(stored.PID)
	if err != nil || proc == nil {
		return
	}
	killGroup(proc)
}
