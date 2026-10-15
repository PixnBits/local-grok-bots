package clisession

import (
	"path/filepath"
	"strings"
)

// SessionMarkerEnv is set on the CLI child only. Boot compares it to the
// value stored with the pid. It is not inherited from the daemon.
const SessionMarkerEnv = "LGB_SESSION_MARKER"

// StoredCLI is the identity captured at spawn. A later boot may signal
// that process only when the live process still matches.
type StoredCLI struct {
	PID    int
	PGID   int
	Start  string
	Exe    string
	Marker string
}

// liveCLI is what the OS reports for a pid right now.
type liveCLI struct {
	PID      int
	PGID     int
	Start    string
	Exe      string
	MarkerOK bool
}

// validMarker is the run id placed in the child environment.
// It is one token so it cannot smuggle a second variable.
func validMarker(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// maySignal is the only decision that allows a boot-time kill.
// The command name is not an input: a substring such as "claude" is not identity.
// requireMarker is true where the OS can read the child environment.
func maySignal(selfPID, selfPGID int, stored StoredCLI, live liveCLI, requireMarker bool) bool {
	if stored.PID <= 1 || stored.PGID <= 1 || stored.Start == "" || stored.Exe == "" {
		return false
	}
	// The group signal uses -pid, so the child must still be that group's leader.
	if stored.PGID != stored.PID {
		return false
	}
	if stored.PID == selfPID || stored.PGID == selfPGID || live.PID == selfPID || live.PGID == selfPGID {
		return false
	}
	if live.PID != stored.PID || live.PGID != stored.PGID || live.Start != stored.Start || !exeMatches(stored.Exe, live.Exe) {
		return false
	}
	if requireMarker && (stored.Marker == "" || !live.MarkerOK) {
		return false
	}
	return true
}

// exeMatches accepts the same path, or a live command line that begins with
// an absolute stored path. A bare name such as "claude" does not match a
// longer command.
func exeMatches(stored, live string) bool {
	if stored == "" || live == "" {
		return false
	}
	if stored == live {
		return true
	}
	if !filepath.IsAbs(stored) {
		return false
	}
	return commandMatchesExe(live, stored)
}

func commandMatchesExe(command, exe string) bool {
	command = strings.TrimSpace(command)
	if command == exe {
		return true
	}
	return strings.HasPrefix(command, exe+" ") || strings.HasPrefix(command, exe+"\t")
}
