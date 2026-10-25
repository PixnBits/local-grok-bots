package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Chown sets the numeric owner of path. Production skips the host call when
// the daemon is not root, because that call is rejected. Tests replace this.
// OwnPath does not call it at all unless EUID is 0.
var Chown = defaultChown

// EUID is the daemon's effective uid. Tests replace it.
var EUID = os.Geteuid

// LookPath resolves a host binary. Tests replace it.
var LookPath = exec.LookPath

func defaultChown(path string, uid, gid int) error {
	if EUID() != 0 {
		return nil
	}
	return os.Chown(path, uid, gid)
}

// JailIDs is the uid and gid that must own the bot workspace.
// A non-root daemon is that user. A root daemon that has bubblewrap uses the
// kernel overflow ids, and the jail command drops to those ids. Without
// bubblewrap the shell is refused, and these ids stay 0 so the workspace
// stays owned by root.
func JailIDs() (uid, gid int) {
	if id := EUID(); id != 0 {
		return id, os.Getegid()
	}
	if _, err := LookPath("bwrap"); err != nil {
		return 0, 0
	}
	return readOverflow("/proc/sys/kernel/overflowuid", 65534), readOverflow("/proc/sys/kernel/overflowgid", 65534)
}

// RootJailWarning is set when a root daemon has no bubblewrap. The shell
// sandbox refuses to run in that case. An empty string means the jail may start.
func RootJailWarning() string {
	if EUID() != 0 {
		return ""
	}
	if _, err := LookPath("bwrap"); err == nil {
		return ""
	}
	return "root requires bwrap; the shell sandbox and git and github grants are refused"
}

func readOverflow(path string, fallback int) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

// OwnPath sets mode and then the jail owner. mode 0 leaves the mode alone.
// A world-writable mode is refused.
func OwnPath(path string, mode os.FileMode) error {
	if mode&0o002 != 0 {
		return errors.New("mode")
	}
	if mode != 0 {
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
	}
	// A non-root daemon already owns the directories it creates. Chown would
	// be rejected, so it is not called. Modes stay 0750 or 0700.
	if EUID() != 0 {
		return nil
	}
	uid, gid := JailIDs()
	return Chown(path, uid, gid)
}
