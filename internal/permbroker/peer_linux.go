//go:build linux

package permbroker

import (
	"os"
	"strconv"
	"strings"
)

// peerStrict reports whether pid is the pinned hook and a descendant of
// the CLI process registered for bot. With no hook identity configured,
// the socket stays on the uid check alone.
func (e *Engine) peerStrict(pid int, bot string) bool {
	ids, root := e.peerExpect(bot)
	if len(ids) == 0 {
		return true
	}
	return peerHookOK(pid, ids) && descendantOf(pid, root)
}

func peerHookOK(pid int, ids []hookID) bool {
	if pid <= 0 {
		return false
	}
	dev, ino, ok := exeIdentity(pid)
	if !ok {
		return false
	}
	for _, id := range ids {
		if id.Dev == dev && id.Ino == ino {
			return true
		}
	}
	return false
}

func exeIdentity(pid int) (dev, ino uint64, ok bool) {
	info, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return 0, 0, false
	}
	dev, ino, _, ok = fileIdentity(info)
	return dev, ino, ok
}

// descendantOf walks parent pids from /proc. The registered process
// itself counts. The walk stops after 64 steps.
func descendantOf(pid, root int) bool {
	if pid <= 0 || root <= 1 {
		return false
	}
	cur := pid
	for i := 0; i < 64; i++ {
		if cur == root {
			return true
		}
		next := ppidOf(cur)
		if next <= 1 || next == cur {
			return false
		}
		cur = next
	}
	return false
}

func ppidOf(pid int) int {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 || i+2 >= len(b) {
		return 0
	}
	fields := strings.Fields(string(b[i+2:]))
	if len(fields) < 2 {
		return 0
	}
	n, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return n
}
