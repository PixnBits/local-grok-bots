package permbroker

import (
	"os"
	"path/filepath"
	"strings"
)

// ceilingCrossDevice asks when a write's resolved path, or the nearest
// existing parent, is on a different device than the workspace root.
// On Linux it also compares mount ids from mountinfo. A same-filesystem
// bind keeps the device id and changes the mount id, so that write asks.
// If mountinfo cannot be read, the write asks. Darwin compares the device
// id only. Without Stat_t the check is skipped.
func ceilingCrossDevice(resolved, ws, realWS string) bool {
	if !deviceCheckActive() {
		return false
	}
	root := strings.TrimSpace(realWS)
	if root == "" {
		root = strings.TrimSpace(ws)
	}
	devAsk := false
	rootDev, okR := pathDevice(root)
	dev, okD := nearestDevice(resolved)
	switch {
	case okR && !okD:
		devAsk = true
	case okR && okD && dev != rootDev:
		devAsk = true
	}
	if devAsk {
		return true
	}
	differ, ok := mountMismatch(resolved, root)
	if !ok || differ {
		return true
	}
	return false
}

func pathDevice(p string) (uint64, bool) {
	if strings.TrimSpace(p) == "" {
		return 0, false
	}
	st, err := os.Lstat(p)
	if err != nil {
		return 0, false
	}
	return deviceOf(st)
}

func nearestDevice(p string) (uint64, bool) {
	cur := strings.TrimSpace(p)
	if cur == "" {
		return 0, false
	}
	for {
		if dev, ok := pathDevice(cur); ok {
			return dev, true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return 0, false
		}
		cur = parent
	}
}
