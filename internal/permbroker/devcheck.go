package permbroker

import (
	"os"
	"path/filepath"
	"strings"
)

// ceilingCrossDevice asks when a write's resolved path, or the nearest
// existing parent, is on a different device than the workspace root.
// A same-filesystem bind mount keeps the device id. The same-inode check
// covers that case. Without Stat_t the check is skipped.
func ceilingCrossDevice(resolved, ws, realWS string) bool {
	if !deviceCheckActive() {
		return false
	}
	root := strings.TrimSpace(realWS)
	if root == "" {
		root = strings.TrimSpace(ws)
	}
	rootDev, ok := pathDevice(root)
	if !ok {
		return false
	}
	dev, ok := nearestDevice(resolved)
	if !ok {
		return true
	}
	return dev != rootDev
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
