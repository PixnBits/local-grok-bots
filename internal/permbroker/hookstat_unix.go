//go:build unix

package permbroker

import (
	"os"
	"syscall"
)

func fileIdentity(info os.FileInfo) (dev, ino uint64, uid uint32, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), st.Uid, true
}

// nlinkOf is the kernel link count. On Unix, Stat_t.Nlink is uint16 or
// uint64 depending on the OS; both convert to uint64.
func nlinkOf(info os.FileInfo) (uint64, bool) {
	if info == nil {
		return 0, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, false
	}
	return uint64(st.Nlink), true
}
