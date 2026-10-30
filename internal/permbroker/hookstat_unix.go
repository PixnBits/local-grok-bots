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
