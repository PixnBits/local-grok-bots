//go:build unix

package daemon

import (
	"os"
	"syscall"
)

func tokenFileID(fi os.FileInfo) (dev, ino uint64, uid uint32, ok bool) {
	if fi == nil {
		return 0, 0, 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), st.Uid, true
}
