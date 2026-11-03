//go:build unix

package sandbox

import (
	"os"
	"syscall"
)

func openExclusive(path string, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
}

func fileUID(fi os.FileInfo) (uint32, bool) {
	if fi == nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, false
	}
	return st.Uid, true
}
