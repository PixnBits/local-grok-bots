//go:build darwin

package daemon

import (
	"os"
	"syscall"
)

func tokenCtime(fi os.FileInfo) (sec, nsec int64, ok bool) {
	if fi == nil {
		return 0, 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, false
	}
	return int64(st.Ctimespec.Sec), int64(st.Ctimespec.Nsec), true
}
