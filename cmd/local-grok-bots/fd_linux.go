//go:build linux

package main

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// closeInheritedFDs marks every fd at or above 3 close-on-exec so a
// restarted or re-exec'd process does not keep a caller's descriptor.
// Standard streams stay open. CloseRange sets the flag and does not close.
func closeInheritedFDs() {
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err == nil {
		return
	}
	d, err := os.Open("/proc/self/fd")
	if err != nil {
		return
	}
	dirfd := int(d.Fd())
	names, rerr := d.Readdirnames(-1)
	if rerr == nil {
		for _, name := range names {
			n, err := strconv.Atoi(name)
			if err != nil || n < 3 || n == dirfd {
				continue
			}
			unix.CloseOnExec(n)
		}
	}
	_ = d.Close()
}
