//go:build linux

package daemon

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// shrinkStdinPipe makes the fake CLI's stdin pipe small enough that one
// control response blocks in Write. The returned size is the pipe capacity.
func shrinkStdinPipe() int {
	sz, err := unix.FcntlInt(os.Stdin.Fd(), unix.F_SETPIPE_SZ, 4096)
	if err != nil || sz <= 0 || sz > 8192 {
		fmt.Fprintf(os.Stderr, "fake claude pipe size %d: %v\n", sz, err)
		os.Exit(1)
	}
	return sz
}
