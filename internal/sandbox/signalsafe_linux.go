//go:build linux

package sandbox

import (
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	safeOnce sync.Once
	safeOK   bool
)

func probedSafeSignal() bool {
	safeOnce.Do(func() {
		fd, err := unix.PidfdOpen(os.Getpid(), 0)
		if err != nil {
			safeOK = false
			return
		}
		_ = unix.Close(fd)
		safeOK = true
	})
	return safeOK
}
