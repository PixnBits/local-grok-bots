//go:build unix

package sandbox

import (
	"os"

	"golang.org/x/sys/unix"
)

// openEventsFile opens the jail event log without following a symlink.
// O_NONBLOCK keeps a replaced FIFO from blocking the daemon. The caller
// accepts only a regular file.
func openEventsFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
