//go:build !linux

package daemon

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func defaultJobPidfdLive(fd int) bool {
	return false
}

func openJobPidfd(pid int) int { return 0 }

func closeJobPidfd(fd int) {}

// openJobLogAt creates the log from a directory file descriptor and does not
// follow symlinks. A new directory is mode 0700. An existing directory is
// only narrowed.
func openJobLogAt(root, id string) (*os.File, error) {
	rootfd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootfd)
	lgb, err := ensureJobDir(rootfd, ".lgb")
	if err != nil {
		return nil, err
	}
	defer unix.Close(lgb)
	jobs, err := ensureJobDir(lgb, "jobs")
	if err != nil {
		return nil, err
	}
	defer unix.Close(jobs)
	fd, err := unix.Openat(jobs, id+".log", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o640)
	if err != nil {
		return nil, err
	}
	if err := unix.Fchmod(fd, 0o640); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), id+".log"), nil
}

func ensureJobDir(parent int, name string) (int, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		return narrowJobDir(fd)
	}
	if !errors.Is(err, unix.ENOENT) {
		return -1, err
	}
	if err := unix.Mkdirat(parent, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, err
	}
	fd, err = unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	return narrowJobDir(fd)
}

func narrowJobDir(fd int) (int, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(fd)
		return -1, unix.ENOTDIR
	}
	mode := os.FileMode(st.Mode) & os.ModePerm
	if mode&^0o700 != 0 {
		if err := unix.Fchmod(fd, uint32(mode&0o700)); err != nil {
			unix.Close(fd)
			return -1, err
		}
	}
	return fd, nil
}
