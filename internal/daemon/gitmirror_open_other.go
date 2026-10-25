//go:build unix && !linux

package daemon

import "golang.org/x/sys/unix"

// openChain resolves parts from rootFd with a component walk. Each step is
// an O_NOFOLLOW open relative to the previous directory descriptor.
func openChain(rootFd int, parts []string) ([]heldDir, error) {
	return openChainWalk(rootFd, parts)
}

// openChecked opens name under dirfd with O_NONBLOCK and keeps the fd only
// when fstat shows a directory or a regular file, as requested.
func openChecked(dirfd int, name string, allowDir, allowReg bool) (int, unix.Stat_t, error) {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, unix.Stat_t{}, err
	}
	mode := uint32(st.Mode) & uint32(unix.S_IFMT)
	if mode == unix.S_IFLNK {
		unix.Close(fd)
		return -1, st, unix.ELOOP
	}
	if !modeAllowed(mode, allowDir, allowReg) {
		unix.Close(fd)
		return -1, st, errGitType
	}
	return fd, st, nil
}

func platformMountID(int) (uint64, bool) { return 0, false }
