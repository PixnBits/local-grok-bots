//go:build unix && !linux

package sandbox

import (
	"os"

	"golang.org/x/sys/unix"
)

// openEventsFile opens a path without following a final symlink.
func openEventsFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// openEventsDirectory pins prep/rw/events. The fd is
// O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC, opened from the prep directory
// so a later replacement of the path is not what the read uses.
func openEventsDirectory(prep string) (*os.File, error) {
	parent, err := unix.Open(prep, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	rw, err := unix.Openat(parent, "rw", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rw)
	fd, err := unix.Openat(rw, "events", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "events"), nil
}

// readPreparedEvents opens "log" relative to the directory pinned in prepare.
// A symlink, a missing file, a non-regular file, or any other error is one
// daemon event, events unavailable.
func readPreparedEvents(p *prepared) []Event {
	if p == nil || p.eventsDir == nil {
		return eventsUnavailable()
	}
	dirfd := int(p.eventsDir.Fd())
	fd, err := unix.Openat(dirfd, "log", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return eventsUnavailable()
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return eventsUnavailable()
	}
	f := os.NewFile(uintptr(fd), "log")
	defer f.Close()
	return eventsFromFile(f)
}
