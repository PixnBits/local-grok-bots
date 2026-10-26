//go:build linux

package sandbox

import (
	"os"

	"golang.org/x/sys/unix"
)

// openEventsFile opens a path without following a final symlink.
// Callers that read the jail log use the directory fd from prepare instead.
// O_NONBLOCK keeps a replaced FIFO from blocking the daemon.
func openEventsFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// openEventsDirectory pins the daemon-created prep/rw/events directory.
// The fd is O_PATH|O_DIRECTORY|O_CLOEXEC and is opened from an fd on prep
// with RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS. It keeps the original
// directory inode if the jail later replaces /lgb/events. It is not passed
// to child processes.
func openEventsDirectory(prep string) (*os.File, error) {
	parent, err := unix.Open(prep, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	how := &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(parent, "rw/events", how)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), "events"), nil
}

// readPreparedEvents opens "log" relative to the directory pinned in prepare.
// A symlink, a missing file, a non-regular file, or any other error is one
// daemon event, events unavailable. The original directory's lines are kept
// when that directory is still readable through the fd.
func readPreparedEvents(p *prepared) []Event {
	if p == nil || p.eventsDir == nil {
		return eventsUnavailable()
	}
	dirfd := int(p.eventsDir.Fd())
	unix.CloseOnExec(dirfd)
	how := &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(dirfd, "log", how)
	if err != nil {
		return eventsUnavailable()
	}
	unix.CloseOnExec(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return eventsUnavailable()
	}
	f := os.NewFile(uintptr(fd), "log")
	defer f.Close()
	return eventsFromFile(f)
}
