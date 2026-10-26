//go:build unix && !linux

package sandbox

import (
	"os"
	"path/filepath"

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

// openEventsDirectory is a no-op outside Linux. The read lstats the path.
func openEventsDirectory(string) (*os.File, error) {
	return nil, nil
}

// readPreparedEvents refuses a symlink at prep/rw/events or at the log,
// and refuses a directory that is not a directory or a log that is not a
// regular file. Any failure is one daemon event, events unavailable.
func readPreparedEvents(p *prepared) []Event {
	if p == nil || p.dir == "" {
		return eventsUnavailable()
	}
	dir := filepath.Join(p.dir, "rw", "events")
	logPath := filepath.Join(dir, "log")
	dst, err := os.Lstat(dir)
	if err != nil || dst.Mode()&os.ModeSymlink != 0 || !dst.IsDir() {
		return eventsUnavailable()
	}
	lst, err := os.Lstat(logPath)
	if err != nil || lst.Mode()&os.ModeSymlink != 0 || !lst.Mode().IsRegular() {
		return eventsUnavailable()
	}
	f, err := openEventsFile(logPath)
	if err != nil {
		return eventsUnavailable()
	}
	defer f.Close()
	return eventsFromFile(f)
}
