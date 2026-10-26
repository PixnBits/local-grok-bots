//go:build !unix

package sandbox

import (
	"os"
	"path/filepath"
)

func openEventsFile(path string) (*os.File, error) {
	return os.Open(path)
}

func openEventsDirectory(string) (*os.File, error) {
	return nil, nil
}

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
