//go:build unix

package daemon

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// spoolDir is a directory held open by fd, so a bot that renames or swaps
// the path for a symlink can't redirect the daemon's reads or writes.
type spoolDir struct{ f *os.File }

func openSpoolDir(path string) (*spoolDir, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &spoolDir{f: os.NewFile(uintptr(fd), path)}, nil
}

func (d *spoolDir) names() ([]string, error) {
	if _, err := d.f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return d.f.Readdirnames(-1)
}

// read opens a regular file in the directory without following links.
func (d *spoolDir) read(name string, max int64) ([]byte, error) {
	fd, err := unix.Openat(int(d.f.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > max {
		return nil, errSpoolFile
	}
	return io.ReadAll(io.LimitReader(f, max))
}

// write creates a new file; it fails if the name exists, even as a link.
func (d *spoolDir) write(name string, body []byte) error {
	tmp := "." + name + ".tmp"
	fd, err := unix.Openat(int(d.f.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmp)
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return unix.Renameat(int(d.f.Fd()), tmp, int(d.f.Fd()), name)
}

func (d *spoolDir) remove(name string) {
	_ = unix.Unlinkat(int(d.f.Fd()), name, 0)
}

func (d *spoolDir) close() { _ = d.f.Close() }

const lgbSupported = true
