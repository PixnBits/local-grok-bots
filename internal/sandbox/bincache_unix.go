//go:build unix

package sandbox

import (
	"errors"
	"os"
	"syscall"
)

func openExclusive(path string, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
}

// rejectFollow reports a symlink at path. O_NOFOLLOW yields ELOOP.
// A missing path is not an error.
func rejectFollow(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err == nil {
		_ = f.Close()
		return nil
	}
	if errors.Is(err, syscall.ELOOP) {
		return err
	}
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func fileUID(fi os.FileInfo) (uint32, bool) {
	if fi == nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, false
	}
	return st.Uid, true
}
