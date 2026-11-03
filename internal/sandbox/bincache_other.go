//go:build !unix

package sandbox

import "os"

func openExclusive(path string, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, mode)
}

func rejectFollow(string) error { return nil }

func fileUID(os.FileInfo) (uint32, bool) { return 0, false }
