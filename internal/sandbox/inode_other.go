//go:build !unix

package sandbox

import "os"

func lstatInode(path string) (dev, ino uint64, isDir bool, err error) {
	st, err := os.Lstat(path)
	if err != nil {
		return 0, 0, false, err
	}
	return 0, 0, st.IsDir(), nil
}
