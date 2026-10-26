//go:build unix

package sandbox

import "golang.org/x/sys/unix"

func lstatInode(path string) (dev, ino uint64, isDir bool, err error) {
	var st unix.Stat_t
	if err = unix.Lstat(path, &st); err != nil {
		return 0, 0, false, err
	}
	isDir = st.Mode&unix.S_IFMT == unix.S_IFDIR
	return uint64(st.Dev), uint64(st.Ino), isDir, nil
}
