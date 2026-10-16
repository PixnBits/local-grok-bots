//go:build unix

package coi

import "golang.org/x/sys/unix"

func dirIdentity(path string) (uint64, uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, 0, err
	}
	return uint64(st.Dev), uint64(st.Ino), nil
}
