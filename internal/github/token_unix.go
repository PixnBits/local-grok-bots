//go:build unix

package github

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func readTokenFile(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00") {
		return "", errToken("path")
	}
	var lst unix.Stat_t
	if err := unix.Lstat(path, &lst); err != nil {
		return "", errToken("read")
	}
	if lst.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", errToken("type")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", errToken("read")
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return "", errToken("read")
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", errToken("type")
	}
	perm := uint32(st.Mode) & 0o7777
	if tokenCheck != nil {
		if err := tokenCheck(st.Uid, perm); err != nil {
			return "", errToken("check")
		}
	} else if perm != 0o600 {
		return "", errToken("mode")
	} else if st.Uid != 0 {
		return "", errToken("owner")
	}
	if st.Size <= 0 || st.Size > 4096 {
		return "", errToken("size")
	}
	buf := make([]byte, st.Size)
	n := 0
	for n < len(buf) {
		got, err := unix.Read(fd, buf[n:])
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return "", errToken("read")
		}
		if got == 0 {
			break
		}
		n += got
	}
	// One extra byte catches a file that grew past the fstat size.
	var extra [1]byte
	got, err := unix.Read(fd, extra[:])
	for err == unix.EINTR {
		got, err = unix.Read(fd, extra[:])
	}
	if err != nil || got > 0 {
		return "", errToken("size")
	}
	return tokenFromBytes(buf[:n])
}
