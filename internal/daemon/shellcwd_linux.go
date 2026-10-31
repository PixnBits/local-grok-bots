//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openShellDirBeneath opens rel from the workspace directory.
// RESOLVE_BENEATH rejects a symlink that resolves outside that directory.
// fallback is true only when the kernel has no openat2.
func openShellDirBeneath(root, rel string) (string, error, bool) {
	dirfd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err, false
	}
	defer unix.Close(dirfd)
	how := &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_BENEATH,
	}
	fd, err := unix.Openat2(dirfd, rel, how)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) {
			return "", err, true
		}
		return "", err, false
	}
	defer unix.Close(fd)
	p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil || p == "" || strings.HasSuffix(p, " (deleted)") || !filepath.IsAbs(p) {
		return filepath.Join(root, rel), nil, false
	}
	return filepath.Clean(p), nil, false
}
