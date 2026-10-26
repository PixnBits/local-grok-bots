//go:build linux

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// buildBindBeforeOpen runs after EvalSymlinks and the overlap check, and
// before openat2. Tests use it to swap a path component in between.
var buildBindBeforeOpen func()

var errBindRecheck = errors.New("bind recheck")

type bindInode struct {
	dev uint64
	ino uint64
}

// openBuildBind pins a build bind that passed the path check.
// openat2 with RESOLVE_NO_SYMLINKS refuses a symlink swapped into any
// component. The fd is O_PATH|O_CLOEXEC and is not O_DIRECTORY, so a file
// or a directory both open. The caller passes it to bwrap --ro-bind-fd.
// A failure, including ENOSYS and ELOOP, refuses the bind. There is no
// path-based --ro-bind fallback.
func openBuildBind(resolved string, protected []string) (*os.File, error) {
	resolved = filepath.Clean(resolved)
	want, ok := statBindInode(resolved)
	if !ok {
		return nil, errBindRecheck
	}
	protectedInodes := snapshotProtectedInodes(protected)
	if buildBindBeforeOpen != nil {
		buildBindBeforeOpen()
	}
	how := &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, resolved, how)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	real, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	real = filepath.Clean(real)
	if real != resolved || bindOverlapsProtected(real, real, protected) {
		unix.Close(fd)
		return nil, errBindRecheck
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	got := bindInode{dev: uint64(st.Dev), ino: uint64(st.Ino)}
	// A rename can place a protected directory at the resolved path with no
	// symlink. readlink still shows that path, so the inode is checked too.
	if got != want || inodeProtected(got, protectedInodes) {
		unix.Close(fd)
		return nil, errBindRecheck
	}
	return os.NewFile(uintptr(fd), resolved), nil
}

func statBindInode(path string) (bindInode, bool) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return bindInode{}, false
	}
	return bindInode{dev: uint64(st.Dev), ino: uint64(st.Ino)}, true
}

func snapshotProtectedInodes(protected []string) []bindInode {
	var out []bindInode
	seen := map[bindInode]struct{}{}
	for _, p := range protected {
		ino, ok := statBindInode(p)
		if !ok {
			continue
		}
		if _, dup := seen[ino]; dup {
			continue
		}
		seen[ino] = struct{}{}
		out = append(out, ino)
	}
	return out
}

func inodeProtected(got bindInode, protected []bindInode) bool {
	for _, ino := range protected {
		if got == ino {
			return true
		}
	}
	return false
}
