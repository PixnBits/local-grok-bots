//go:build linux

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// buildBindBeforeOpen runs after the protected-inode snapshot and before the
// bind path is stat'd and opened. Tests use it to rename or swap a path
// component in between. The snapshot is taken first so a parent of a secret
// renamed onto the bind path still matches an inode the check already holds.
var buildBindBeforeOpen func()

var errBindRecheck = errors.New("bind recheck")

type bindInode struct {
	dev uint64
	ino uint64
}

// openBuildBind pins a build bind that passed the path check.
// openat2 with RESOLVE_NO_SYMLINKS refuses a symlink swapped into any
// component. The fd is O_PATH|O_CLOEXEC and is not O_DIRECTORY, so a file
// or a directory both open. Bubblewrap mounts it with --ro-bind-fd and does
// not fall back to a path bind. The unshare fallback cannot mount this fd
// (/proc/self/fd/N returns EINVAL from the new user namespace), so it
// refuses the bind instead of mounting the path. A failure here, including
// ENOSYS and ELOOP, also refuses the bind.
func openBuildBind(resolved string, protected []string) (*os.File, error) {
	resolved = filepath.Clean(resolved)
	protectedInodes := snapshotProtectedInodes(protected)
	if buildBindBeforeOpen != nil {
		buildBindBeforeOpen()
	}
	want, ok := statBindInode(resolved)
	if !ok {
		return nil, errBindRecheck
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

// snapshotProtectedInodes records each protected path and every ancestor
// directory up to, but not including, "/". A bind whose opened inode is one
// of those would contain a secret or would be DATA_DIR when the daemon put
// DATA_DIR on the protected list. The walk does not enter the opened object.
func snapshotProtectedInodes(protected []string) []bindInode {
	var out []bindInode
	seen := map[bindInode]struct{}{}
	add := func(p string) {
		ino, ok := statBindInode(p)
		if !ok {
			return
		}
		if _, dup := seen[ino]; dup {
			return
		}
		seen[ino] = struct{}{}
		out = append(out, ino)
	}
	for _, p := range protected {
		p = filepath.Clean(strings.TrimSpace(p))
		if p == "" || p == "." || p == "/" {
			continue
		}
		add(p)
		for {
			parent := filepath.Dir(p)
			if parent == p || parent == "/" || parent == "." {
				break
			}
			add(parent)
			p = parent
		}
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
