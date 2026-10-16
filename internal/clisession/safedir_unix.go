//go:build unix

package clisession

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// dirFD is a directory descriptor. Components opened from it use
// O_NOFOLLOW, so a symlink is not a directory the walk enters.
type dirFD struct {
	fd int
}

func openConfiguredRoot(path string) (*dirFD, error) {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return nil, errors.New("credential root is empty")
	}
	if !filepath.IsAbs(path) {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		path = abs
	}
	lst, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if lst.Mode()&os.ModeSymlink != 0 {
		return nil, ErrCredSymlink
	}
	if !lst.IsDir() {
		return nil, errors.New("credential root is not a directory")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		if isSymlinkAt(unix.AT_FDCWD, path) {
			return nil, ErrCredSymlink
		}
		return nil, err
	}
	return &dirFD{fd: fd}, nil
}

func (d *dirFD) close() {
	if d == nil || d.fd < 0 {
		return
	}
	_ = unix.Close(d.fd)
	d.fd = -1
}

func (d *dirFD) dup() (*dirFD, error) {
	if d == nil || d.fd < 0 {
		return nil, errors.New("directory is closed")
	}
	fd, err := unix.Dup(d.fd)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	return &dirFD{fd: fd}, nil
}

func (d *dirFD) names() ([]string, error) {
	dup, err := d.dup()
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup.fd), "d")
	dup.fd = -1
	defer f.Close()
	return f.Readdirnames(-1)
}

func safeComponent(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00")
}

func splitRel(rel string) ([]string, error) {
	rel = filepath.Clean(rel)
	if rel == "" || rel == "." || filepath.IsAbs(rel) {
		return nil, errors.New("credential path is not relative")
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for _, p := range parts {
		if !safeComponent(p) {
			return nil, errors.New("credential path is not relative")
		}
	}
	return parts, nil
}

func isSymlinkAt(dirfd int, name string) bool {
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFLNK
}

func (d *dirFD) openDir(name string) (*dirFD, error) {
	if d == nil || d.fd < 0 {
		return nil, errors.New("directory is closed")
	}
	if !safeComponent(name) {
		return nil, errors.New("bad path component")
	}
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		if isSymlinkAt(d.fd, name) {
			return nil, ErrCredSymlink
		}
		return nil, err
	}
	return &dirFD{fd: fd}, nil
}

// walk opens each component of rel. create makes missing directories.
// A symlink component returns ErrCredSymlink.
func (d *dirFD) walk(rel string, create bool) (*dirFD, error) {
	parts, err := splitRel(rel)
	if err != nil {
		return nil, err
	}
	cur, err := d.dup()
	if err != nil {
		return nil, err
	}
	for _, p := range parts {
		next, err := cur.openDir(p)
		if err != nil && create && errors.Is(err, unix.ENOENT) {
			if mk := unix.Mkdirat(cur.fd, p, 0o700); mk != nil && !errors.Is(mk, unix.EEXIST) {
				cur.close()
				return nil, mk
			}
			next, err = cur.openDir(p)
		}
		cur.close()
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}

func parentOf(root *dirFD, rel string, create bool) (parent *dirFD, base string, err error) {
	parts, err := splitRel(rel)
	if err != nil {
		return nil, "", err
	}
	base = parts[len(parts)-1]
	if len(parts) == 1 {
		parent, err = root.dup()
		return parent, base, err
	}
	parent, err = root.walk(filepath.Join(parts[:len(parts)-1]...), create)
	return parent, base, err
}

func mkdirNoFollow(root, rel string) error {
	d, err := openConfiguredRoot(root)
	if err != nil {
		return err
	}
	defer d.close()
	child, err := d.walk(rel, true)
	if err != nil {
		return err
	}
	child.close()
	return nil
}

func writeFileNoFollow(root, rel string, data []byte, mode os.FileMode) error {
	d, err := openConfiguredRoot(root)
	if err != nil {
		return err
	}
	defer d.close()
	parent, base, err := parentOf(d, rel, true)
	if err != nil {
		return err
	}
	defer parent.close()
	if isSymlinkAt(parent.fd, base) {
		return ErrCredSymlink
	}
	if err := unix.Unlinkat(parent.fd, base, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	fd, err := unix.Openat(parent.fd, base, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		if isSymlinkAt(parent.fd, base) {
			return ErrCredSymlink
		}
		return err
	}
	defer unix.Close(fd)
	return writeFull(fd, data)
}

func writeFull(fd int, data []byte) error {
	for len(data) > 0 {
		n, err := unix.Write(fd, data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func removeFileNoFollow(root, rel string) error {
	d, err := openConfiguredRoot(root)
	if err != nil {
		return err
	}
	defer d.close()
	parent, base, err := parentOf(d, rel, false)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer parent.close()
	if isSymlinkAt(parent.fd, base) {
		// The final name is unlinked. The target stays.
		err = unix.Unlinkat(parent.fd, base, 0)
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	err = unix.Unlinkat(parent.fd, base, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

// removeTreeNoFollow removes rel under root. A symlink entry is unlinked.
// The walk does not enter it. A symlink in a parent component of rel is an error.
func removeTreeNoFollow(root, rel string) error {
	d, err := openConfiguredRoot(root)
	if err != nil {
		return err
	}
	defer d.close()
	parent, base, err := parentOf(d, rel, false)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer parent.close()
	return parent.removeEntry(base)
}

func (d *dirFD) removeEntry(name string) error {
	if !safeComponent(name) {
		return errors.New("bad path component")
	}
	child, err := d.openDir(name)
	if err != nil && errors.Is(err, unix.EACCES) {
		// A mode 000 directory is still owned by this process. chmod does not
		// follow the entry; openDir already rejected a symlink.
		ch := unix.Fchmodat(d.fd, name, 0o700, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(ch, unix.EOPNOTSUPP) || errors.Is(ch, unix.ENOSYS) {
			ch = unix.Fchmodat(d.fd, name, 0o700, 0)
		}
		if ch == nil {
			child, err = d.openDir(name)
		}
	}
	if err != nil {
		if errors.Is(err, ErrCredSymlink) || errors.Is(err, unix.ENOTDIR) {
			uerr := unix.Unlinkat(d.fd, name, 0)
			if uerr != nil && !errors.Is(uerr, unix.ENOENT) {
				return uerr
			}
			return nil
		}
		if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer child.close()
	names, err := child.names()
	if err != nil {
		return err
	}
	for _, n := range names {
		if n == "." || n == ".." {
			continue
		}
		if err := child.removeEntry(n); err != nil {
			return err
		}
	}
	if err := unix.Unlinkat(d.fd, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

func lstatAt(dirfd int, name string) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	return st, err
}

func readlinkAt(dirfd int, name string) (string, error) {
	buf := make([]byte, 4096)
	for {
		n, err := unix.Readlinkat(dirfd, name, buf)
		if err != nil {
			return "", err
		}
		if n < len(buf) {
			return string(buf[:n]), nil
		}
		buf = make([]byte, len(buf)*2)
	}
}

func readFileAt(dirfd int, name string) ([]byte, error) {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

func readFollowLeaf(dirfd int, name string) ([]byte, error) {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

func sameStatInode(st unix.Stat_t, real os.FileInfo) bool {
	if real == nil {
		return false
	}
	sys, ok := real.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return uint64(st.Dev) == uint64(sys.Dev) && uint64(st.Ino) == uint64(sys.Ino)
}

func scrubTree(dataDir, realPath string) error {
	root, err := openConfiguredRoot(dataDir)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.close()
	cli, err := root.openDir("cli")
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if errors.Is(err, ErrCredSymlink) {
		return nil
	}
	if err != nil {
		return err
	}
	defer cli.close()
	names, err := cli.names()
	if err != nil {
		return err
	}
	var bots []string
	for _, n := range names {
		if safeBotID(n) {
			bots = append(bots, n)
		}
	}
	if len(bots) == 0 {
		return nil
	}
	realPath = filepath.Clean(realPath)
	var realInfo os.FileInfo
	var realBytes []byte
	var secrets []string
	if realPath != "" && realPath != "." {
		if st, err := os.Stat(realPath); err == nil && st.Mode().IsRegular() {
			realInfo = st
			if b, err := readLimited(realPath); err == nil {
				realBytes = b
				secrets = loginSecrets(b)
			}
		}
	}
	var first error
	for _, bot := range bots {
		bfd, err := cli.openDir(bot)
		if errors.Is(err, ErrCredSymlink) || errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		for _, rel := range grokAuthRel {
			if err := scrubOne(bfd, rel, realPath, realInfo, realBytes, secrets); err != nil && first == nil {
				first = err
			}
		}
		bfd.close()
	}
	return first
}

func scrubOne(bot *dirFD, rel, realPath string, realInfo os.FileInfo, realBytes []byte, secrets []string) error {
	parent, base, err := parentOf(bot, rel, false)
	if errors.Is(err, ErrCredSymlink) {
		return nil
	}
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer parent.close()
	if !staleLeaf(parent, base, realPath, realInfo, realBytes, secrets) {
		return nil
	}
	err = unix.Unlinkat(parent.fd, base, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func staleLeaf(parent *dirFD, name, realPath string, realInfo os.FileInfo, realBytes []byte, secrets []string) bool {
	st, err := lstatAt(parent.fd, name)
	if err != nil {
		return false
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		if linkTextMatches(parent.fd, name, realPath) || sameOpenInode(parent.fd, name, realInfo) {
			return true
		}
		b, err := readFollowLeaf(parent.fd, name)
		return contentMatches(b, err, realBytes, secrets)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFREG && sameStatInode(st, realInfo) {
		return st.Nlink > 1
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return false
	}
	b, err := readFileAt(parent.fd, name)
	return contentMatches(b, err, realBytes, secrets)
}

func contentMatches(b []byte, err error, realBytes []byte, secrets []string) bool {
	if err != nil {
		return false
	}
	if len(realBytes) > 0 && bytes.Equal(b, realBytes) {
		return true
	}
	for _, s := range secrets {
		if s != "" && bytes.Contains(b, []byte(s)) {
			return true
		}
	}
	return false
}

func linkTextMatches(dirfd int, name, realPath string) bool {
	if realPath == "" {
		return false
	}
	target, err := readlinkAt(dirfd, name)
	if err != nil {
		return false
	}
	return filepath.Clean(target) == filepath.Clean(realPath)
}

func sameOpenInode(dirfd int, name string, real os.FileInfo) bool {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false
	}
	return sameStatInode(st, real)
}
