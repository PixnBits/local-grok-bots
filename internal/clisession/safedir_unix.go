//go:build unix

package clisession

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
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
	_, err := removeFileNoted(root, rel)
	return err
}

func removeFileNoted(root, rel string) ([]SymlinkNote, error) {
	d, err := openConfiguredRoot(root)
	if err != nil {
		return nil, err
	}
	defer d.close()
	parent, base, err := parentOf(d, rel, false)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer parent.close()
	var notes []SymlinkNote
	if isSymlinkAt(parent.fd, base) {
		noteSymlink(&notes, EventSymlinkUnlinked, rel)
	}
	err = unix.Unlinkat(parent.fd, base, 0)
	if errors.Is(err, unix.ENOENT) {
		return notes, nil
	}
	return notes, err
}

// removeTreeNoFollow removes rel under root. A symlink entry is unlinked.
// The walk does not enter it. A symlink in a parent component of rel is an error.
func removeTreeNoFollow(root, rel string) error {
	_, err := removeTreeNoted(root, rel)
	return err
}

func removeTreeNoted(root, rel string) ([]SymlinkNote, error) {
	d, err := openConfiguredRoot(root)
	if err != nil {
		return nil, err
	}
	defer d.close()
	parent, base, err := parentOf(d, rel, false)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer parent.close()
	var notes []SymlinkNote
	err = parent.removeEntry(base, rel, &notes)
	return notes, err
}

func (d *dirFD) removeEntry(name, rel string, notes *[]SymlinkNote) error {
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
			if isSymlinkAt(d.fd, name) {
				noteSymlink(notes, EventSymlinkUnlinked, rel)
			}
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
		childRel := n
		if rel != "" {
			childRel = filepath.Join(rel, n)
		}
		if err := child.removeEntry(n, childRel, notes); err != nil {
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

func openRegularAt(dirfd int, name string, follow bool) (int, error) {
	flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC
	if !follow {
		flags |= unix.O_NOFOLLOW
	}
	fd, err := unix.Openat(dirfd, name, flags, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return -1, errNotRegular
	}
	return fd, nil
}

func readFileAt(dirfd int, name string) ([]byte, error) {
	fd, err := openRegularAt(dirfd, name, false)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

func readFollowLeaf(dirfd int, name string) ([]byte, error) {
	fd, err := openRegularAt(dirfd, name, true)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

func readRegularNoFollow(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, errNotRegular
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

func symlinkNoFollow(root, rel, target string) error {
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
	if cur, err := readlinkAt(parent.fd, base); err == nil && cur == target {
		return nil
	}
	if err := unix.Unlinkat(parent.fd, base, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		if isSymlinkAt(parent.fd, base) {
			return ErrCredSymlink
		}
		return err
	}
	if err := unix.Symlinkat(target, parent.fd, base); err != nil {
		if isSymlinkAt(parent.fd, base) {
			return ErrCredSymlink
		}
		return err
	}
	return nil
}

func linkCredNoFollow(src, root, rel string) error {
	st, err := os.Stat(src)
	if err != nil || !st.Mode().IsRegular() {
		return nil
	}
	return symlinkNoFollow(root, rel, src)
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

func scrubTree(dataDir, realPath string) ([]SymlinkNote, error) {
	root, err := openConfiguredRoot(dataDir)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.close()
	cli, err := root.openDir("cli")
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if errors.Is(err, ErrCredSymlink) {
		return []SymlinkNote{{Event: EventSymlinkSkipped, Rel: "cli"}}, nil
	}
	if err != nil {
		return nil, err
	}
	defer cli.close()
	names, err := cli.names()
	if err != nil {
		return nil, err
	}
	var bots []string
	for _, n := range names {
		if safeBotID(n) {
			bots = append(bots, n)
		}
	}
	if len(bots) == 0 {
		return nil, nil
	}
	realPath = filepath.Clean(realPath)
	var realInfo os.FileInfo
	var realBytes []byte
	var secrets []string
	if realPath != "" && realPath != "." {
		if st, err := os.Lstat(realPath); err == nil && st.Mode().IsRegular() {
			realInfo = st
			if b, err := readLimited(realPath); err == nil {
				realBytes = b
				secrets = loginSecrets(b)
			}
		}
	}
	var notes []SymlinkNote
	var first error
	for _, bot := range bots {
		botRel := filepath.Join("cli", bot)
		bfd, err := cli.openDir(bot)
		if errors.Is(err, ErrCredSymlink) {
			noteSymlink(&notes, EventSymlinkSkipped, botRel)
			continue
		}
		if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		for _, rel := range grokAuthRel {
			n, err := scrubOne(bfd, rel, filepath.Join(botRel, rel), realPath, realInfo, realBytes, secrets)
			notes = append(notes, n...)
			if err != nil && first == nil {
				first = err
			}
		}
		bfd.close()
	}
	return notes, first
}

func scrubOne(bot *dirFD, rel, fullRel, realPath string, realInfo os.FileInfo, realBytes []byte, secrets []string) ([]SymlinkNote, error) {
	parent, base, err := parentOf(bot, rel, false)
	if errors.Is(err, ErrCredSymlink) {
		return []SymlinkNote{{Event: EventSymlinkSkipped, Rel: fullRel}}, nil
	}
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer parent.close()
	if !staleLeaf(parent, base, realPath, realInfo, realBytes, secrets) {
		return nil, nil
	}
	var notes []SymlinkNote
	if isSymlinkAt(parent.fd, base) {
		noteSymlink(&notes, EventSymlinkUnlinked, fullRel)
	}
	err = unix.Unlinkat(parent.fd, base, 0)
	if errors.Is(err, unix.ENOENT) {
		return notes, nil
	}
	return notes, err
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
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return false
	}
	return sameStatInode(st, real)
}

// writeFileInDir creates dir if needed and replaces name inside it.
// The walk uses O_NOFOLLOW. macOS uses symlinks for /tmp, /var, and /etc;
// those three, and only when they point under /private, are crossed.
// Any other symlink is refused.
func writeFileInDir(dir, name string, data []byte, mode os.FileMode) error {
	if !safeComponent(name) {
		return errors.New("bad path component")
	}
	parent, err := ensureDirNoFollow(dir, 0)
	if err != nil {
		return err
	}
	defer parent.close()
	return writeReplacingAt(parent, name, data, mode)
}

func ensureDirNoFollow(path string, depth int) (*dirFD, error) {
	if depth > 4 {
		return nil, ErrCredSymlink
	}
	path, err := absClean(path)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	cur := &dirFD{fd: fd}
	walked := "/"
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for i, name := range parts {
		if name == "" {
			continue
		}
		next, err := cur.openDir(name)
		if err != nil && errors.Is(err, unix.ENOENT) {
			if mk := unix.Mkdirat(cur.fd, name, 0o700); mk != nil && !errors.Is(mk, unix.EEXIST) {
				cur.close()
				return nil, mk
			}
			next, err = cur.openDir(name)
		}
		if err != nil && isSymlinkAt(cur.fd, name) {
			target, ok := osDirSymlink(walked, name, cur.fd)
			cur.close()
			if !ok {
				return nil, ErrCredSymlink
			}
			rest := append([]string{target}, parts[i+1:]...)
			return ensureDirNoFollow(filepath.Join(rest...), depth+1)
		}
		cur.close()
		if err != nil {
			return nil, err
		}
		cur = next
		if walked == "/" {
			walked = "/" + name
		} else {
			walked += "/" + name
		}
	}
	return cur, nil
}

// osDirSymlink allows the macOS /tmp, /var, and /etc links into /private.
func osDirSymlink(parent, name string, fd int) (string, bool) {
	linkPath := "/" + name
	if parent != "/" {
		linkPath = parent + "/" + name
	}
	switch linkPath {
	case "/tmp", "/var", "/etc":
	default:
		return "", false
	}
	target, err := readlinkAt(fd, name)
	if err != nil || target == "" {
		return "", false
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(parent, target)
	}
	target = filepath.Clean(target)
	if !strings.HasPrefix(target, "/private/") {
		return "", false
	}
	return target, true
}

func writeReplacingAt(parent *dirFD, base string, data []byte, mode os.FileMode) error {
	if parent == nil || parent.fd < 0 {
		return errors.New("directory is closed")
	}
	if isSymlinkAt(parent.fd, base) {
		return ErrCredSymlink
	}
	if st, err := lstatAt(parent.fd, base); err == nil {
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return errNotRegular
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	var tmp string
	var fd int
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		tmp, err = siblingTemp(base)
		if err != nil {
			return err
		}
		fd, err = unix.Openat(parent.fd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EEXIST) {
			if isSymlinkAt(parent.fd, tmp) {
				return ErrCredSymlink
			}
			return err
		}
	}
	if err != nil {
		return err
	}
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(parent.fd, tmp, 0)
		return err
	}
	writeErr := writeFull(fd, data)
	_ = unix.Close(fd)
	if writeErr != nil {
		_ = unix.Unlinkat(parent.fd, tmp, 0)
		return writeErr
	}
	if isSymlinkAt(parent.fd, base) {
		_ = unix.Unlinkat(parent.fd, tmp, 0)
		return ErrCredSymlink
	}
	if err := unix.Renameat(parent.fd, tmp, parent.fd, base); err != nil {
		_ = unix.Unlinkat(parent.fd, tmp, 0)
		return err
	}
	return nil
}

func tooManyLinks(st os.FileInfo) bool {
	if st == nil || st.Sys() == nil {
		return false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return false
	}
	return sys.Nlink > 1
}

// createExclusiveNoFollow creates name inside an existing directory.
// A symlink at the directory or the new name is refused. An existing name
// is left in place.
func createExclusiveNoFollow(dir, name string, data []byte) error {
	if !safeComponent(name) {
		return errors.New("bad path component")
	}
	st, err := os.Lstat(dir)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return errors.New("seal directory is not available")
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		if isSymlinkAt(unix.AT_FDCWD, dir) {
			return ErrCredSymlink
		}
		return err
	}
	defer unix.Close(fd)
	if isSymlinkAt(fd, name) {
		return ErrCredSymlink
	}
	wfd, err := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		if isSymlinkAt(fd, name) {
			return ErrCredSymlink
		}
		return err
	}
	defer unix.Close(wfd)
	return writeFull(wfd, data)
}

func siblingTemp(base string) (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	name := "." + base + "." + hex.EncodeToString(buf[:])
	if !safeComponent(name) {
		return "", errors.New("bad path component")
	}
	return name, nil
}
