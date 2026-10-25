//go:build unix

package daemon

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/github"
	"golang.org/x/sys/unix"
)

const (
	maxGitFile  int64 = 1 << 30
	maxGitTotal int64 = 1 << 31
	maxGitFiles       = 200000
	maxConfig         = 1 << 20
)

// beforeMirrorCopy, when set, runs after resolve and before the mirror
// read. Production leaves it nil.
var beforeMirrorCopy func()

// heldDir is one path component opened relative to the previous descriptor.
type heldDir struct {
	fd   int
	name string
	dev  uint64
	ino  uint64
}

// repoHandle is the workspace repository kept open for the config check and
// the mirror copy. Close releases every directory descriptor.
type repoHandle struct {
	root       int
	chain      []heldDir
	repo       int
	repoParent int
	repoName   string
	git        int
	repoDev    uint64
	repoIno    uint64
	gitDev     uint64
	gitIno     uint64
	closed     bool
}

func (h *repoHandle) Close() error {
	if h == nil || h.closed {
		return nil
	}
	h.closed = true
	if h.git >= 0 {
		unix.Close(h.git)
		h.git = -1
	}
	for i := len(h.chain) - 1; i >= 0; i-- {
		if h.chain[i].fd >= 0 {
			unix.Close(h.chain[i].fd)
			h.chain[i].fd = -1
		}
	}
	if h.root >= 0 {
		unix.Close(h.root)
		h.root = -1
	}
	h.repo = -1
	h.repoParent = -1
	return nil
}

// configReason reports "config" when .git/config must be refused.
// The read uses the held .git descriptor.
func (h *repoHandle) configReason() string {
	if h == nil || h.git < 0 || h.closed {
		return "config"
	}
	denied, err := configDeniedAt(h.git)
	if err != nil || denied {
		return "config"
	}
	return ""
}

// stable reports whether the repository directory and .git are still the
// files recorded when the handle was opened.
func (h *repoHandle) stable() bool {
	if h == nil || h.closed || h.git < 0 || h.repo < 0 {
		return false
	}
	if !statMatch(h.repo, h.repoDev, h.repoIno) || !statMatch(h.git, h.gitDev, h.gitIno) {
		return false
	}
	if h.repoName != "" && !statAtMatch(h.repoParent, h.repoName, h.repoDev, h.repoIno) {
		return false
	}
	return statAtMatch(h.repo, ".git", h.gitDev, h.gitIno)
}

func statMatch(fd int, dev, ino uint64) bool {
	if fd < 0 {
		return false
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false
	}
	return uint64(st.Dev) == dev && uint64(st.Ino) == ino && st.Mode&unix.S_IFMT == unix.S_IFDIR
}

func statAtMatch(dirfd int, name string, dev, ino uint64) bool {
	if dirfd < 0 || name == "" || strings.ContainsAny(name, "/\\\x00") {
		return false
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false
	}
	return uint64(st.Dev) == dev && uint64(st.Ino) == ino && st.Mode&unix.S_IFMT == unix.S_IFDIR
}

func configDeniedAt(gitFd int) (bool, error) {
	fd, err := unix.Openat(gitFd, "config", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if err == unix.ENOENT {
			return false, nil
		}
		return true, nil
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return true, nil
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return true, nil
	}
	if st.Size < 0 || st.Size > maxConfig {
		return true, nil
	}
	buf := make([]byte, 0, int(st.Size))
	tmp := make([]byte, 32*1024)
	for len(buf) <= maxConfig {
		n, err := unix.Read(fd, tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) > maxConfig {
				return true, nil
			}
		}
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return true, nil
		}
		if n == 0 {
			break
		}
	}
	return github.RepoConfigDenied(string(buf)), nil
}

// resolveWorkspaceRepo opens the workspace once and returns the repository
// directory that contains the nearest .git at rel. The caller closes it.
// ".." , an absolute path, a symlink component, a gitfile, and a path outside
// the workspace are refused.
func resolveWorkspaceRepo(ws, rel string) (*repoHandle, string) {
	if ws == "" || !filepath.IsAbs(ws) {
		return nil, "repository not found in workspace"
	}
	parts, reason := workspaceRelParts(rel)
	if reason != "" {
		return nil, reason
	}
	rootFd, err := unix.Open(ws, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "repository not found in workspace"
	}
	chain, err := openChain(rootFd, parts)
	if err != nil {
		unix.Close(rootFd)
		return nil, openErrReason(err)
	}
	h, reason := findRepo(rootFd, chain)
	if reason != "" {
		closeHeld(rootFd, chain, -1)
		return nil, reason
	}
	return h, ""
}

func openErrReason(err error) string {
	switch {
	case errors.Is(err, unix.ELOOP):
		return "symlink"
	case errors.Is(err, unix.ENOENT):
		return "repository not found in workspace"
	default:
		return "path"
	}
}

// directoryErr turns O_DIRECTORY's ENOTDIR into ELOOP when the component is a
// symlink. O_DIRECTORY reports both a symlink and a non-directory as ENOTDIR.
func directoryErr(parent int, name string, err error) error {
	if err == nil || !errors.Is(err, unix.ENOTDIR) {
		return err
	}
	var st unix.Stat_t
	if ferr := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); ferr != nil {
		return err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return unix.ELOOP
	}
	return err
}

// componentErr classifies a failed resolve. An intermediate symlink is ELOOP
// from openat2. A final symlink is ENOTDIR because the open asks for a directory.
func componentErr(rootFd int, parts []string, err error) error {
	if err == nil || errors.Is(err, unix.ELOOP) || !errors.Is(err, unix.ENOTDIR) {
		return err
	}
	parent := rootFd
	var extra []int
	defer func() {
		for _, fd := range extra {
			unix.Close(fd)
		}
	}()
	for i, part := range parts {
		if errors.Is(directoryErr(parent, part, unix.ENOTDIR), unix.ELOOP) {
			return unix.ELOOP
		}
		var st unix.Stat_t
		if ferr := unix.Fstatat(parent, part, &st, unix.AT_SYMLINK_NOFOLLOW); ferr != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || i == len(parts)-1 {
			return err
		}
		fd, oerr := unix.Openat(parent, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if oerr != nil {
			return directoryErr(parent, part, oerr)
		}
		extra = append(extra, fd)
		parent = fd
	}
	return err
}

func findRepo(rootFd int, chain []heldDir) (*repoHandle, string) {
	type step struct {
		fd     int
		name   string
		parent int
	}
	steps := make([]step, 0, 1+len(chain))
	steps = append(steps, step{fd: rootFd, parent: -1})
	parent := rootFd
	for _, n := range chain {
		steps = append(steps, step{fd: n.fd, name: n.name, parent: parent})
		parent = n.fd
	}
	for i := len(steps) - 1; i >= 0; i-- {
		gitFd, kind, err := openGitAt(steps[i].fd)
		if err != nil {
			return nil, "path"
		}
		switch kind {
		case "dir":
			var rst, gst unix.Stat_t
			if unix.Fstat(steps[i].fd, &rst) != nil || unix.Fstat(gitFd, &gst) != nil {
				unix.Close(gitFd)
				return nil, "path"
			}
			if rst.Mode&unix.S_IFMT != unix.S_IFDIR || gst.Mode&unix.S_IFMT != unix.S_IFDIR {
				unix.Close(gitFd)
				return nil, "path"
			}
			return &repoHandle{
				root:       rootFd,
				chain:      chain,
				repo:       steps[i].fd,
				repoParent: steps[i].parent,
				repoName:   steps[i].name,
				git:        gitFd,
				repoDev:    uint64(rst.Dev),
				repoIno:    uint64(rst.Ino),
				gitDev:     uint64(gst.Dev),
				gitIno:     uint64(gst.Ino),
			}, ""
		case "symlink":
			return nil, "symlink"
		case "file":
			return nil, "gitfile"
		case "none":
			continue
		default:
			return nil, "path"
		}
	}
	return nil, "repository not found in workspace"
}

func closeHeld(root int, chain []heldDir, git int) {
	if git >= 0 {
		unix.Close(git)
	}
	for i := len(chain) - 1; i >= 0; i-- {
		if chain[i].fd >= 0 {
			unix.Close(chain[i].fd)
		}
	}
	if root >= 0 {
		unix.Close(root)
	}
}

func workspaceRelParts(rel string) ([]string, string) {
	if rel == "" || strings.ContainsAny(rel, "\\\x00\r\n") || filepath.IsAbs(rel) {
		return nil, "path"
	}
	for _, part := range strings.Split(rel, "/") {
		if part == ".." {
			return nil, "path"
		}
	}
	clean := filepath.Clean(rel)
	if clean == "." {
		return nil, ""
	}
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
		return nil, "path"
	}
	var parts []string
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			return nil, "path"
		}
		parts = append(parts, part)
	}
	return parts, ""
}

func openGitAt(dirfd int) (int, string, error) {
	fd, err := unix.Openat(dirfd, ".git", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOENT):
			return -1, "none", nil
		case errors.Is(err, unix.ELOOP):
			return -1, "symlink", nil
		default:
			return -1, "", err
		}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, "", err
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		return fd, "dir", nil
	case unix.S_IFREG:
		unix.Close(fd)
		return -1, "file", nil
	default:
		unix.Close(fd)
		return -1, "path", nil
	}
}

// openChainWalk opens each component from the previous descriptor.
// A symlink is not followed. Every directory must stay on the root device.
func openChainWalk(rootFd int, parts []string) ([]heldDir, error) {
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFd, &rootStat); err != nil {
		return nil, err
	}
	rootDev := uint64(rootStat.Dev)
	var nodes []heldDir
	parent := rootFd
	for _, part := range parts {
		fd, err := unix.Openat(parent, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			classified := directoryErr(parent, part, err)
			closeHeldDirs(nodes)
			return nil, classified
		}
		node, err := heldFrom(parent, fd, part, rootDev)
		if err != nil {
			unix.Close(fd)
			closeHeldDirs(nodes)
			return nil, err
		}
		nodes = append(nodes, node)
		parent = fd
	}
	return nodes, nil
}

func heldFrom(parent, fd int, name string, rootDev uint64) (heldDir, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return heldDir{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(st.Dev) != rootDev {
		if uint64(st.Dev) != rootDev {
			return heldDir{}, unix.EXDEV
		}
		return heldDir{}, unix.ENOTDIR
	}
	node := heldDir{fd: fd, name: name, dev: uint64(st.Dev), ino: uint64(st.Ino)}
	if !statAtMatch(parent, name, node.dev, node.ino) {
		return heldDir{}, unix.ELOOP
	}
	return node, nil
}

func closeHeldDirs(nodes []heldDir) {
	for i := len(nodes) - 1; i >= 0; i-- {
		if nodes[i].fd >= 0 {
			unix.Close(nodes[i].fd)
		}
	}
}

// copyGitMirror builds a bare repository under parent from the held
// repository. It reads that repository only through its open descriptors.
func copyGitMirror(parent string, h *repoHandle) (string, error) {
	if h == nil || h.git < 0 || h.closed || !filepath.IsAbs(parent) {
		return "", errors.New("mirror")
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return "", err
	}
	if beforeMirrorCopy != nil {
		beforeMirrorCopy()
	}
	dir, err := os.MkdirTemp(parent, "m-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	if err := fillMirror(dir, h); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	if !h.stable() {
		_ = os.RemoveAll(dir)
		return "", errors.New("mirror")
	}
	return dir, nil
}

func fillMirror(dir string, h *repoHandle) error {
	var root unix.Stat_t
	if err := unix.Fstat(h.git, &root); err != nil {
		return err
	}
	c := &copier{rootDev: uint64(root.Dev)}
	for _, name := range []string{"HEAD", "packed-refs", "shallow"} {
		optional := name != "HEAD"
		if err := copyFileNamed(c, h.git, name, filepath.Join(dir, name), optional); err != nil {
			return err
		}
	}
	if err := copyDirNamed(c, h.git, "refs", filepath.Join(dir, "refs"), "refs"); err != nil {
		return err
	}
	if err := copyDirNamed(c, h.git, "objects", filepath.Join(dir, "objects"), "objects"); err != nil {
		return err
	}
	return writeBareConfig(dir)
}

func writeBareConfig(dir string) error {
	path := filepath.Join(dir, "config")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	body := []byte(bareMirrorConfig)
	_, err = f.Write(body)
	cerr := f.Close()
	if err != nil {
		return err
	}
	return cerr
}

type copier struct {
	rootDev uint64
	total   int64
	files   int
}

func copyFileNamed(c *copier, dirfd int, name, dst string, optional bool) error {
	if !safeGitName(name) {
		return errors.New("name")
	}
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if optional && err == unix.ENOENT {
			return nil
		}
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("type")
	}
	return copyRegular(c, fd, &st, dst)
}

func copyDirNamed(c *copier, parent int, name, dst, rel string) error {
	if !safeGitName(name) {
		return errors.New("name")
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return copyDirFd(c, fd, dst, rel)
}

func copyDirFd(c *copier, fd int, dst, rel string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("type")
	}
	if uint64(st.Dev) != c.rootDev {
		return errors.New("device")
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dst, 0o700); err != nil {
		return err
	}
	names, err := dirNames(fd)
	if err != nil {
		return err
	}
	for _, ent := range names {
		if !safeGitName(ent) {
			return errors.New("name")
		}
		childRel := rel + "/" + ent
		if childRel == "objects/info/alternates" || strings.HasPrefix(childRel, "objects/info/alternates/") {
			continue
		}
		if err := copyEntry(c, fd, ent, filepath.Join(dst, ent), childRel); err != nil {
			return err
		}
	}
	return nil
}

func copyEntry(c *copier, parent int, name, dst, rel string) error {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if uint64(st.Dev) != c.rootDev {
		return errors.New("device")
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		return copyDirFd(c, fd, dst, rel)
	case unix.S_IFREG:
		return copyRegular(c, fd, &st, dst)
	default:
		return errors.New("type")
	}
}

func copyRegular(c *copier, fd int, st *unix.Stat_t, dst string) error {
	if st.Size < 0 || st.Size > maxGitFile || c.total+st.Size > maxGitTotal || c.files >= maxGitFiles {
		return errors.New("size")
	}
	dup, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	src := os.NewFile(uintptr(dup), "git")
	defer src.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(src, st.Size+1))
	cerr := out.Close()
	if err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	if n > st.Size || n > maxGitFile {
		return errors.New("size")
	}
	c.total += n
	c.files++
	return nil
}

func dirNames(fd int) ([]string, error) {
	dup, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), "dir")
	defer f.Close()
	return f.Readdirnames(-1)
}

func safeGitName(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 255 {
		return false
	}
	return !strings.ContainsAny(s, "/\\\x00")
}
