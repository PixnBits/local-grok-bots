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

// workspaceConfigReason returns "config" when the workspace git config must
// be refused. A missing .git is not a config denial. Git is not invoked.
func workspaceConfigReason(ws string) string {
	if ws == "" || !filepath.IsAbs(ws) {
		return "config"
	}
	wsFd, err := unix.Open(ws, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "config"
	}
	defer unix.Close(wsFd)
	gitFd, err := unix.Openat(wsFd, ".git", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if err == unix.ENOENT {
			return ""
		}
		return "config"
	}
	defer unix.Close(gitFd)
	denied, err := configDeniedAt(gitFd)
	if err != nil || denied {
		return "config"
	}
	return ""
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

// copyGitMirror builds a bare repository under parent from the workspace
// refs and objects. It does not copy config, hooks, attributes, or alternates.
func copyGitMirror(parent, ws string) (string, error) {
	if !filepath.IsAbs(parent) || !filepath.IsAbs(ws) {
		return "", errors.New("mirror")
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(parent, "m-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	if err := fillMirror(dir, ws); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

func fillMirror(dir, ws string) error {
	wsFd, err := unix.Open(ws, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(wsFd)
	gitFd, err := unix.Openat(wsFd, ".git", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(gitFd)
	var root unix.Stat_t
	if err := unix.Fstat(gitFd, &root); err != nil {
		return err
	}
	c := &copier{rootDev: uint64(root.Dev)}
	for _, name := range []string{"HEAD", "packed-refs", "shallow"} {
		optional := name != "HEAD"
		if err := copyFileNamed(c, gitFd, name, filepath.Join(dir, name), optional); err != nil {
			return err
		}
	}
	if err := copyDirNamed(c, gitFd, "refs", filepath.Join(dir, "refs"), "refs"); err != nil {
		return err
	}
	if err := copyDirNamed(c, gitFd, "objects", filepath.Join(dir, "objects"), "objects"); err != nil {
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
