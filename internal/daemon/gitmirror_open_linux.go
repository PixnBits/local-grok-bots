//go:build linux

package daemon

import (
	"errors"
	"strings"

	"golang.org/x/sys/unix"
)

// openat2Fn resolves one path from a directory descriptor. Tests replace it.
var openat2Fn = unix.Openat2

// openChain resolves parts from rootFd. openat2 applies
// RESOLVE_BENEATH, RESOLVE_NO_SYMLINKS, and RESOLVE_NO_XDEV. ENOSYS uses the
// component walk.
func openChain(rootFd int, parts []string) ([]heldDir, error) {
	if len(parts) == 0 {
		return nil, nil
	}
	nodes, err := openChainAt2(rootFd, parts)
	if errors.Is(err, unix.ENOSYS) {
		return openChainWalk(rootFd, parts)
	}
	return nodes, err
}

func openChainAt2(rootFd int, parts []string) ([]heldDir, error) {
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFd, &rootStat); err != nil {
		return nil, err
	}
	rootDev := uint64(rootStat.Dev)
	rootMnt, rootOK := mountID(rootFd)
	final, err := openat2Dir(rootFd, strings.Join(parts, "/"))
	if err != nil {
		return nil, componentErr(rootFd, parts, err)
	}
	var finalStat unix.Stat_t
	if err := unix.Fstat(final, &finalStat); err != nil {
		unix.Close(final)
		return nil, err
	}
	unix.Close(final)
	if finalStat.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(finalStat.Dev) != rootDev {
		return nil, unix.ENOTDIR
	}
	var nodes []heldDir
	parent := rootFd
	for _, part := range parts {
		fd, err := openat2Dir(parent, part)
		if err != nil {
			classified := directoryErr(parent, part, err)
			closeHeldDirs(nodes)
			return nil, classified
		}
		node, err := heldFrom(parent, fd, part, rootDev, rootMnt, rootOK)
		if err != nil {
			unix.Close(fd)
			closeHeldDirs(nodes)
			return nil, err
		}
		nodes = append(nodes, node)
		parent = fd
	}
	last := nodes[len(nodes)-1]
	if last.dev != uint64(finalStat.Dev) || last.ino != uint64(finalStat.Ino) {
		closeHeldDirs(nodes)
		return nil, unix.EXDEV
	}
	return nodes, nil
}

// openChecked stats name with O_PATH, then opens it again from dirfd.
// A FIFO never reaches a blocking open. The returned fd is not the O_PATH fd.
func openChecked(dirfd int, name string, allowDir, allowReg bool) (int, unix.Stat_t, error) {
	pfd, err := unix.Openat(dirfd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	defer unix.Close(pfd)
	var pst unix.Stat_t
	if err := unix.Fstat(pfd, &pst); err != nil {
		return -1, unix.Stat_t{}, err
	}
	mode := uint32(pst.Mode) & uint32(unix.S_IFMT)
	if mode == unix.S_IFLNK {
		return -1, pst, unix.ELOOP
	}
	if !modeAllowed(mode, allowDir, allowReg) {
		return -1, pst, errGitType
	}
	flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if mode == unix.S_IFDIR {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat(dirfd, name, flags, 0)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, unix.Stat_t{}, err
	}
	if uint32(st.Mode)&uint32(unix.S_IFMT) != mode || uint64(st.Dev) != uint64(pst.Dev) || uint64(st.Ino) != uint64(pst.Ino) {
		unix.Close(fd)
		return -1, st, errGitType
	}
	return fd, st, nil
}

func platformMountID(fd int) (uint64, bool) {
	var stx unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &stx); err != nil {
		return 0, false
	}
	if stx.Mask&unix.STATX_MNT_ID == 0 {
		return 0, false
	}
	return stx.Mnt_id, true
}

func openat2Dir(dirfd int, path string) (int, error) {
	how := &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	}
	return openat2Fn(dirfd, path, how)
}
