//go:build linux

package permbroker

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func peerCred(c net.Conn) (uid, pid int, err error) {
	uc, ok := c.(*net.UnixConn)
	if !ok || uc == nil {
		return 0, 0, errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *unix.Ucred
	var gerr error
	cerr := raw.Control(func(fd uintptr) {
		cred, gerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if cerr != nil {
		return 0, 0, cerr
	}
	if gerr != nil {
		return 0, 0, gerr
	}
	if cred == nil {
		return 0, 0, errors.New("no peer credential")
	}
	return int(cred.Uid), int(cred.Pid), nil
}
