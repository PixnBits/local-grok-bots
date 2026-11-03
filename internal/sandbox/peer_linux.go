//go:build linux

package sandbox

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerPID is the connecting process in this process's pid namespace.
func peerPID(conn net.Conn) int {
	uc, ok := conn.(*net.UnixConn)
	if !ok || uc == nil {
		return 0
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0
	}
	var cred *unix.Ucred
	var gerr error
	cerr := raw.Control(func(fd uintptr) {
		cred, gerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if cerr != nil || gerr != nil || cred == nil || cred.Pid <= 1 {
		return 0
	}
	return int(cred.Pid)
}
