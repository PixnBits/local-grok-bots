//go:build !linux

package sandbox

import "net"

func peerPID(net.Conn) int { return 0 }
