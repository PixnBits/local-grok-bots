//go:build !linux

package permbroker

import (
	"errors"
	"net"
)

// peerCred fails closed where SO_PEERCRED is not available. A socket
// that cannot name the peer is not an allow path.
func peerCred(net.Conn) (int, int, error) {
	return 0, 0, errors.New("peer credentials are not available")
}
