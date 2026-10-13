package sandbox

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
)

// ProxyAvailable reports that this build can route a CLI through the sandbox proxy.
func ProxyAvailable() bool { return true }

// OpenCLIProxy compiles the connect interposer if needed and listens on
// dir/proxy.sock. The caller removes dir. Close stops the listener.
// A missing compiler fails closed.
func OpenCLIProxy(ctx context.Context, dir string, allow []string, dial func(context.Context, string, string) (net.Conn, error)) (preload, sock string, closeFn func(), err error) {
	preload, err = ensurePreload()
	if err != nil {
		return "", "", nil, fmt.Errorf("cli network proxy unavailable: %w", err)
	}
	sock = filepath.Join(dir, "proxy.sock")
	np, err := ListenNetProxy(ctx, sock, allow, dial)
	if err != nil {
		return "", "", nil, fmt.Errorf("cli network proxy unavailable: %w", err)
	}
	return preload, sock, np.Close, nil
}
