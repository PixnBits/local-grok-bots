package sandbox

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProxyDialTimeout(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sock := filepath.Join(dir, "proxy.sock")
	p, err := startProxy(context.Background(), sock, []string{"net"}, []string{"example.com"}, nil, func(ctx context.Context, network, addr string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	if _, err := c.Write([]byte("CONNECT example.com 80\n")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
	buf := make([]byte, 32)
	n, err := c.Read(buf)
	elapsed := time.Since(start)
	if err != nil && n == 0 {
		t.Fatal(err)
	}
	if !strings.Contains(string(buf[:n]), "DENY") {
		t.Fatalf("reply %q", buf[:n])
	}
	if elapsed >= 13*time.Second {
		t.Fatalf("dial took %s", elapsed)
	}
	if elapsed < 8*time.Second {
		t.Fatalf("dial returned too fast: %s", elapsed)
	}
}
