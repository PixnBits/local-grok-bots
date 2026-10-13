package sandbox

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestListenNetProxyConsultsAllowlist(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "proxy.sock")
	var got []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		got = append(got, addr)
		server, client := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, server)
			_ = server.Close()
		}()
		return client, nil
	}
	px, err := ListenNetProxy(context.Background(), sock, []string{"Allowed.Test."}, dial)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(px.Close)

	if !strings.HasPrefix(proxyLine(t, sock, "CONNECT allowed.test 443\n"), "OK") {
		t.Fatal("allowlisted connect was not accepted")
	}
	if proxyLine(t, sock, "CONNECT denied.test 80\n") != "DENY" {
		t.Fatal("denied host was accepted")
	}
	if len(got) != 1 || got[0] != "allowed.test:443" {
		t.Fatalf("dialed %#v", got)
	}
}

func proxyLine(t *testing.T, sock, line string) string {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(c, line); err != nil {
		t.Fatal(err)
	}
	var buf [8]byte
	n, err := c.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(buf[:n]))
}

func TestOpenCLIProxyFailsClosedWithoutCompiler(t *testing.T) {
	// The helper is exercised when a compiler exists. A failure must name the proxy.
	_, _, closeFn, err := OpenCLIProxy(context.Background(), t.TempDir(), nil, nil)
	if err != nil {
		if !strings.Contains(err.Error(), "proxy unavailable") {
			t.Fatal(err)
		}
		return
	}
	closeFn()
}
