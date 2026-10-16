package sandbox

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHTTPAllowProxyFiltersTargets(t *testing.T) {
	up := listenLocal(t)
	defer up.Close()
	got := make(chan string, 4)
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 256)
		n, _ := c.Read(buf)
		got <- string(buf[:n])
		_, _ = c.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
	}()
	var dialed []string
	p, err := StartHTTPAllowProxy(t.TempDir(), []string{"Allowed.Test."}, func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return net.Dial("tcp", up.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	st, err := os.Stat(p.Sock())
	if err != nil || filepath.Base(p.Sock()) != "sock" || st.Mode().Perm() != 0o600 {
		t.Fatalf("sock %s %v %v", p.Sock(), st, err)
	}
	body := proxyText(t, p.Sock(), "GET http://allowed.test/ok HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	if !strings.Contains(body, "204") {
		t.Fatalf("allow %q", body)
	}
	select {
	case line := <-got:
		if !strings.Contains(line, "GET /ok ") {
			t.Fatalf("upstream %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream saw nothing")
	}
	if len(dialed) != 1 || dialed[0] != "allowed.test:80" {
		t.Fatalf("dialed %v", dialed)
	}
	for _, req := range []string{
		"GET http://other.test/no HTTP/1.1\r\nHost: other.test\r\n\r\n",
		"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n",
		"CONNECT 10.1.2.3:443 HTTP/1.1\r\nHost: 10.1.2.3:443\r\n\r\n",
		"CONNECT 172.16.0.1:443 HTTP/1.1\r\nHost: 172.16.0.1:443\r\n\r\n",
		"CONNECT 169.254.1.1:443 HTTP/1.1\r\nHost: 169.254.1.1:443\r\n\r\n",
		"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n",
		"GET /relative HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
		"GET http://user:pass@allowed.test/x HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
	} {
		body = proxyText(t, p.Sock(), req)
		if !strings.Contains(body, "403") {
			t.Fatalf("expected deny for %q got %q", req, body)
		}
	}
	if len(dialed) != 1 {
		t.Fatalf("denied target was dialed %v", dialed)
	}
}

func TestHTTPAllowEmptyListDenies(t *testing.T) {
	p, err := StartHTTPAllowProxy(t.TempDir(), nil, func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("empty allowlist dialed")
		return nil, io.EOF
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	body := proxyText(t, p.Sock(), "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
	if !strings.Contains(body, "403") {
		t.Fatalf("body %q", body)
	}
}

func TestForbiddenIP(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "169.254.1.1", "::1", "0.0.0.0", "224.0.0.1"} {
		if !forbiddenIP(net.ParseIP(s)) {
			t.Fatalf("%s should be refused", s)
		}
	}
	if forbiddenIP(net.ParseIP("203.0.113.1")) {
		t.Fatal("documentation address was treated as local")
	}
}

func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func proxyText(t *testing.T, sock, req string) string {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b, err := io.ReadAll(c)
	if err != nil && len(b) == 0 {
		t.Fatal(err)
	}
	return string(b)
}
