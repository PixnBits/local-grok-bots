package sandbox

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
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
	p, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
		Allow: []string{"Allowed.Test."},
		Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		},
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			return net.Dial("tcp", up.Addr().String())
		},
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
	if len(dialed) != 1 || dialed[0] != "203.0.113.10:80" {
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
	p, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
		Dial: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("empty allowlist dialed")
			return nil, io.EOF
		},
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
	for _, s := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1", "169.254.1.1", "::1",
		"0.0.0.0", "0.8.8.8", "224.0.0.1", "100.64.0.1", "100.127.255.254",
		"198.18.0.1", "198.19.255.1",
		"64:ff9b::192.0.2.1", "2002:c000:201::",
		"::ffff:10.1.2.3", "::ffff:172.16.0.1", "::ffff:192.168.0.1",
		"::ffff:100.64.0.1", "::ffff:0.1.2.3", "::ffff:198.18.0.1",
		"::ffff:127.0.0.1", "::ffff:169.254.1.1", "::ffff:224.0.0.1",
		"fe80::1", "fc00::1",
	} {
		if !forbiddenIP(net.ParseIP(s)) {
			t.Fatalf("%s should be refused", s)
		}
	}
	for _, s := range []string{
		"203.0.113.1", "192.0.2.1", "198.51.100.1", "2001:db8::1",
		"::ffff:203.0.113.1", "100.128.0.1", "100.63.255.255",
		"64:ff9b:1::192.0.2.1",
	} {
		if ip := net.ParseIP(s); ip == nil || forbiddenIP(ip) {
			t.Fatalf("%s should be dialable", s)
		}
	}
}

func TestResolvedAddressesAreRefused(t *testing.T) {
	refused := []string{
		"100.64.0.1", "100.127.255.254", "0.0.0.0", "0.8.8.8",
		"198.18.0.1", "198.19.255.1", "64:ff9b::192.0.2.1", "2002:c000:201::",
		"::ffff:10.1.2.3", "::ffff:172.16.0.1", "::ffff:192.168.0.1",
		"::ffff:100.64.0.1", "::ffff:0.1.2.3", "::ffff:198.18.0.1",
		"::ffff:127.0.0.1", "::ffff:169.254.1.1",
		"10.1.2.3", "172.16.0.1", "172.31.255.1", "192.168.0.1",
		"127.0.0.1", "::1", "169.254.1.1", "fe80::1",
	}
	var current net.IP
	var dialed []string
	var lookups int
	p, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
		Allow: []string{"allowed.test"},
		Resolve: func(context.Context, string) ([]net.IP, error) {
			lookups++
			if lookups > 1 {
				return []net.IP{net.ParseIP("10.1.2.3")}, nil
			}
			return []net.IP{append(net.IP(nil), current...)}, nil
		},
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			return nil, io.EOF
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, s := range refused {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("parse %s", s)
		}
		current = ip
		lookups = 0
		dialed = nil
		body := proxyText(t, p.Sock(), "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
		if !strings.Contains(body, "403") || len(dialed) != 0 || lookups != 1 {
			t.Fatalf("%s body %q dialed %v lookups %d", s, body, dialed, lookups)
		}
	}
}

func TestDialUsesTheCheckedIPOnce(t *testing.T) {
	var lookups int
	var dialed []string
	p, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
		Allow: []string{"allowed.test"},
		Resolve: func(context.Context, string) ([]net.IP, error) {
			lookups++
			if lookups > 1 {
				return []net.IP{net.ParseIP("10.1.2.3")}, nil
			}
			return []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("203.0.113.10")}, nil
		},
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			return nil, io.EOF
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	body := proxyText(t, p.Sock(), "GET http://allowed.test/ok HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	if !strings.Contains(body, "403") {
		t.Fatalf("body %q", body)
	}
	if lookups != 1 || len(dialed) != 1 || dialed[0] != "192.0.2.10:80" {
		t.Fatalf("lookups %d dialed %v", lookups, dialed)
	}
	lookups = 0
	dialed = nil
	p2, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
		Allow: []string{"allowed.test"},
		Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("10.1.2.3")}, nil
		},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("mixed answer was dialed")
			return nil, io.EOF
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	body = proxyText(t, p2.Sock(), "GET http://allowed.test/ok HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	if !strings.Contains(body, "403") {
		t.Fatalf("mixed %q", body)
	}
}

func TestListedLiteralSpecialRangesAreRefused(t *testing.T) {
	for _, s := range []string{"100.64.0.1", "0.1.2.3", "198.18.0.1", "10.9.8.7", "192.168.0.8", "169.254.1.1"} {
		p, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
			Allow: []string{s},
			Dial: func(context.Context, string, string) (net.Conn, error) {
				t.Fatalf("dialed %s", s)
				return nil, io.EOF
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		body := proxyText(t, p.Sock(), "CONNECT "+s+":443 HTTP/1.1\r\nHost: "+s+":443\r\n\r\n")
		p.Close()
		if !strings.Contains(body, "403") {
			t.Fatalf("%s %q", s, body)
		}
	}
}

func TestEgressPortsDefaultAndNarrow(t *testing.T) {
	var dialed int
	p, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
		Allow: []string{"allowed.test"},
		Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dialed++
			return nil, io.EOF
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, req := range []string{
		"CONNECT allowed.test:22 HTTP/1.1\r\nHost: allowed.test:22\r\n\r\n",
		"GET http://allowed.test:8080/x HTTP/1.1\r\nHost: allowed.test:8080\r\n\r\n",
	} {
		body := proxyText(t, p.Sock(), req)
		if !strings.Contains(body, "403") {
			t.Fatalf("port %q", body)
		}
	}
	if dialed != 0 {
		t.Fatalf("closed port dialed %d", dialed)
	}
	narrow, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
		Allow: []string{"allowed.test"},
		Ports: []int{443},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("port 80 dialed")
			return nil, io.EOF
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer narrow.Close()
	body := proxyText(t, narrow.Sock(), "GET http://allowed.test/ok HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	if !strings.Contains(body, "403") {
		t.Fatalf("narrow %q", body)
	}
	none, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
		Allow: []string{"allowed.test"},
		Ports: []int{},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("empty port list dialed")
			return nil, io.EOF
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer none.Close()
	body = proxyText(t, none.Sock(), "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
	if !strings.Contains(body, "403") {
		t.Fatalf("empty ports %q", body)
	}
}

func TestConnectRequiresMatchingSNI(t *testing.T) {
	match := clientHello(t, "allowed.test")
	other := clientHello(t, "other.test")
	folded := clientHello(t, "Allowed.Test")
	missing := clientHello(t, "")
	for _, tc := range []struct {
		name   string
		hello  []byte
		reason string
		allow  bool
	}{
		{"match", match, "ok", true},
		{"folded", folded, "ok", true},
		{"mismatch", other, "sni-mismatch", false},
		{"missing", missing, "sni-missing", false},
		{"garbage", []byte("not a client hello"), "sni-missing", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := listenLocal(t)
			defer up.Close()
			got := make(chan []byte, 1)
			go func() {
				c, err := up.Accept()
				if err != nil {
					got <- []byte("accept-failed")
					return
				}
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				buf := make([]byte, 8192)
				n, _ := c.Read(buf)
				got <- append([]byte(nil), buf[:n]...)
			}()
			evCh := make(chan EgressEvent, 1)
			p, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
				Allow: []string{"allowed.test"},
				Resolve: func(context.Context, string) ([]net.IP, error) {
					return []net.IP{net.ParseIP("203.0.113.10")}, nil
				},
				Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
					if addr != "203.0.113.10:443" {
						return nil, io.EOF
					}
					return net.Dial("tcp", up.Addr().String())
				},
				Audit: func(ev EgressEvent) { evCh <- ev },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			status := doConnect(t, p.Sock(), "allowed.test", tc.hello)
			if !strings.Contains(status, "200") {
				t.Fatalf("status %q", status)
			}
			select {
			case raw := <-got:
				if tc.allow {
					if string(raw) != string(tc.hello) {
						t.Fatalf("forwarded %d bytes, hello %d", len(raw), len(tc.hello))
					}
				} else if len(raw) != 0 {
					t.Fatalf("denied hello was forwarded (%d bytes)", len(raw))
				}
			case <-time.After(2 * time.Second):
				t.Fatal("upstream timed out")
			}
			select {
			case ev := <-evCh:
				if ev.Allow != tc.allow || ev.Reason != tc.reason || ev.Host != "allowed.test" || ev.Port != 443 {
					t.Fatalf("audit %+v", ev)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no audit")
			}
		})
	}
}

func TestEgressAuditOmitsRequestBytes(t *testing.T) {
	const marker = "unit-header-marker"
	var events []EgressEvent
	p, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
		Allow: []string{"allowed.test"},
		Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, io.EOF
		},
		Audit: func(ev EgressEvent) { events = append(events, ev) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	body := proxyText(t, p.Sock(), "GET http://allowed.test/ok HTTP/1.1\r\nHost: allowed.test\r\nX-Secret: "+marker+"\r\n\r\n"+marker)
	if !strings.Contains(body, "403") || len(events) != 1 || events[0].Reason != "dial" || events[0].Allow {
		t.Fatalf("body %q events %+v", body, events)
	}
	text := events[0].Host + events[0].Reason
	if strings.Contains(text, marker) || strings.Contains(text, "X-Secret") {
		t.Fatalf("audit kept request bytes %+v", events[0])
	}
}

func TestPythonClientHelloSNI(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(c, hdr); err != nil {
			got <- nil
			return
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n < 1 || n > 16384 {
			got <- nil
			return
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(c, body); err != nil {
			got <- nil
			return
		}
		got <- append(hdr, body...)
	}()
	script := fmt.Sprintf(`
import socket, ssl
s = socket.create_connection(("127.0.0.1", %d), timeout=2)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    ctx.wrap_socket(s, server_hostname="allowed.test")
except Exception:
    pass
`, port)
	cmd := exec.Command("python3", "-c", script)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	select {
	case rec := <-got:
		if len(rec) == 0 {
			t.Fatal("no client hello")
		}
		name, clean := clientHelloSNI(rec)
		if !clean || name != "allowed.test" {
			t.Fatalf("python hello clean=%v name=%q len=%d", clean, name, len(rec))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}
}

func clientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	errCh := make(chan error, 1)
	go func() {
		cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
		errCh <- tls.Client(client, cfg).Handshake()
	}()
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(server, hdr); err != nil {
		t.Fatal(err)
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	body := make([]byte, n)
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	_ = client.Close()
	<-errCh
	return append(hdr, body...)
}

func doConnect(t *testing.T, sock, host string, hello []byte) string {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req := "CONNECT " + host + ":443 HTTP/1.1\r\nHost: " + host + ":443\r\nX-Secret: unit-header-marker\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" {
			break
		}
	}
	if len(hello) > 0 {
		if _, err := c.Write(hello); err != nil {
			t.Fatal(err)
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = io.Copy(io.Discard, br)
	return line
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
