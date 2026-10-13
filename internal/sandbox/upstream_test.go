package sandbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpstreamProxyHonoursAllowlistAndHidesSecrets(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	proxyAddr := ln.Addr().String()
	secret := "s3cret"
	token := base64.StdEncoding.EncodeToString([]byte("user:" + secret))
	gotReq := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		var buf []byte
		one := []byte{0}
		for len(buf) < 2048 {
			n, err := c.Read(one)
			if n == 1 {
				buf = append(buf, one[0])
				if strings.HasSuffix(string(buf), "\r\n\r\n") {
					break
				}
			}
			if err != nil {
				break
			}
		}
		gotReq <- string(buf)
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, _ = io.Copy(io.Discard, c)
	}()

	var dialed []string
	base := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		if addr == proxyAddr {
			return net.Dial(network, addr)
		}
		server, client := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, server)
			_ = server.Close()
		}()
		return client, nil
	}
	up := Upstream{
		HTTPProxy:  "http://user:" + secret + "@" + proxyAddr,
		HTTPSProxy: "http://user:" + secret + "@" + proxyAddr,
		NoProxy:    "direct.test",
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "proxy.sock")
	px, err := ListenNetProxy(context.Background(), sock, []string{"allowed.test", "direct.test"}, base)
	if err != nil {
		t.Fatal(err)
	}
	defer px.Close()
	px.UseUpstream(up)
	var events []Event
	px.SetObserver(func(ev Event) { events = append(events, ev) })

	if !strings.HasPrefix(proxyLine(t, sock, "CONNECT allowed.test 443\n"), "OK") {
		t.Fatal("allowlisted connect was not accepted")
	}
	select {
	case req := <-gotReq:
		if !strings.Contains(req, "CONNECT allowed.test:443") || !strings.Contains(req, "Proxy-Authorization: Basic "+token) {
			t.Fatalf("request %q", req)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("corporate proxy was not contacted")
	}
	if !strings.HasPrefix(proxyLine(t, sock, "CONNECT direct.test 80\n"), "OK") {
		t.Fatal("NO_PROXY host was not dialed directly")
	}
	if proxyLine(t, sock, "CONNECT denied.test 80\n") != "DENY" {
		t.Fatal("denied host was accepted")
	}
	if len(dialed) != 2 || dialed[0] != proxyAddr || dialed[1] != "direct.test:80" {
		t.Fatalf("dialed %#v", dialed)
	}
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), token) {
		t.Fatalf("event log leaked credentials: %s", raw)
	}
	if !strings.Contains(string(raw), "via "+proxyAddr) || !strings.Contains(string(raw), "direct") || !strings.Contains(string(raw), "denied.test") {
		t.Fatalf("events %s", raw)
	}
}

func TestDisabledUpstreamDialsTheDestination(t *testing.T) {
	var got []string
	base := func(ctx context.Context, network, addr string) (net.Conn, error) {
		got = append(got, addr)
		server, client := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, server)
			_ = server.Close()
		}()
		return client, nil
	}
	dial := Upstream{}.Wrap(base)
	if _, err := dial(context.Background(), "tcp", "allowed.test:443"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "allowed.test:443" {
		t.Fatalf("%#v", got)
	}
}
