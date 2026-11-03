package sandbox

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPAllowHeaderCap(t *testing.T) {
	t.Run("too large", func(t *testing.T) {
		var dialed atomic.Int32
		p, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
			Allow: []string{"example.com"},
			Dial: func(context.Context, string, string) (net.Conn, error) {
				dialed.Add(1)
				return nil, io.ErrClosedPipe
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		c, err := net.Dial("unix", p.Sock())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		payload := []byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Pad: " + strings.Repeat("a", 1<<20) + "\r\n\r\n")
		var wroteAll atomic.Bool
		errc := make(chan error, 1)
		go func() {
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			n, werr := c.Write(payload)
			if werr == nil && n == len(payload) {
				wroteAll.Store(true)
			}
			errc <- werr
		}()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(c)
		line, rerr := br.ReadString('\n')
		if rerr != nil {
			t.Fatalf("read: %v", rerr)
		}
		if !strings.Contains(line, "431") || !strings.Contains(line, "Request Header Fields Too Large") {
			t.Fatalf("status %q", line)
		}
		if wroteAll.Load() {
			t.Fatal("proxy buffered the whole request before answering")
		}
		// The response arrived while the client still had bytes to write.
		select {
		case <-errc:
		case <-time.After(2 * time.Second):
		}
		if wroteAll.Load() {
			t.Fatal("client finished writing the 1MiB request")
		}
		if dialed.Load() != 0 {
			t.Fatalf("dialed %d", dialed.Load())
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := io.Copy(io.Discard, br); err != nil && err != io.EOF {
			// A closed connection is the expected end.
		}
	})

	t.Run("eight kibibytes", func(t *testing.T) {
		ln := listenLocal(t)
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			br := bufio.NewReader(c)
			for {
				line, rerr := br.ReadString('\n')
				if rerr != nil || line == "\r\n" {
					break
				}
			}
			_, _ = io.WriteString(c, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		}()
		var dialed atomic.Int32
		p, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
			Allow: []string{"example.com"},
			Resolve: func(context.Context, string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("203.0.113.10")}, nil
			},
			Dial: func(context.Context, string, string) (net.Conn, error) {
				dialed.Add(1)
				return net.Dial("tcp", ln.Addr().String())
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		pad := strings.Repeat("b", 8<<10)
		req := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Pad: " + pad + "\r\n\r\n"
		body := proxyText(t, p.Sock(), req)
		if !strings.Contains(body, "204") {
			t.Fatalf("body %q dialed %d", body, dialed.Load())
		}
		if dialed.Load() != 1 {
			t.Fatalf("dialed %d", dialed.Load())
		}
	})
}

func TestLiteralForbiddenIPAfterAllow(t *testing.T) {
	var dialed atomic.Int32
	var mu sync.Mutex
	var events []Event
	p, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
		Decide: func(host string, port int) (bool, Event) {
			return true, Event{Kind: "grant_use", Grant: "net", Host: host}
		},
		Record: func(ev Event) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dialed.Add(1)
			return nil, io.ErrClosedPipe
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	checks := []struct {
		host    string
		connect string
		http    string
	}{
		{"127.0.0.1", "127.0.0.1", "127.0.0.1"},
		{"::1", "[::1]", "[::1]"},
	}
	for _, tc := range checks {
		body := proxyText(t, p.Sock(), "GET http://"+tc.http+"/ HTTP/1.1\r\nHost: "+tc.http+"\r\n\r\n")
		if !strings.Contains(body, "403") {
			t.Fatalf("GET %s: %q", tc.host, body)
		}
		line := doConnect(t, p.Sock(), tc.connect, nil)
		if !strings.Contains(line, "403") {
			t.Fatalf("CONNECT %s: %q", tc.host, line)
		}
	}
	if dialed.Load() != 0 {
		t.Fatalf("dialed %d", dialed.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	var hits int
	for _, ev := range events {
		if ev.Kind == "grant_denied" && ev.Detail == "address" {
			hits++
		}
	}
	if hits != 4 {
		t.Fatalf("events %+v", events)
	}
}
