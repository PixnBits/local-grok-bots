package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPAllowConnectionLimit(t *testing.T) {
	var audits atomic.Int32
	var records atomic.Int32
	var busyAudit atomic.Int32
	var busyRecord atomic.Int32
	p, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
		Allow: []string{"example.com"},
		Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			a, b := net.Pipe()
			go func() {
				_, _ = io.Copy(io.Discard, a)
				_ = a.Close()
			}()
			return b, nil
		},
		Audit: func(ev EgressEvent) {
			audits.Add(1)
			if !ev.Allow && ev.Reason == "busy" {
				busyAudit.Add(1)
			}
		},
		Record: func(ev Event) {
			records.Add(1)
			if ev.Kind == "grant_denied" && (ev.Detail == "busy" || strings.HasPrefix(ev.Detail, "busy ")) {
				busyRecord.Add(1)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	baseG := runtime.NumGoroutine()

	const n = 3000
	payload := bytes.Repeat([]byte("A"), 60<<10)
	conns := make([]net.Conn, 0, n)
	for i := 0; i < n; i++ {
		c, derr := net.Dial("unix", p.Sock())
		if derr != nil {
			t.Fatalf("dial %d: %v", i, derr)
		}
		conns = append(conns, c)
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Write(payload)
	}
	time.Sleep(200 * time.Millisecond)
	grew := runtime.NumGoroutine() - baseG
	runtime.GC()
	var during runtime.MemStats
	runtime.ReadMemStats(&during)
	heap := int64(during.HeapInuse) - int64(before.HeapInuse)
	if heap < 0 {
		heap = 0
	}

	var n503 atomic.Int32
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			br := bufio.NewReader(c)
			line, rerr := br.ReadString('\n')
			if rerr == nil && strings.Contains(line, "503") {
				n503.Add(1)
			}
		}(c)
	}
	wg.Wait()
	for _, c := range conns {
		_ = c.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p.slotMu.Lock()
		left := p.slots
		p.slotMu.Unlock()
		if left == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if n503.Load() < 1000 {
		t.Fatalf("503 responses %d, want a large share of %d", n503.Load(), n)
	}
	if grew >= 400 {
		t.Fatalf("goroutine growth %d (base %d)", grew, baseG)
	}
	if heap > 64<<20 {
		t.Fatalf("heap growth %d", heap)
	}
	if busyAudit.Load() < 1 || busyRecord.Load() < 1 {
		t.Fatalf("busy audit %d record %d", busyAudit.Load(), busyRecord.Load())
	}
	if busyAudit.Load() > 20 || busyRecord.Load() > 20 {
		t.Fatalf("busy audit %d record %d not rate-limited", busyAudit.Load(), busyRecord.Load())
	}

	up := listenLocal(t)
	defer up.Close()
	go func() {
		c, aerr := up.Accept()
		if aerr != nil {
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
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}()
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		return net.Dial("tcp", up.Addr().String())
	}
	body := proxyText(t, p.Sock(), "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if !strings.Contains(body, "200") {
		t.Fatalf("after flood: %q", body)
	}
}

func TestSpliceProxyConnectionLimit(t *testing.T) {
	sock := t.TempDir() + "/proxy.sock"
	dialed := make(chan struct{}, 1)
	p, err := startProxy(context.Background(), sock, []string{"net"}, []string{"example.com"}, nil, func(context.Context, string, string) (net.Conn, error) {
		select {
		case dialed <- struct{}{}:
		default:
		}
		a, b := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, a)
			_ = a.Close()
		}()
		return b, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	baseG := runtime.NumGoroutine()

	const n = 3000
	partial := bytes.Repeat([]byte("C"), 64)
	conns := make([]net.Conn, 0, n)
	for i := 0; i < n; i++ {
		c, derr := net.Dial("unix", sock)
		if derr != nil {
			t.Fatalf("dial %d: %v", i, derr)
		}
		conns = append(conns, c)
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Write(partial)
	}
	time.Sleep(200 * time.Millisecond)
	grew := runtime.NumGoroutine() - baseG
	runtime.GC()
	var during runtime.MemStats
	runtime.ReadMemStats(&during)
	heap := int64(during.HeapInuse) - int64(before.HeapInuse)
	if heap < 0 {
		heap = 0
	}

	var closed atomic.Int32
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			var one [1]byte
			_, rerr := c.Read(one[:])
			// A parked handler keeps the socket open, so the read times out.
			// A busy close returns EOF or a reset, sometimes after the unread
			// bytes the client already wrote.
			var ne net.Error
			if errors.As(rerr, &ne) && ne.Timeout() {
				return
			}
			if rerr != nil {
				closed.Add(1)
			}
		}(c)
	}
	wg.Wait()

	if closed.Load() < 1000 {
		t.Fatalf("closed without a handler %d", closed.Load())
	}
	if grew >= 400 {
		t.Fatalf("goroutine growth %d (base %d)", grew, baseG)
	}
	if heap > 64<<20 {
		t.Fatalf("heap growth %d", heap)
	}
	ev := p.drain()
	var busy int
	for _, e := range ev {
		if e.Kind == "grant_denied" && (e.Detail == "busy" || strings.HasPrefix(e.Detail, "busy ")) {
			busy++
		}
	}
	if busy < 1 || busy > 20 {
		t.Fatalf("busy events %d in %+v", busy, ev)
	}

	for _, c := range conns {
		_ = c.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p.slotMu.Lock()
		left := p.slots
		p.slotMu.Unlock()
		if left == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, "CONNECT example.com 443\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "OK") {
		t.Fatalf("after flood: %q", line)
	}
}
