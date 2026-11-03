package sandbox

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPAllowDenyAuditRateLimited(t *testing.T) {
	const n = 2000
	denyReq := "GET http://nope.test/x HTTP/1.1\r\nHost: nope.test\r\n\r\n"
	headerReq := "GET http://nope.test/x HTTP/1.1\r\nHost: nope.test\r\nX-Pad: " + strings.Repeat("a", httpHeaderMax) + "\r\n\r\n"

	check := func(t *testing.T, audits []EgressEvent, reason string, sent int) {
		t.Helper()
		var calls, sum int
		for _, ev := range audits {
			if ev.Allow || ev.Reason != reason {
				continue
			}
			calls++
			sum += ev.Count
		}
		// Close flushes the last partial second, so the sum matches the requests.
		if calls > 5 {
			t.Fatalf("%s audits %d", reason, calls)
		}
		if sum != sent {
			t.Fatalf("%s count %d sent %d calls %d", reason, sum, sent, calls)
		}
	}

	t.Run("cli", func(t *testing.T) {
		var mu sync.Mutex
		var audits []EgressEvent
		p := startBoundProxy(t, EgressConfig{
			Allow: []string{"allowed.test"},
			Audit: func(ev EgressEvent) {
				mu.Lock()
				audits = append(audits, ev)
				mu.Unlock()
			},
		})
		if err := burstProxy(p.Sock(), denyReq, n); err != nil {
			t.Fatal(err)
		}
		if err := burstProxy(p.Sock(), headerReq, n); err != nil {
			t.Fatal(err)
		}
		p.Close()
		mu.Lock()
		got := append([]EgressEvent(nil), audits...)
		mu.Unlock()
		check(t, got, "host", n)
		check(t, got, "header", n)
	})

	t.Run("decide", func(t *testing.T) {
		var mu sync.Mutex
		var audits []EgressEvent
		var records []Event
		p := startBoundProxy(t, EgressConfig{
			Decide: func(host string, port int) (bool, Event) {
				return false, Event{Kind: "net_request", Grant: "net", Host: host, Detail: "not allowlisted"}
			},
			Record: func(ev Event) {
				mu.Lock()
				records = append(records, ev)
				mu.Unlock()
			},
			Audit: func(ev EgressEvent) {
				mu.Lock()
				audits = append(audits, ev)
				mu.Unlock()
			},
		})
		if err := burstProxy(p.Sock(), denyReq, n); err != nil {
			t.Fatal(err)
		}
		if err := burstProxy(p.Sock(), headerReq, n); err != nil {
			t.Fatal(err)
		}
		p.Close()
		mu.Lock()
		gotAudit := append([]EgressEvent(nil), audits...)
		gotRec := append([]Event(nil), records...)
		mu.Unlock()
		check(t, gotAudit, "host", n)
		check(t, gotAudit, "header", n)
		var headerCalls, headerSum, hostRec int
		for _, ev := range gotRec {
			if ev.Detail == "header" {
				headerCalls++
				headerSum += ev.Count
				continue
			}
			hostRec++
		}
		if headerCalls > 5 || headerSum != n {
			t.Fatalf("header records calls %d sum %d", headerCalls, headerSum)
		}
		if hostRec != n {
			t.Fatalf("host records %d", hostRec)
		}
	})
}

func startBoundProxy(t *testing.T, cfg EgressConfig) *HTTPAllow {
	t.Helper()
	p, err := StartHTTPAllowProxy(t.TempDir(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func burstProxy(sock, req string, n int) error {
	const workers = 32
	jobs := make(chan int, n)
	var wg sync.WaitGroup
	errc := make(chan error, 1)
	var once sync.Once
	fail := func(err error) {
		if err != nil {
			once.Do(func() { errc <- err })
		}
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				fail(oneProxyReq(sock, req))
			}
		}()
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	select {
	case err := <-errc:
		return err
	default:
		return nil
	}
}

func oneProxyReq(sock, req string) error {
	c, err := net.Dial("unix", sock)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, req)
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(line, "403") && !strings.Contains(line, "431") {
		return errStatus(line)
	}
	return nil
}

type errStatus string

func (e errStatus) Error() string { return "status " + string(e) }

func TestHTTPAllowPlainHTTPReleasesSlot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	p, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
		Allow: []string{"allowed.test"},
		Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return net.Dial("tcp", srv.Listener.Addr().String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		done := make(chan struct{})
		go func() {
			p.Close()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}()
	for i := 0; i < 300; i++ {
		code, body, err := plainProxyStatus(p.Sock())
		if err != nil {
			t.Fatalf("req %d: %v", i, err)
		}
		if code != 200 || body != "ok" {
			t.Fatalf("req %d: %d %q", i, code, body)
		}
	}
}

func plainProxyStatus(sock string) (int, string, error) {
	c, err := net.Dial("unix", sock)
	if err != nil {
		return 0, "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n"); err != nil {
		return 0, "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(b), nil
}

func TestHTTPAllowCloseClosesUpstreams(t *testing.T) {
	var open atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			open.Add(1)
		case http.StateClosed:
			open.Add(-1)
		}
	}
	srv.Start()
	defer srv.Close()
	p, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
		Allow: []string{"allowed.test"},
		Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return net.Dial("tcp", srv.Listener.Addr().String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := runtime.NumGoroutine()
	for i := 0; i < 4; i++ {
		code, _, err := plainProxyStatus(p.Sock())
		if err != nil || code != 200 {
			t.Fatalf("plain %d: %v code %d", i, err, code)
		}
	}
	c, err := net.Dial("unix", p.Sock())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("connect %q", line)
	}
	// Drop the read deadline so the held client stays open until Close.
	_ = c.SetDeadline(time.Time{})
	deadline := time.Now().Add(2 * time.Second)
	for open.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if open.Load() < 1 {
		t.Fatalf("upstream open %d before close", open.Load())
	}
	finished := make(chan struct{})
	go func() {
		p.Close()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return")
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if open.Load() == 0 && runtime.NumGoroutine() <= base+2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("open %d goroutines %d base %d", open.Load(), runtime.NumGoroutine(), base)
}

func TestHTTPAllowDenyAuditPerHost(t *testing.T) {
	const n = 500
	hosts := []string{"a.denied.test", "b.denied.test"}
	var mu sync.Mutex
	var audits []EgressEvent
	p := startBoundProxy(t, EgressConfig{
		Allow: []string{"allowed.test"},
		Audit: func(ev EgressEvent) {
			mu.Lock()
			audits = append(audits, ev)
			mu.Unlock()
		},
	})
	reqs := make([]string, 0, n*len(hosts))
	for i := 0; i < n; i++ {
		for _, host := range hosts {
			reqs = append(reqs, denyReq(host))
		}
	}
	if err := burstRequests(p.Sock(), reqs); err != nil {
		t.Fatal(err)
	}
	p.Close()
	mu.Lock()
	got := append([]EgressEvent(nil), audits...)
	mu.Unlock()
	for _, host := range hosts {
		var calls, sum int
		for _, ev := range got {
			if ev.Allow || ev.Host != host {
				continue
			}
			calls++
			sum += ev.Count
		}
		if calls > 5 {
			t.Fatalf("%s audits %d", host, calls)
		}
		if sum != n {
			t.Fatalf("%s count %d sent %d calls %d", host, sum, n, calls)
		}
	}
}

func TestHTTPAllowDenyAuditSlotBound(t *testing.T) {
	const hosts = reasonSlotMax + 40
	const each = 2
	var mu sync.Mutex
	var audits []EgressEvent
	p := startBoundProxy(t, EgressConfig{
		Allow: []string{"allowed.test"},
		Audit: func(ev EgressEvent) {
			mu.Lock()
			audits = append(audits, ev)
			mu.Unlock()
		},
	})
	reqs := make([]string, 0, hosts*each)
	for i := 0; i < hosts; i++ {
		req := denyReq(fmt.Sprintf("h%d.denied.test", i))
		for j := 0; j < each; j++ {
			reqs = append(reqs, req)
		}
	}
	if err := burstRequests(p.Sock(), reqs); err != nil {
		t.Fatal(err)
	}
	p.Close()
	mu.Lock()
	got := append([]EgressEvent(nil), audits...)
	mu.Unlock()
	var sum int
	for _, ev := range got {
		if ev.Allow {
			continue
		}
		sum += ev.Count
	}
	if sum != hosts*each {
		t.Fatalf("count %d sent %d", sum, hosts*each)
	}
	p.denies.mu.Lock()
	nslots := len(p.denies.slots)
	p.denies.mu.Unlock()
	if nslots == 0 || nslots > reasonSlotMax {
		t.Fatalf("slots %d", nslots)
	}
}

func TestReasonNoteRecordKeepsSlot(t *testing.T) {
	var n reasonNote
	for i := 0; i < reasonSlotMax; i++ {
		if _, ok := n.mark("host", fmt.Sprintf("h%d.denied.test", i), 80, nil); !ok {
			t.Fatalf("first mark %d", i)
		}
	}
	rec := Event{Kind: "grant_denied", Host: "rec.denied.test", Detail: "kept"}
	em, ok := n.mark("host", "rec.denied.test", 80, &rec)
	if !ok || !em.doRec || em.host != "rec.denied.test" || em.port != 80 || em.count != 1 {
		t.Fatalf("record emit ok %v host %s port %d count %d rec %v", ok, em.host, em.port, em.count, em.doRec)
	}
	if em.record.Detail != "kept" || em.record.Count != 1 {
		t.Fatalf("record detail %s count %d", em.record.Detail, em.record.Count)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.slots) > reasonSlotMax {
		t.Fatalf("slots %d", len(n.slots))
	}
	if _, ok := n.slots[reasonKey{"host", "rec.denied.test", 80}]; !ok {
		t.Fatal("record slot missing")
	}
}

func TestHTTPAllowPlainHTTPExpectContinue(t *testing.T) {
	const body = "continue-body"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(b)
	}))
	defer srv.Close()
	p, err := StartHTTPAllowProxy(t.TempDir(), EgressConfig{
		Allow: []string{"allowed.test"},
		Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return net.Dial("tcp", srv.Listener.Addr().String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	code, got, err := plainProxyPost(p.Sock(), body)
	if err != nil {
		t.Fatal(err)
	}
	if code != 200 || got != body {
		t.Fatalf("code %d body %q", code, got)
	}
}

func denyReq(host string) string {
	return "GET http://" + host + "/x HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
}

func burstRequests(sock string, reqs []string) error {
	const workers = 32
	jobs := make(chan string, len(reqs))
	var wg sync.WaitGroup
	errc := make(chan error, 1)
	var once sync.Once
	fail := func(err error) {
		if err != nil {
			once.Do(func() { errc <- err })
		}
	}
	n := workers
	if n > len(reqs) {
		n = len(reqs)
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range jobs {
				fail(oneProxyReq(sock, req))
			}
		}()
	}
	for _, req := range reqs {
		jobs <- req
	}
	close(jobs)
	wg.Wait()
	select {
	case err := <-errc:
		return err
	default:
		return nil
	}
}

func plainProxyPost(sock, body string) (int, string, error) {
	c, err := net.Dial("unix", sock)
	if err != nil {
		return 0, "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	req := fmt.Sprintf("POST http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: %d\r\nExpect: 100-continue\r\n\r\n%s", len(body), body)
	if _, err := io.WriteString(c, req); err != nil {
		return 0, "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(b), nil
}
