package coi

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestEgressReplacesBearer(t *testing.T) {
	var gotAuth, gotHost string
	trip := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotAuth = r.Header.Get("Authorization")
		gotHost = r.URL.Host
		return &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
		}, nil
	})
	eg, err := StartEgress(t.TempDir(), []string{"api.test"}, nil, "real-token-value", trip)
	if err != nil {
		t.Fatal(err)
	}
	defer eg.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveBridge(ln, eg.Sock())
	req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/v1/ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+PlaceholderToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	if gotAuth != "Bearer real-token-value" || strings.Contains(gotAuth, PlaceholderToken) {
		t.Fatalf("auth %q", gotAuth)
	}
	if gotHost != "api.test" {
		t.Fatalf("host %q", gotHost)
	}
	deny, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	deny.Host = "evil.example"
	resp, err = http.DefaultClient.Do(deny)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("evil status %d", resp.StatusCode)
	}
}

func TestLoopbackReplacesBearer(t *testing.T) {
	var gotAuth string
	var calls atomic.Int32
	trip := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		gotAuth = r.Header.Get("Authorization")
		if r.URL == nil || r.URL.Path != "/v1/ping" {
			t.Errorf("upstream path %v", r.URL)
		}
		if r.Header.Get("X-Secret") != "" || r.Header.Get("Cookie") != "" {
			t.Errorf("forwarded a stripped header")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	reads := 0
	eg, err := StartLoopback([]string{GrokChatHost}, nil, func() (string, error) {
		reads++
		return "real-token-value", nil
	}, trip)
	if err != nil {
		t.Fatal(err)
	}
	defer eg.Close()
	base := eg.Base()
	if !strings.HasPrefix(base, "http://127.0.0.1:") {
		t.Fatalf("base %q", base)
	}
	host, port, err := net.SplitHostPort(strings.TrimPrefix(base, "http://"))
	if err != nil || host != "127.0.0.1" || port == "" || port == "0" {
		t.Fatalf("listen %q", base)
	}
	ifaces, _ := net.InterfaceAddrs()
	for _, addr := range ifaces {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP == nil || ipnet.IP.IsLoopback() || ipnet.IP.To4() == nil {
			continue
		}
		conn, dialErr := net.DialTimeout("tcp", ipnet.IP.String()+":"+port, 200*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			t.Fatalf("proxy accepted %s", ipnet.IP)
		}
	}
	const gate = "unit-loopback-gate1"
	stop := eg.Admit("bot-a", "run-1", gate)
	req, err := http.NewRequest(http.MethodGet, base+"/bots/bot-a/runs/run-1/v1/ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+gate)
	req.Header.Set("X-Secret", "nope")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "ok" || calls.Load() != 1 {
		t.Fatalf("status %d body %s calls %d", resp.StatusCode, body, calls.Load())
	}
	if gotAuth != "Bearer real-token-value" || strings.Contains(gotAuth, gate) || strings.Contains(gotAuth, PlaceholderToken) {
		t.Fatalf("auth replaced incorrectly")
	}
	before := calls.Load()
	beforeReads := reads
	for _, auth := range []string{"", "Bearer " + PlaceholderToken, "Bearer real-token-value", "Token " + gate} {
		deny, err := http.NewRequest(http.MethodGet, base+"/bots/bot-a/runs/run-1/v1/ping", nil)
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			deny.Header.Set("Authorization", auth)
		}
		resp, err = http.DefaultClient.Do(deny)
		if err != nil {
			t.Fatal(err)
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || strings.Contains(string(body), "real-token-value") || strings.Contains(string(body), gate) {
			t.Fatalf("auth %q status %d body %s", auth, resp.StatusCode, body)
		}
	}
	if calls.Load() != before || reads != beforeReads {
		t.Fatalf("rejected client reached upstream calls=%d reads=%d", calls.Load(), reads)
	}
	for _, p := range []string{"/admin", "/v1/../x", "/v2/x"} {
		deny, err := http.NewRequest(http.MethodGet, base+p, nil)
		if err != nil {
			t.Fatal(err)
		}
		deny.Header.Set("Authorization", "Bearer "+gate)
		resp, err = http.DefaultClient.Do(deny)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s status %d", p, resp.StatusCode)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("denied path reached upstream: %d", calls.Load())
	}
	if reads != 2 {
		t.Fatalf("bearer reads %d", reads)
	}
	stop()
	revoked, err := http.NewRequest(http.MethodGet, base+"/bots/bot-a/runs/run-1/v1/ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	revoked.Header.Set("Authorization", "Bearer "+gate)
	resp, err = http.DefaultClient.Do(revoked)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || calls.Load() != 1 || reads != 2 {
		t.Fatalf("revoked status %d calls %d reads %d", resp.StatusCode, calls.Load(), reads)
	}
	stop()
}

func TestLoopbackRejectsMismatchedBotRun(t *testing.T) {
	var calls atomic.Int32
	var gotPath string
	trip := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL != nil {
			gotPath = r.URL.Path
		}
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	eg, err := StartLoopback([]string{GrokChatHost}, nil, func() (string, error) {
		return "real-token-value", nil
	}, trip)
	if err != nil {
		t.Fatal(err)
	}
	defer eg.Close()
	base := eg.Base()
	const a = "unit-gate-bot-a-0001"
	const b = "unit-gate-bot-b-0002"
	stopA := eg.Admit("bot-a", "run-1", a)
	stopB := eg.Admit("bot-b", "run-2", b)
	defer stopB()
	client := &http.Client{Timeout: 2 * time.Second}
	code := func(url, bearer string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, url, strings.NewReader(`{"n":1}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("X-Secret", bearer)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		buf, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(buf), bearer) || strings.Contains(string(buf), "real-token-value") {
			t.Fatalf("body leaked %s", buf)
		}
		return resp.StatusCode
	}
	if code(base+"/bots/bot-a/runs/run-1/v1/ping", a) != 204 {
		t.Fatal("matched bot run rejected")
	}
	if gotPath != "/v1/ping" {
		t.Fatalf("upstream path %s", gotPath)
	}
	if code(base+"/bots/bot-b/runs/run-2/v1/ping", a) != http.StatusForbidden {
		t.Fatal("bot mismatch admitted")
	}
	if code(base+"/bots/bot-a/runs/run-2/v1/ping", a) != http.StatusForbidden {
		t.Fatal("run mismatch admitted")
	}
	if code(base+"/v1/ping", a) != http.StatusForbidden {
		t.Fatal("unscoped path admitted")
	}
	stopA()
	if code(base+"/bots/bot-a/runs/run-1/v1/ping", a) != http.StatusForbidden {
		t.Fatal("ended run admitted")
	}
	if code(base+"/bots/bot-b/runs/run-2/v1/ping", b) != 204 {
		t.Fatal("other run revoked")
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream calls %d", calls.Load())
	}
}

func TestLoopbackAuditsRequest(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	trip := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    200,
			Header:        http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:          pr,
			ContentLength: -1,
		}, nil
	})
	eg, err := StartLoopback([]string{GrokChatHost}, nil, func() (string, error) {
		return "real-token-value", nil
	}, trip)
	if err != nil {
		t.Fatal(err)
	}
	defer eg.Close()
	const gate = "unit-loopback-gate1"
	const headerMark = "unit-header-marker"
	const bodyMark = "unit-body-marker"
	const queryMark = "unit-query-marker"
	var mu sync.Mutex
	var lines []string
	eg.SetAudit(func(botID, runID, path string, status int, suppressed int) {
		mu.Lock()
		lines = append(lines, fmt.Sprintf("bot=%s run=%s path=%s status=%d", botID, runID, path, status))
		mu.Unlock()
	})
	stop := eg.Admit("bot-a", "run-1", gate)
	defer stop()
	req, err := http.NewRequest(http.MethodPost, eg.Base()+"/bots/bot-a/runs/run-1/v1/ping?q="+queryMark, strings.NewReader(`{"note":"`+bodyMark+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+gate)
	req.Header.Set("X-Secret", headerMark)
	ready := make(chan struct{})
	got := make(chan string, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			got <- "err"
			return
		}
		defer resp.Body.Close()
		close(ready)
		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		got <- string(buf[:n])
		_, _ = io.Copy(io.Discard, resp.Body)
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("headers were not sent")
	}
	if _, err := pw.Write([]byte("data: hi\n\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if !strings.Contains(s, "data: hi") {
			t.Fatalf("chunk %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("response was not flushed")
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	deny, err := http.NewRequest(http.MethodGet, eg.Base()+"/bots/bot-b/runs/run-2/v1/ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	deny.Header.Set("Authorization", "Bearer "+gate)
	deny.Header.Set("X-Secret", headerMark)
	resp, err := http.DefaultClient.Do(deny)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mismatch %d", resp.StatusCode)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(lines)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	text := strings.Join(lines, "\n")
	mu.Unlock()
	if !strings.Contains(text, "bot=bot-a run=run-1 path=/v1/ping status=200") {
		t.Fatalf("audit %s", text)
	}
	if !strings.Contains(text, "bot=bot-b run=run-2 path=/v1/ping status=403") {
		t.Fatalf("denied audit %s", text)
	}
	for _, bad := range []string{gate, headerMark, bodyMark, queryMark, "real-token-value", "Authorization", "X-Secret"} {
		if strings.Contains(text, bad) {
			t.Fatal("audit contains a secret or header")
		}
	}
}

func TestEgressAuditsUnixSocketRequest(t *testing.T) {
	trip := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 204,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
	eg, addr := startBridge(t, nil, trip)
	const headerMark = "unit-header-marker"
	const bodyMark = "unit-body-marker"
	var mu sync.Mutex
	var lines []string
	eg.BindRoute("bot-coi", "run-coi")
	eg.SetAudit(func(botID, runID, path string, status int, suppressed int) {
		mu.Lock()
		lines = append(lines, fmt.Sprintf("bot=%s run=%s path=%s status=%d", botID, runID, path, status))
		mu.Unlock()
	})
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/v1/ping", strings.NewReader(bodyMark))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+PlaceholderToken)
	req.Header.Set("X-Secret", headerMark)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if code := rawStatus(t, addr, "/admin"); code != http.StatusForbidden {
		t.Fatalf("deny %d", code)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(lines)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	text := strings.Join(lines, "\n")
	mu.Unlock()
	if !strings.Contains(text, "bot=bot-coi run=run-coi path=/v1/ping status=204") {
		t.Fatalf("allow audit %s", text)
	}
	if !strings.Contains(text, "bot=bot-coi run=run-coi path=/admin status=403") {
		t.Fatalf("deny audit %s", text)
	}
	for _, bad := range []string{PlaceholderToken, headerMark, bodyMark, "Authorization", "X-Secret", "real-token-value"} {
		if strings.Contains(text, bad) {
			t.Fatal("audit contains a secret or header")
		}
	}
}

func TestForbiddenProxyAuditIsRateLimited(t *testing.T) {
	prev := denyAuditLimit
	denyAuditLimit = 3
	t.Cleanup(func() { denyAuditLimit = prev })
	eg, addr := startBridge(t, nil, nil)
	var mu sync.Mutex
	var n int
	eg.SetAudit(func(botID, runID, path string, status int, suppressed int) {
		mu.Lock()
		n++
		mu.Unlock()
	})
	for i := 0; i < 10; i++ {
		if code := rawStatus(t, addr, "/admin"); code != http.StatusForbidden {
			t.Fatalf("deny %d", code)
		}
	}
	mu.Lock()
	got := n
	mu.Unlock()
	if got != 3 {
		t.Fatalf("audited %d, want 3", got)
	}
}

func TestLoopbackForbiddenAuditIsRateLimited(t *testing.T) {
	prev := denyAuditLimit
	denyAuditLimit = 3
	t.Cleanup(func() { denyAuditLimit = prev })
	eg, err := StartLoopback([]string{GrokChatHost}, nil, func() (string, error) {
		return "real-token-value", nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer eg.Close()
	var mu sync.Mutex
	var n int
	eg.SetAudit(func(botID, runID, path string, status int, suppressed int) {
		mu.Lock()
		n++
		mu.Unlock()
	})
	for i := 0; i < 10; i++ {
		req, err := http.NewRequest(http.MethodGet, eg.Base()+"/v1/ping", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
	mu.Lock()
	got := n
	mu.Unlock()
	if got != 3 {
		t.Fatalf("audited %d, want 3", got)
	}
}

func TestForbiddenAuditReportsSuppressed(t *testing.T) {
	prev := denyAuditLimit
	denyAuditLimit = 2
	t.Cleanup(func() { denyAuditLimit = prev })
	eg, addr := startBridge(t, nil, nil)
	var mu sync.Mutex
	var suppressed int
	var rows int
	eg.SetAudit(func(botID, runID, path string, status int, n int) {
		if status != http.StatusForbidden {
			return
		}
		mu.Lock()
		rows++
		suppressed = n
		mu.Unlock()
	})
	for i := 0; i < 6; i++ {
		if code := rawStatus(t, addr, "/admin"); code != http.StatusForbidden {
			t.Fatalf("deny %d", code)
		}
	}
	time.Sleep(1100 * time.Millisecond)
	if code := rawStatus(t, addr, "/admin"); code != http.StatusForbidden {
		t.Fatalf("later deny %d", code)
	}
	mu.Lock()
	gotRows, gotSkip := rows, suppressed
	mu.Unlock()
	if gotRows != 3 {
		t.Fatalf("rows %d", gotRows)
	}
	if gotSkip != 4 {
		t.Fatalf("suppressed %d", gotSkip)
	}
}

func TestEgressPathAllowlistSkipsUpstream(t *testing.T) {
	var calls atomic.Int32
	trip := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL == nil || (r.URL.Path != "/v1/ping" && r.URL.Path != "/v1/responses" && r.URL.Path != "/V1/ping") {
			t.Errorf("upstream path %v", r.URL)
		}
		return &http.Response{
			StatusCode: 204,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
	eg, addr := startBridge(t, nil, trip)
	if code := rawStatus(t, addr, "/v1/ping"); code != 204 {
		t.Fatalf("allow status %d", code)
	}
	if code := rawStatus(t, addr, "/v1/ping?x=1"); code != 204 {
		t.Fatalf("query status %d", code)
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream calls %d", calls.Load())
	}
	for _, path := range []string{
		"/v2/x",
		"/admin",
		"/v1/../x",
		"/v1/%2e%2e/x",
		"/v1/%252e%252e/x",
		"//v1/ping",
		"/v1//ping",
		"/v1/./ping",
		"/v1/%2fping",
		"/v10",
		"/v1/..%2fx",
		"/v1/ping?x=..",
		"/v1/ping?x=%2e%2e",
		"/v1/ping?x=%2E%2E",
		"/v1/ping?x=%252e%252e",
		"/v1/ping?x=%2fetc",
		"/v1/ping?x=%5cetc",
		"/V1/ping",
	} {
		before := calls.Load()
		code := rawStatus(t, addr, path)
		if code != http.StatusForbidden {
			t.Fatalf("%s status %d", path, code)
		}
		if calls.Load() != before {
			t.Fatalf("%s contacted upstream", path)
		}
	}
	if _, err := StartEgress(t.TempDir(), []string{"api.test"}, []string{"/v1/../admin"}, "tok", trip); err == nil {
		t.Fatal("bad prefix started")
	}
	eg.Close()

	narrow, narrowAddr := startBridge(t, []string{"/v1/responses"}, trip)
	defer narrow.Close()
	if code := rawStatus(t, narrowAddr, "/v1/responses"); code != 204 {
		t.Fatalf("narrow allow %d", code)
	}
	before := calls.Load()
	if code := rawStatus(t, narrowAddr, "/v1/ping"); code != http.StatusForbidden || calls.Load() != before {
		t.Fatalf("narrow deny code %d calls %d", code, calls.Load())
	}
	none, noneAddr := startBridge(t, []string{}, trip)
	defer none.Close()
	before = calls.Load()
	if code := rawStatus(t, noneAddr, "/v1/ping"); code != http.StatusForbidden || calls.Load() != before {
		t.Fatalf("empty prefixes code %d calls %d", code, calls.Load())
	}
	upper, upperAddr := startBridge(t, []string{"/V1"}, trip)
	defer upper.Close()
	if code := rawStatus(t, upperAddr, "/V1/ping"); code != 204 {
		t.Fatalf("stored case %d", code)
	}
	before = calls.Load()
	if code := rawStatus(t, upperAddr, "/v1/ping"); code != http.StatusForbidden || calls.Load() != before {
		t.Fatalf("folded path code %d calls %d", code, calls.Load())
	}
}

func TestForwardHeaderAllowlist(t *testing.T) {
	h := http.Header{
		"Authorization":         {"Bearer jail-authorization"},
		"x-api-key":             {"jail-api-key"},
		"Api-Key":               {"jail-api-key-2"},
		"Cookie":                {"jail-cookie"},
		"X-Custom-Token":        {"jail-custom-token"},
		"X-Auth-Extra":          {"jail-auth-extra"},
		"Proxy-Authorization":   {"Basic jail-proxy"},
		"X-Xai-Token-Auth":      {"jail-xai"},
		"X-Request-Id":          {"drop-me"},
		"Content-Type":          {"application/json"},
		"Accept":                {"text/event-stream"},
		"User-Agent":            {"grok-cli"},
		"X-Grok-Model-Override": {"grok-build"},
	}
	keepForwardHeaders(h)
	if h.Get("Content-Type") != "application/json" || h.Get("Accept") != "text/event-stream" || h.Get("User-Agent") != "grok-cli" || h.Get("X-Grok-Model-Override") != "grok-build" {
		t.Fatalf("kept %v", h)
	}
	if len(h) != 4 {
		t.Fatalf("left %v", h)
	}
}

func TestEgressStripsJailAuthHeaders(t *testing.T) {
	seen := make(chan http.Header, 1)
	trip := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen <- r.Header.Clone()
		return &http.Response{
			StatusCode: 204,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
	_, addr := startBridge(t, nil, trip)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := "GET /v1/ping HTTP/1.1\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Authorization: Bearer jail-authorization\r\n" +
		"Proxy-Authorization: Basic jail-proxy\r\n" +
		"X-Api-Key: jail-api-key\r\n" +
		"Api-Key: jail-api-key-2\r\n" +
		"Cookie: jail-cookie\r\n" +
		"X-Xai-Token-Auth: jail-xai\r\n" +
		"X-Custom-Token: jail-custom-token\r\n" +
		"X-Auth-Extra: jail-auth-extra\r\n" +
		"X-Request-Id: drop-me\r\n" +
		"Content-Type: application/json\r\n" +
		"Accept: text/event-stream\r\n" +
		"User-Agent: grok-cli\r\n" +
		"X-Grok-Model-Override: grok-build\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 204 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got := <-seen
	if got.Get("Authorization") != "Bearer real-token-value" {
		t.Fatalf("auth %q", got.Get("Authorization"))
	}
	if got.Get("Content-Type") != "application/json" || got.Get("Accept") != "text/event-stream" || got.Get("User-Agent") != "grok-cli" || got.Get("X-Grok-Model-Override") != "grok-build" {
		t.Fatalf("forwarded headers %v", got)
	}
	if got.Get("X-Request-Id") != "" {
		t.Fatalf("request id %q", got.Get("X-Request-Id"))
	}
	blob := fmt.Sprint(got)
	for _, secret := range []string{
		"jail-authorization", "jail-proxy", "jail-api-key", "jail-api-key-2",
		"jail-cookie", "jail-xai", "jail-custom-token", "jail-auth-extra",
	} {
		if strings.Contains(blob, secret) {
			t.Fatalf("forwarded %s", secret)
		}
	}
}

func TestNormalizeProxyPath(t *testing.T) {
	okPath := map[string]string{
		"/v1":                         "/v1",
		"/v1/":                        "/v1",
		"/v1/ping":                    "/v1/ping",
		"/v1/foo%20bar":               "/v1/foo bar",
		"http://api.test/v1/ping?x=1": "/v1/ping",
	}
	for in, want := range okPath {
		got, ok := normalizeProxyPath(in)
		if !ok || got != want {
			t.Fatalf("%s -> %q ok=%v", in, got, ok)
		}
	}
	for _, in := range []string{
		"",
		"v1",
		"/v1/../x",
		"/v1/%2e%2e/x",
		"/v1/%252e%252e/admin",
		"//v1/ping",
		"/v1//ping",
		"/v1/./ping",
		`/v1/\../x`,
		"/v1/%5c../x",
		"/v1/%2fx",
		"/v1/%00",
	} {
		if _, ok := normalizeProxyPath(in); ok {
			t.Fatalf("accepted %s", in)
		}
	}
}

func startBridge(t *testing.T, prefixes []string, trip roundTripFunc) (*Egress, string) {
	t.Helper()
	eg, err := StartEgress(t.TempDir(), []string{"api.test"}, prefixes, "real-token-value", trip)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eg.Close)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveBridge(ln, eg.Sock())
	return eg, ln.Addr().String()
}

func rawStatus(t *testing.T, addr, target string) int {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET "+target+" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestLoopbackServesUnixSocket(t *testing.T) {
	eg, err := StartLoopback([]string{GrokChatHost}, nil, func() (string, error) {
		return "real-token-value", nil
	}, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer eg.Close()
	if err := eg.ListenUnix(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := eg.ListenUnix(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	sock := eg.Sock()
	if sock == "" || filepath.Base(sock) != "sock" || strings.HasSuffix(sock, ".sock") {
		t.Fatalf("sock %q", sock)
	}
	st, err := os.Stat(sock)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st, err)
	}
	dir, err := os.Stat(filepath.Dir(sock))
	if err != nil || dir.Mode().Perm() != 0o700 {
		t.Fatalf("dir %v %v", dir, err)
	}
	if !strings.HasPrefix(eg.Base(), "http://127.0.0.1:") {
		t.Fatalf("tcp base %q", eg.Base())
	}
	code := unixStatus(t, sock, "/v1/ping", "")
	if code != http.StatusForbidden {
		t.Fatalf("ungated %d", code)
	}
	const gate = "unit-unix-gate-value"
	drop := eg.Admit("bot1", "run1", gate)
	defer drop()
	code = unixStatus(t, sock, "/bots/bot1/runs/run1/v1/ping", "Bearer "+gate)
	if code != http.StatusNoContent {
		t.Fatalf("gated status %d", code)
	}
}

func unixStatus(t *testing.T, sock, path, auth string) int {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := "GET " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
	if auth != "" {
		req += "Authorization: " + auth + "\r\n"
	}
	req += "\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestDialAllowlistRejectsOtherHosts(t *testing.T) {
	_, err := dialAllowlisted(t.Context(), "tcp", "evil.example:443", map[string]bool{"api.x.ai": true})
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatal(err)
	}
}
