package coi

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
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

func TestEgressPathAllowlistSkipsUpstream(t *testing.T) {
	var calls atomic.Int32
	trip := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL == nil || (r.URL.Path != "/v1/ping" && r.URL.Path != "/v1/responses") {
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
	if calls.Load() != 1 {
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

func TestDialAllowlistRejectsOtherHosts(t *testing.T) {
	_, err := dialAllowlisted(t.Context(), "tcp", "evil.example:443", map[string]bool{"api.x.ai": true})
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatal(err)
	}
}
