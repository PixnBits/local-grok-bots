package coi

import (
	"bufio"
	"fmt"
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

func TestDialAllowlistRejectsOtherHosts(t *testing.T) {
	_, err := dialAllowlisted(t.Context(), "tcp", "evil.example:443", map[string]bool{"api.x.ai": true})
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatal(err)
	}
}
