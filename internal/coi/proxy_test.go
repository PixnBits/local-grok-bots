package coi

import (
	"io"
	"net"
	"net/http"
	"strings"
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
	eg, err := StartEgress(t.TempDir(), []string{"api.test"}, "real-token-value", trip)
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

func TestDialAllowlistRejectsOtherHosts(t *testing.T) {
	_, err := dialAllowlisted(t.Context(), "tcp", "evil.example:443", map[string]bool{"api.x.ai": true})
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatal(err)
	}
}
