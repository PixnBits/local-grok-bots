package github

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
)

func TestGzipDefaultClientBothProxies(t *testing.T) {
	const branch = "main"
	raw := []byte(`{"default_branch":"main","name":"widgets"}`)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	gz := append([]byte(nil), buf.Bytes()...)

	var mu sync.Mutex
	var encodings []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enc := r.Header.Get("Accept-Encoding")
		mu.Lock()
		encodings = append(encodings, enc)
		mu.Unlock()
		if !bytes.Contains([]byte(enc), []byte("gzip")) {
			t.Errorf("upstream Accept-Encoding %q", enc)
			http.Error(w, "no gzip", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(gz)))
		if _, err := w.Write(gz); err != nil {
			t.Errorf("write gzip: %v", err)
		}
	}))
	defer up.Close()

	client := &http.Client{}
	readProxy := gzipProxy(t, up.URL, AccessRead)
	readSrv := httptest.NewServer(readProxy)
	defer readSrv.Close()

	got, err := DefaultBranch(context.Background(), client, readSrv.URL+"/api/repos/acme/widgets")
	if err != nil || got != branch {
		t.Fatalf("DefaultBranch %q %v", got, err)
	}
	assertPlainJSON(t, client, readSrv.URL+"/api/repos/acme/widgets")

	writeProxy := gzipProxy(t, up.URL, AccessWrite)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := Route{Service: "api", Owner: "acme", Repo: "widgets", Path: "/repos/acme/widgets"}
		rec := httptest.NewRecorder()
		status, ferr := writeProxy.forward(rec, r, writeProxy.apiBase, route, tokenSecret)
		if ferr != nil {
			http.Error(w, "upstream", http.StatusBadGateway)
			return
		}
		for k, vs := range rec.Header() {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(status)
		_, _ = io.Copy(w, rec.Body)
	}))
	defer front.Close()
	assertPlainJSON(t, client, front.URL+"/repos/acme/widgets")

	mu.Lock()
	defer mu.Unlock()
	if len(encodings) < 3 {
		t.Fatalf("upstream hits %d", len(encodings))
	}
	for _, enc := range encodings {
		if enc != "gzip" {
			t.Fatalf("forwarded client encoding %q", enc)
		}
	}
}

func gzipProxy(t *testing.T, upstream string, access Access) *Proxy {
	t.Helper()
	p, err := New(Config{
		Repos:   []string{"acme/widgets"},
		Token:   func() (string, error) { return tokenSecret, nil },
		GitBase: upstream,
		APIBase: upstream,
		Access:  access,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func assertPlainJSON(t *testing.T, client *http.Client, rawURL string) {
	t.Helper()
	res, err := client.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %q", res.StatusCode, body)
	}
	if res.Header.Get("Content-Encoding") != "" {
		t.Fatalf("Content-Encoding %q", res.Header.Get("Content-Encoding"))
	}
	if bytes.HasPrefix(body, []byte{0x1f, 0x8b}) {
		t.Fatalf("body is still gzip")
	}
	var doc struct {
		DefaultBranch string `json:"default_branch"`
		Name          string `json:"name"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode %v body %q", err, body)
	}
	if doc.DefaultBranch != "main" || doc.Name != "widgets" {
		t.Fatalf("doc %#v", doc)
	}
	if cl := res.Header.Get("Content-Length"); cl != "" && cl != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length %s body %d", cl, len(body))
	}
}
