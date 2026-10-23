package github

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestProxyStripsCallerAuthAndAudits(t *testing.T) {
	const caller = "caller-supplied-auth-value"
	var mu sync.Mutex
	var gotAuth, gotProxy, gotProto, gotPath string
	var hits int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		hits++
		gotAuth = r.Header.Get("Authorization")
		gotProxy = r.Header.Get("Proxy-Authorization")
		gotProto = r.Header.Get("Git-Protocol")
		gotPath = r.URL.RequestURI()
		if r.Header.Get("X-Secret") != "" {
			t.Errorf("forwarded X-Secret")
		}
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		_, _ = w.Write([]byte("pack-ok"))
	}))
	defer up.Close()

	var audits []Audit
	p, err := New(Config{
		Repos:   []string{"Acme/Widgets"},
		Token:   func() (string, error) { return tokenSecret, nil },
		GitBase: up.URL,
		APIBase: up.URL,
		Audit:   func(a Audit) { audits = append(audits, a) },
	})
	if err != nil {
		t.Fatal(err)
	}
	p.Bind("bot_1", "run_1")
	srv := httptest.NewServer(p)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/github/Acme/Widgets.git/info/refs?service=git-upload-pack", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+caller)
	req.Header.Set("Proxy-Authorization", "Basic "+caller)
	req.Header.Set("Git-Protocol", "version=2")
	req.Header.Set("X-Secret", tokenSecret)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(body) != "pack-ok" {
		t.Fatalf("status %d body %q", res.StatusCode, body)
	}
	mu.Lock()
	if hits != 1 || gotAuth != "Bearer "+tokenSecret || gotProxy != "" || gotProto != "version=2" {
		mu.Unlock()
		t.Fatalf("upstream hits=%d auth=%q proxy=%q proto=%q", hits, gotAuth, gotProxy, gotProto)
	}
	if gotAuth == "Bearer "+caller || strings.Contains(gotPath, tokenSecret) {
		mu.Unlock()
		t.Fatalf("caller auth survived: %q %q", gotAuth, gotPath)
	}
	if !strings.Contains(gotPath, "/Acme/Widgets.git/info/refs") || !strings.Contains(gotPath, "service=git-upload-pack") {
		path := gotPath
		mu.Unlock()
		t.Fatalf("path %q", path)
	}
	mu.Unlock()
	if len(audits) != 1 || audits[0].Action != "github_allow" || audits[0].Decision != "allow" || audits[0].Status != 200 {
		t.Fatalf("audit %#v", audits)
	}
	if audits[0].Owner != "acme" || audits[0].Repo != "widgets" || audits[0].Bot != "bot_1" || audits[0].Run != "run_1" {
		t.Fatalf("audit ids %#v", audits[0])
	}
	blob := audits[0].Path + audits[0].Reason + audits[0].Action
	if strings.Contains(blob, tokenSecret) || strings.Contains(blob, caller) {
		t.Fatalf("audit leaked %q", blob)
	}

	audits = nil
	res, err = http.Get(srv.URL + "/github/other/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatal(err)
	}
	denied, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden || hits != 1 {
		t.Fatalf("other repo %d hits %d", res.StatusCode, hits)
	}
	if strings.Contains(string(denied), tokenSecret) || strings.Contains(string(denied), caller) {
		t.Fatalf("deny body %q", denied)
	}
	if len(audits) != 1 || audits[0].Action != "github_refuse" || audits[0].Reason != "repo" || audits[0].Decision != "refuse" {
		t.Fatalf("deny audit %#v", audits)
	}

	res, err = http.Get(srv.URL + "/api/repos/Acme/Widgets")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || hits != 2 {
		t.Fatalf("api %d hits %d", res.StatusCode, hits)
	}
	res, err = http.Get(srv.URL + "/api/user")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden || hits != 2 {
		t.Fatalf("user %d hits %d", res.StatusCode, hits)
	}
	res, err = http.Get(srv.URL + "/github/Acme/Widgets.git/info/refs/../../secret")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden || hits != 2 {
		t.Fatalf("traversal %d hits %d", res.StatusCode, hits)
	}
}

func TestProxyTCPGateAndUnixSocket(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+tokenSecret {
			t.Errorf("auth %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer up.Close()
	p, err := New(Config{
		Repos:   []string{"acme/widgets"},
		Token:   func() (string, error) { return tokenSecret, nil },
		GitBase: up.URL,
		APIBase: up.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	base, err := p.ListenTCP()
	if err != nil {
		t.Fatal(err)
	}
	bare := strings.TrimSuffix(strings.TrimPrefix(base, "http://"), "/g/"+p.Gate())
	res, err := http.Get("http://" + bare + "/github/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("missing gate %d", res.StatusCode)
	}
	res, err = http.Get(base + "/github/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("gate %d", res.StatusCode)
	}

	if err := p.ListenUnix(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p.Sock())
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %o", st.Mode().Perm())
	}
	client := &http.Client{Transport: &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.Dial("unix", p.Sock())
		},
	}}
	req, err := http.NewRequest(http.MethodGet, "http://proxy/github/acme/widgets.git/info/refs?service=git-upload-pack", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("unix %d", res.StatusCode)
	}
}

func TestProxyRejectsBadBase(t *testing.T) {
	_, err := New(Config{
		Token:   func() (string, error) { return tokenSecret, nil },
		GitBase: "https://user:" + tokenSecret + "@github.com",
	})
	if err == nil || strings.Contains(err.Error(), tokenSecret) {
		t.Fatalf("base %v", err)
	}
}
