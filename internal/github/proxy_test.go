package github

import (
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

func gitBasic(tok string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+tok))
}

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
	if hits != 1 || gotAuth != gitBasic(tokenSecret) || gotProxy != "" || gotProto != "version=2" {
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
	if len(audits) != 1 || audits[0].Action != "github_allow" || audits[0].Decision != "allow" || audits[0].Status != 200 || audits[0].Method != http.MethodGet {
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
	if len(audits) != 1 || audits[0].Action != "github_refuse" || audits[0].Reason != "repo" || audits[0].Decision != "refuse" || audits[0].Method != http.MethodGet {
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
		if r.Header.Get("Authorization") != gitBasic(tokenSecret) {
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

func TestReadProxyRefusesWrites(t *testing.T) {
	var mu sync.Mutex
	var hits int
	var sawAuth string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		sawAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	defer up.Close()
	var audits []Audit
	p, err := New(Config{
		Repos:   []string{"acme/widgets"},
		Token:   func() (string, error) { return tokenSecret, nil },
		GitBase: up.URL,
		APIBase: up.URL,
		Audit:   func(a Audit) { audits = append(audits, a) },
		Access:  AccessRead,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.ListenUnix(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.Dial("unix", p.Sock())
		},
	}}
	do := func(method, path string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(method, "http://proxy"+path, strings.NewReader("0000"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tokenSecret)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res.StatusCode, string(body)
	}
	denied := []string{
		http.MethodPost + " /github/acme/widgets.git/git-receive-pack",
		http.MethodPost + " /api/repos/acme/widgets/pulls",
		http.MethodPost + " /api/repos/acme/widgets/merges",
		http.MethodPost + " /api/repos/acme/widgets/git/refs",
		http.MethodPost + " /api/repos/acme/widgets/pulls/1/merge",
		http.MethodHead + " /github/acme/widgets.git/info/refs?service=git-upload-pack",
		http.MethodGet + " /api/repos/acme/widgets/merges",
	}
	for _, item := range denied {
		method, path, _ := strings.Cut(item, " ")
		audits = nil
		code, body := do(method, path)
		if code != http.StatusForbidden || strings.Contains(body, tokenSecret) {
			t.Fatalf("%s %s -> %d %q", method, path, code, body)
		}
		mu.Lock()
		gotHits := hits
		gotAuth := sawAuth
		mu.Unlock()
		if gotHits != 0 || gotAuth != "" {
			t.Fatalf("%s %s forwarded hits=%d auth=%q", method, path, gotHits, gotAuth)
		}
		if len(audits) != 1 || audits[0].Method != method {
			t.Fatalf("%s audit %#v", item, audits)
		}
		if method != http.MethodGet && audits[0].Action != "github_write" {
			t.Fatalf("%s action %#v", item, audits[0])
		}
	}
	audits = nil
	code, body := do(http.MethodGet, "/github/acme/widgets.git/info/refs?service=git-upload-pack")
	if code != http.StatusOK || body != "upstream-ok" {
		t.Fatalf("upload-pack GET %d %q", code, body)
	}
	if len(audits) != 1 || audits[0].Action != "github_allow" || audits[0].Method != http.MethodGet {
		t.Fatalf("get audit %#v", audits)
	}
	audits = nil
	code, body = do(http.MethodPost, "/github/acme/widgets.git/git-upload-pack")
	if code != http.StatusOK || body != "upstream-ok" {
		t.Fatalf("upload-pack POST %d %q", code, body)
	}
	mu.Lock()
	if hits != 2 || sawAuth != gitBasic(tokenSecret) {
		mu.Unlock()
		t.Fatalf("allowed hits=%d auth=%q", hits, sawAuth)
	}
	mu.Unlock()
	if len(audits) != 1 || audits[0].Action != "github_write" || audits[0].Method != http.MethodPost || audits[0].Decision != "allow" {
		t.Fatalf("post audit %#v", audits)
	}
	code, body = do(http.MethodGet, "/api/repos/acme/widgets")
	if code != http.StatusOK {
		t.Fatalf("repo GET %d %q", code, body)
	}
	code, body = do(http.MethodGet, "/api/repos/acme/widgets/pulls/1")
	if code != http.StatusOK {
		t.Fatalf("pull GET %d %q", code, body)
	}

	writeProxy, err := New(Config{
		Repos:   []string{"acme/widgets"},
		Token:   func() (string, error) { return tokenSecret, nil },
		GitBase: up.URL,
		APIBase: up.URL,
		Access:  AccessWrite,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer writeProxy.Close()
	if err := writeProxy.ListenUnix(t.TempDir()); err == nil {
		t.Fatal("write proxy listened on a unix socket")
	}
	base, err := writeProxy.ListenTCP()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/github/acme/widgets.git/git-receive-pack",
		"/api/repos/acme/widgets/pulls",
	} {
		req, err := http.NewRequest(http.MethodPost, base+path, strings.NewReader("0000"))
		if err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("write %s -> %d", path, res.StatusCode)
		}
	}
	res, err := http.Get(base + "/github/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("write proxy allowed upload-pack GET %d", res.StatusCode)
	}
}

func TestUpstreamAuthOnBothProxies(t *testing.T) {
	var mu sync.Mutex
	var gotAuth, gotPath string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.RequestURI()
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer up.Close()
	routes := []struct {
		name    string
		service string
		method  string
		path    string
		query   string
		basic   bool
	}{
		{"info/refs", "github", http.MethodGet, "/acme/widgets.git/info/refs", "service=git-upload-pack", true},
		{"upload-pack", "github", http.MethodPost, "/acme/widgets.git/git-upload-pack", "", true},
		{"receive-pack", "github", http.MethodPost, "/acme/widgets.git/git-receive-pack", "", true},
		{"api", "api", http.MethodGet, "/repos/acme/widgets", "", false},
	}
	for _, access := range []Access{AccessRead, AccessWrite} {
		p, err := New(Config{
			Repos:   []string{"acme/widgets"},
			Token:   func() (string, error) { return tokenSecret, nil },
			GitBase: up.URL,
			APIBase: up.URL,
			Access:  access,
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range routes {
			base := p.gitBase
			if tc.service == "api" {
				base = p.apiBase
			}
			route := Route{Service: tc.service, Owner: "acme", Repo: "widgets", Path: tc.path, Query: tc.query}
			req, err := http.NewRequest(tc.method, "http://proxy"+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			if _, err := p.forward(rec, req, base, route, tokenSecret); err != nil {
				t.Fatalf("%v %s: %v", access, tc.name, err)
			}
			mu.Lock()
			auth, path := gotAuth, gotPath
			mu.Unlock()
			want := "Bearer " + tokenSecret
			if tc.basic {
				want = gitBasic(tokenSecret)
			}
			if auth != want {
				t.Fatalf("%v %s auth %q", access, tc.name, auth)
			}
			if tc.basic {
				raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
				if err != nil || string(raw) != "x-access-token:"+tokenSecret {
					t.Fatalf("%v %s basic %q %v", access, tc.name, raw, err)
				}
			}
			if strings.Contains(auth, "Bearer "+tokenSecret) && tc.basic {
				t.Fatalf("%v %s used bearer", access, tc.name)
			}
			if !strings.Contains(path, tc.path) {
				t.Fatalf("%v %s path %q", access, tc.name, path)
			}
		}
	}
}

func TestProxyAuditsTokenReasonWithoutBytes(t *testing.T) {
	cases := []struct {
		name string
		tok  string
		err  error
		want string
	}{
		{"owner", "", errToken("owner"), "token file: not root-owned"},
		{"mode", "", errToken("mode"), "mode"},
		{"missing", "", errToken("read"), "missing"},
		{"shape", "bad token", nil, "shape"},
		{"wrapped", "", errors.New("leak " + tokenSecret), "token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var audits []Audit
			p, err := New(Config{
				Repos: []string{"acme/widgets"},
				Token: func() (string, error) {
					if tc.err != nil {
						return "", tc.err
					}
					return tc.tok, nil
				},
				Audit: func(a Audit) { audits = append(audits, a) },
			})
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(p)
			defer srv.Close()
			res, err := http.Get(srv.URL + "/github/acme/widgets.git/info/refs?service=git-upload-pack")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("status %d", res.StatusCode)
			}
			if len(audits) != 1 || audits[0].Reason != tc.want || audits[0].Status != http.StatusServiceUnavailable {
				t.Fatalf("audit %#v", audits)
			}
			blob := string(body) + audits[0].Reason + audits[0].Path + audits[0].Action
			if strings.Contains(blob, tokenSecret) || strings.Contains(blob, "bad token") || strings.Contains(blob, "leak") {
				t.Fatalf("reason leaked %q", blob)
			}
		})
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
