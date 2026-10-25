package daemon

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/config"
)

const (
	aliceName = "alice"
	bobName   = "bob"
	aliceTok  = "abcdefghijklmnopqrstuvwxyz012345:more"
	bobTok    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
)

func TestNamedTokensBearerAndCookie(t *testing.T) {
	if len(aliceTok) < 32 || len(bobTok) < 32 {
		t.Fatal("fixture tokens are short")
	}
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	body := "# comment\n\n" + aliceName + ":" + aliceTok + "\n\n" + bobName + ":" + bobTok + "\n"
	path := writeTokenFile(t, dir, body, 0o600)
	stderr := takeStderr(t)
	app := newTokenApp(t, dir, path, "", auditPath)
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)

	if res, _ := do(t, "GET", srv.URL+"/api/health", nil, ""); res.StatusCode != 200 {
		t.Fatalf("health %d", res.StatusCode)
	}
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, ""); res.StatusCode != 401 {
		t.Fatalf("open %d", res.StatusCode)
	}
	for _, tok := range []string{aliceTok, bobTok} {
		if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, tok); res.StatusCode != 200 {
			t.Fatalf("bearer %d", res.StatusCode)
		}
		res, cookie := loginCookie(t, srv.URL, tok)
		if res.StatusCode != http.StatusSeeOther || cookie == nil || cookie.Value != tok || !cookie.HttpOnly {
			t.Fatalf("login %d cookie %+v", res.StatusCode, cookie)
		}
		creq, err := http.NewRequest(http.MethodGet, srv.URL+"/api/bots", nil)
		if err != nil {
			t.Fatal(err)
		}
		creq.AddCookie(cookie)
		cres, err := http.DefaultClient.Do(creq)
		if err != nil {
			t.Fatal(err)
		}
		cres.Body.Close()
		if cres.StatusCode != 200 {
			t.Fatalf("cookie %d", cres.StatusCode)
		}
	}
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, aliceTok+"nope"); res.StatusCode != 401 {
		t.Fatalf("wrong bearer %d", res.StatusCode)
	}
	bad, cookie := loginCookie(t, srv.URL, aliceTok+"nope")
	if bad.StatusCode != 401 || cookie != nil {
		t.Fatalf("bad login %d cookie %+v", bad.StatusCode, cookie)
	}

	logged := stderr()
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, name := range []string{aliceName, bobName} {
		if !strings.Contains(text, `"token_name":"`+name+`"`) || !strings.Contains(text, `"action":"auth_login"`) {
			t.Fatalf("audit missing %s:\n%s", name, text)
		}
	}
	if !strings.Contains(text, `"action":"auth_login_failed"`) {
		t.Fatalf("audit missing failure:\n%s", text)
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "auth_login_failed") && strings.Contains(line, "token_name") {
			t.Fatalf("failure names a token:\n%s", line)
		}
	}
	for _, secret := range []string{aliceTok, bobTok} {
		if strings.Contains(text, secret) || strings.Contains(logged, secret) {
			t.Fatal("token value was written")
		}
	}
}

func TestNamedTokenRemovedOnRestart(t *testing.T) {
	dir := t.TempDir()
	path := writeTokenFile(t, dir, aliceName+":"+aliceTok+"\n"+bobName+":"+bobTok+"\n", 0o600)
	app := newTokenApp(t, dir, path, "", "")
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, bobTok); res.StatusCode != 200 {
		t.Fatalf("before restart %d", res.StatusCode)
	}
	srv.Close()
	app.Shutdown()

	writeTokenFile(t, dir, aliceName+":"+aliceTok+"\n", 0o600)
	app2 := newTokenApp(t, dir, path, "", "")
	srv2 := httptest.NewServer(app2.Handler())
	t.Cleanup(srv2.Close)
	if res, _ := do(t, "GET", srv2.URL+"/api/bots", nil, aliceTok); res.StatusCode != 200 {
		t.Fatalf("kept token %d", res.StatusCode)
	}
	if res, _ := do(t, "GET", srv2.URL+"/api/bots", nil, bobTok); res.StatusCode != 401 {
		t.Fatalf("removed token %d", res.StatusCode)
	}
}

func TestEmptyTokenFileLeavesAPIOpen(t *testing.T) {
	dir := t.TempDir()
	path := writeTokenFile(t, dir, "# none\n\n", 0o600)
	app := newTokenApp(t, dir, path, "", "")
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, ""); res.StatusCode != 200 {
		t.Fatalf("empty file %d", res.StatusCode)
	}
}

func TestFileNamedDefaultWithoutAdminToken(t *testing.T) {
	dir := t.TempDir()
	path := writeTokenFile(t, dir, "default:"+aliceTok+"\n", 0o600)
	app := newTokenApp(t, dir, path, "", "")
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, aliceTok); res.StatusCode != 200 {
		t.Fatalf("default name %d", res.StatusCode)
	}
}

func TestAuthTokensFileRejects(t *testing.T) {
	stderr := takeStderr(t)
	checks := []struct {
		name   string
		body   string
		auth   string
		want   string
		secret string
	}{
		{"bad line", "# c\n\nnot-a-pair\n", "", "line 3", "not-a-pair"},
		{"bad name", "# c\nbad name:" + aliceTok + "\n", "", "line 2", aliceTok},
		{"short token", "alice:" + strings.Repeat("a", 31) + "\n", "", "line 1", strings.Repeat("a", 31)},
		{"token space", "alice:" + aliceTok + " trailing\n", "", "line 1", aliceTok},
		{"duplicate name", "alice:" + aliceTok + "\nalice:" + bobTok + "\n", "", "line 2: duplicate name", aliceTok},
		{"duplicate token", "alice:" + aliceTok + "\nbob:" + aliceTok + "\n", "", "line 2: duplicate token", aliceTok},
		{"default name", "default:" + bobTok + "\n", aliceTok, "line 1: duplicate name", bobTok},
		{"default value", "alice:" + aliceTok + "\n", aliceTok, "line 1: duplicate token", aliceTok},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeTokenFile(t, dir, tc.body, 0o600)
			err := startTokens(t, dir, path, tc.auth)
			if err == nil || !strings.Contains(err.Error(), tc.want) || (tc.secret != "" && strings.Contains(err.Error(), tc.secret)) {
				t.Fatalf("err %v", err)
			}
			if tc.auth != "" && strings.Contains(err.Error(), tc.auth) {
				t.Fatal("error includes the default token")
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := writeTokenFile(t, dir, "alice:"+aliceTok+"\n", 0o600)
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		err := startTokens(t, dir, link, "")
		if err == nil || !strings.Contains(err.Error(), "symlink") || strings.Contains(err.Error(), aliceTok) {
			t.Fatalf("err %v", err)
		}
		st, statErr := os.Stat(target)
		if statErr != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("target mode %v %v", st, statErr)
		}
	})
	t.Run("mode", func(t *testing.T) {
		dir := t.TempDir()
		path := writeTokenFile(t, dir, "alice:"+aliceTok+"\n", 0o644)
		err := startTokens(t, dir, path, "")
		st, statErr := os.Stat(path)
		if err == nil || !strings.Contains(err.Error(), "mode") || strings.Contains(err.Error(), aliceTok) {
			t.Fatalf("err %v", err)
		}
		if statErr != nil || st.Mode().Perm() != 0o644 {
			t.Fatalf("mode changed %v %v", st, statErr)
		}
	})
	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "tokens")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		err := startTokens(t, dir, path, "")
		if err == nil || !strings.Contains(err.Error(), "regular") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		dir := t.TempDir()
		path := writeTokenFile(t, dir, strings.Repeat("x", authTokensMax+1), 0o600)
		err := startTokens(t, dir, path, "")
		if err == nil || !strings.Contains(err.Error(), "64 KiB") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("exact cap", func(t *testing.T) {
		dir := t.TempDir()
		line := "alice:" + aliceTok + "\n"
		rest := authTokensMax - len(line)
		body := line + "#" + strings.Repeat(".", rest-2) + "\n"
		if len(body) != authTokensMax {
			t.Fatalf("size %d", len(body))
		}
		path := writeTokenFile(t, dir, body, 0o600)
		app := newTokenApp(t, dir, path, "", "")
		srv := httptest.NewServer(app.Handler())
		t.Cleanup(srv.Close)
		if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, aliceTok); res.StatusCode != 200 {
			t.Fatalf("cap %d", res.StatusCode)
		}
	})
	t.Run("stricter mode", func(t *testing.T) {
		dir := t.TempDir()
		path := writeTokenFile(t, dir, "alice:"+aliceTok+"\n", 0o400)
		app := newTokenApp(t, dir, path, "", "")
		srv := httptest.NewServer(app.Handler())
		t.Cleanup(srv.Close)
		if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, aliceTok); res.StatusCode != 200 {
			t.Fatalf("mode 0400 %d", res.StatusCode)
		}
	})
	if logged := stderr(); strings.Contains(logged, aliceTok) || strings.Contains(logged, bobTok) {
		t.Fatal("stderr includes a token")
	}
}

func TestGeneratedTokenDuplicateIsRejected(t *testing.T) {
	t.Setenv("AUTH_TOKEN", "")
	dir := t.TempDir()
	policy := writeCLIPolicy(t, dir)
	app := newCLIApp(t, dir, policy)
	tok := app.cfg.AuthToken
	app.Shutdown()
	path := writeTokenFile(t, dir, "other:"+tok+"\n", 0o600)
	err := startWithPolicy(t, dir, path, "", policy)
	if err == nil || !strings.Contains(err.Error(), "duplicate token") || strings.Contains(err.Error(), tok) {
		t.Fatalf("value clash %v", err)
	}
	path = writeTokenFile(t, dir, "default:"+strings.Repeat("d", 32)+"\n", 0o600)
	err = startWithPolicy(t, dir, path, "", policy)
	if err == nil || !strings.Contains(err.Error(), "duplicate name") || strings.Contains(err.Error(), strings.Repeat("d", 32)) {
		t.Fatalf("name clash %v", err)
	}
}

func newTokenApp(t *testing.T, dir, tokensFile, authToken, auditPath string) *App {
	t.Helper()
	app, err := openTokenApp(t, dir, tokensFile, authToken, auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	return app
}

func startTokens(t *testing.T, dir, tokensFile, authToken string) error {
	t.Helper()
	app, err := openTokenApp(t, dir, tokensFile, authToken, "")
	if app != nil {
		app.Shutdown()
	}
	return err
}

func startWithPolicy(t *testing.T, dir, tokensFile, authToken, policy string) error {
	t.Helper()
	cfg := config.Config{
		DataDir:        dir,
		BindAddr:       "127.0.0.1:0",
		OllamaURL:      "http://127.0.0.1:9",
		Model:          "test-model",
		Version:        "0.1.0",
		AuthToken:      authToken,
		AuthTokensFile: tokensFile,
		PolicyPath:     policy,
	}
	app, err := New(cfg, nil)
	if app != nil {
		app.Shutdown()
	}
	return err
}

func openTokenApp(t *testing.T, dir, tokensFile, authToken, auditPath string) (*App, error) {
	t.Helper()
	cfg := config.Config{
		DataDir:        dir,
		BindAddr:       "127.0.0.1:0",
		OllamaURL:      "http://127.0.0.1:9",
		Model:          "test-model",
		Version:        "0.1.0",
		AuthToken:      authToken,
		AuthTokensFile: tokensFile,
	}
	if auditPath != "" {
		policyPath := filepath.Join(dir, "policy.toml")
		body := "[security]\naudit_log = " + strconv.Quote(auditPath) + "\n"
		if err := os.WriteFile(policyPath, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg.PolicyPath = policyPath
	}
	app, err := New(cfg, nil)
	if app != nil {
		app.noGrokProxy = true
	}
	return app, err
}

func writeTokenFile(t *testing.T, dir, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "tokens")
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func loginCookie(t *testing.T, base, token string) (*http.Response, *http.Cookie) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := client.Get(base + "/login?token=" + url.QueryEscape(token))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == authCookie {
			cookie = c
		}
	}
	return res, cookie
}

func takeStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stderr
	os.Stderr = w
	var once sync.Once
	var text string
	take := func() string {
		once.Do(func() {
			os.Stderr = prev
			_ = w.Close()
			b, _ := io.ReadAll(r)
			_ = r.Close()
			text = string(b)
		})
		return text
	}
	t.Cleanup(func() { _ = take() })
	return take
}
