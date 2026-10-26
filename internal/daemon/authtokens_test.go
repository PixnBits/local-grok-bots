package daemon

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

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

func TestAuthTokensFileEmptyRefuses(t *testing.T) {
	for _, body := range []string{"", "# none\n\n", "\n\n  \n"} {
		dir := t.TempDir()
		path := writeTokenFile(t, dir, body, 0o600)
		err := startTokens(t, dir, path, "")
		if err == nil || !strings.Contains(err.Error(), "AUTH_TOKENS_FILE") || strings.Contains(err.Error(), "# none") {
			t.Fatalf("body %q err %v", body, err)
		}
		err = startTokens(t, dir, path, aliceTok)
		if err == nil || !strings.Contains(err.Error(), "AUTH_TOKENS_FILE") || strings.Contains(err.Error(), aliceTok) {
			t.Fatalf("with AUTH_TOKEN body %q err %v", body, err)
		}
	}
}

func TestFileNamedDefaultWithoutAdminToken(t *testing.T) {
	dir := t.TempDir()
	path := writeTokenFile(t, dir, "default:"+aliceTok+"\n", 0o600)
	err := startTokens(t, dir, path, "")
	if err == nil || !strings.Contains(err.Error(), "line 1: name \"default\" is reserved") || strings.Contains(err.Error(), "duplicate name") || strings.Contains(err.Error(), aliceTok) {
		t.Fatalf("err %v", err)
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
		{"nul", "alice:" + strings.Repeat("a", 31) + "\x00b\n", "", "line 1: invalid token", strings.Repeat("a", 31) + "\x00b"},
		{"esc", "alice:" + strings.Repeat("b", 32) + "\x1b\n", "", "line 1: invalid token", strings.Repeat("b", 32) + "\x1b"},
		{"del", "alice:" + strings.Repeat("c", 32) + "\x7f\n", "", "line 1: invalid token", strings.Repeat("c", 32) + "\x7f"},
		{"non-ascii", "alice:" + strings.Repeat("d", 32) + "é\n", "", "line 1: invalid token", strings.Repeat("d", 32) + "é"},
		{"duplicate name", "alice:" + aliceTok + "\nalice:" + bobTok + "\n", "", "line 2: duplicate name", aliceTok},
		{"duplicate token", "alice:" + aliceTok + "\nbob:" + aliceTok + "\n", "", "line 2: duplicate token", aliceTok},
		{"default name", "default:" + bobTok + "\n", aliceTok, "line 1: name \"default\" is reserved", bobTok},
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

func TestPrintableASCIITokenAccepted(t *testing.T) {
	tok := strings.Repeat("!~", 16)
	if len(tok) != 32 {
		t.Fatalf("len %d", len(tok))
	}
	dir := t.TempDir()
	path := writeTokenFile(t, dir, "alice:"+tok+"\n", 0o600)
	app := newTokenApp(t, dir, path, "", "")
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, tok); res.StatusCode != 200 {
		t.Fatalf("printable %d", res.StatusCode)
	}
}

func TestAuthTokensFileFIFO(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := readAuthTokensFile(path)
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "regular") {
			t.Fatalf("err %v", err)
		}
	case <-time.After(2 * time.Second):
		w, werr := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if werr == nil {
			w.Close()
		}
		t.Fatal("readAuthTokensFile blocked on a FIFO")
	}
}

func TestAuthTokensFileInsideWorkspace(t *testing.T) {
	body := "alice:" + aliceTok + "\n"
	write := func(t *testing.T, path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	refuse := func(t *testing.T, dir, path string) {
		t.Helper()
		err := startTokens(t, dir, path, "")
		if err == nil || !strings.Contains(err.Error(), "AUTH_TOKENS_FILE") || strings.Contains(err.Error(), aliceTok) {
			t.Fatalf("err %v", err)
		}
	}
	t.Run("workspace", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "workspace", "tokens")
		write(t, path)
		refuse(t, dir, path)
	})
	t.Run("symlink target", func(t *testing.T) {
		dir := t.TempDir()
		outside := t.TempDir()
		target := filepath.Join(dir, "workspace", "tokens")
		write(t, target)
		link := filepath.Join(outside, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		refuse(t, dir, link)
	})
	t.Run("cli home", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "cli", "b1", "home", "tokens")
		write(t, path)
		refuse(t, dir, path)
	})
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
	if err == nil || !strings.Contains(err.Error(), "name \"default\" is reserved") || strings.Contains(err.Error(), "duplicate name") || strings.Contains(err.Error(), strings.Repeat("d", 32)) {
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
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
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
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
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

func TestAuthTokensFileHardLink(t *testing.T) {
	dir := t.TempDir()
	path := writeTokenFile(t, dir, "alice:"+aliceTok+"\n", 0o600)
	if err := os.Link(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	err := startTokens(t, dir, path, "")
	if err == nil || !strings.Contains(err.Error(), "hard link") || strings.Contains(err.Error(), aliceTok) {
		t.Fatalf("err %v", err)
	}
	st, statErr := os.Stat(path)
	if statErr != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st, statErr)
	}
}

func TestAuthTokensASCIITrim(t *testing.T) {
	tok := strings.Repeat("z", 32)
	t.Run("spaces tabs crlf", func(t *testing.T) {
		dir := t.TempDir()
		path := writeTokenFile(t, dir, " \talice\t: \t"+tok+" \t\r\n", 0o600)
		app := newTokenApp(t, dir, path, "", "")
		srv := httptest.NewServer(app.Handler())
		t.Cleanup(srv.Close)
		if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, tok); res.StatusCode != 200 {
			t.Fatalf("trimmed %d", res.StatusCode)
		}
	})
	for _, tc := range []struct {
		name string
		body string
	}{
		{"leading nbsp", "alice:\u00A0" + tok + "\n"},
		{"trailing nbsp", "alice:" + tok + "\u00A0\n"},
		{"em space", "alice:" + tok + "\u2003\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeTokenFile(t, dir, tc.body, 0o600)
			err := startTokens(t, dir, path, "")
			if err == nil || !strings.Contains(err.Error(), "invalid token") || strings.Contains(err.Error(), tok) {
				t.Fatalf("err %v", err)
			}
		})
	}
}

func TestAuthTokensReloadSwaps(t *testing.T) {
	buf := captureStartup(t)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	path := writeTokenFile(t, dir, "alice:"+aliceTok+"\n", 0o600)
	app := newTokenApp(t, dir, path, "", auditPath)
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, aliceTok); res.StatusCode != 200 {
		t.Fatalf("before %d", res.StatusCode)
	}
	writeTokenFile(t, dir, "bob:"+bobTok+"\n", 0o600)
	app.ReloadAuthTokens()
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, aliceTok); res.StatusCode != 401 {
		t.Fatalf("old bearer %d", res.StatusCode)
	}
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, bobTok); res.StatusCode != 200 {
		t.Fatalf("new bearer %d", res.StatusCode)
	}
	res, cookie := loginCookie(t, srv.URL, aliceTok)
	if res.StatusCode != 401 || cookie != nil {
		t.Fatalf("old login %d cookie %+v", res.StatusCode, cookie)
	}
	res, cookie = loginCookie(t, srv.URL, bobTok)
	if res.StatusCode != http.StatusSeeOther || cookie == nil || cookie.Value != bobTok {
		t.Fatalf("new login %d cookie %+v", res.StatusCode, cookie)
	}
	secs := app.authSecrets()
	joined := strings.Join(secs, "\n")
	if strings.Contains(joined, aliceTok) || !strings.Contains(joined, bobTok) {
		t.Fatalf("secrets %q", joined)
	}
	log := buf.String()
	if !strings.Contains(log, "local-grok-bots: reloaded AUTH_TOKENS_FILE (1 tokens)") || strings.Contains(log, aliceTok) || strings.Contains(log, bobTok) {
		t.Fatalf("log:\n%s", log)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"action":"auth_tokens_reloaded"`) || !strings.Contains(text, `"count":1`) || strings.Contains(text, aliceTok) || strings.Contains(text, bobTok) {
		t.Fatalf("audit:\n%s", text)
	}
}

func TestAuthTokensReloadKeepsOldOnFailure(t *testing.T) {
	buf := captureStartup(t)
	dir := t.TempDir()
	path := writeTokenFile(t, dir, "alice:"+aliceTok+"\n", 0o600)
	app := newTokenApp(t, dir, path, "", "")
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)

	t.Run("bad line", func(t *testing.T) {
		bad := "not-a-pair-" + strings.Repeat("q", 16)
		writeTokenFile(t, dir, bad+"\n", 0o600)
		app.ReloadAuthTokens()
		if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, aliceTok); res.StatusCode != 200 {
			t.Fatalf("kept %d", res.StatusCode)
		}
		log := buf.String()
		if !strings.Contains(log, "local-grok-bots: WARN: AUTH_TOKENS_FILE reload failed; keeping the previous tokens:") || strings.Contains(log, aliceTok) || strings.Contains(log, bad) {
			t.Fatalf("log:\n%s", log)
		}
	})
	t.Run("empty", func(t *testing.T) {
		writeTokenFile(t, dir, "", 0o600)
		app.ReloadAuthTokens()
		if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, aliceTok); res.StatusCode != 200 {
			t.Fatalf("empty kept %d", res.StatusCode)
		}
		if !strings.Contains(buf.String(), "local-grok-bots: WARN: AUTH_TOKENS_FILE reload failed; keeping the previous tokens:") {
			t.Fatalf("log:\n%s", buf.String())
		}
	})
	t.Run("hard link", func(t *testing.T) {
		writeTokenFile(t, dir, "alice:"+aliceTok+"\n", 0o600)
		if err := os.Link(path, filepath.Join(dir, "tokens-link")); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
		app.ReloadAuthTokens()
		if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, aliceTok); res.StatusCode != 200 {
			t.Fatalf("link kept %d", res.StatusCode)
		}
		if !strings.Contains(buf.String(), "hard link") || strings.Contains(buf.String(), aliceTok) {
			t.Fatalf("log:\n%s", buf.String())
		}
	})
}

func TestAuthTokensReloadFailureAudited(t *testing.T) {
	buf := captureStartup(t)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	path := writeTokenFile(t, dir, "alice:"+aliceTok+"\n", 0o600)
	app := newTokenApp(t, dir, path, "", auditPath)
	bad := "not-a-pair-" + strings.Repeat("q", 16)
	writeTokenFile(t, dir, bad+"\n", 0o600)
	app.ReloadAuthTokens()

	log := buf.String()
	const warn = "local-grok-bots: WARN: AUTH_TOKENS_FILE reload failed; keeping the previous tokens:"
	if !strings.Contains(log, warn) || !strings.Contains(log, "invalid line") || strings.Contains(log, aliceTok) || strings.Contains(log, bad) {
		t.Fatalf("log:\n%s", log)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, aliceTok) || strings.Contains(text, bad) || strings.Contains(text, "invalid line") || strings.Contains(text, "auth tokens:") {
		t.Fatalf("audit leaked:\n%s", text)
	}
	var rows []map[string]any
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("row %q: %v", line, err)
		}
		rows = append(rows, row)
	}
	if len(rows) != 1 {
		t.Fatalf("rows %d:\n%s", len(rows), text)
	}
	row := rows[0]
	if len(row) != 2 || row["action"] != "auth_tokens_reload_failed" || row["ts"] == "" {
		t.Fatalf("row %#v", row)
	}
	if _, ok := row["ts"].(string); !ok {
		t.Fatalf("ts %#v", row["ts"])
	}
}

func TestAuthTokensReloadRace(t *testing.T) {
	dir := t.TempDir()
	path := writeTokenFile(t, dir, "alice:"+aliceTok+"\n", 0o600)
	app := newTokenApp(t, dir, path, "", "")
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	bodies := []string{"alice:" + aliceTok + "\n", "bob:" + bobTok + "\n"}
	wg.Add(2)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			i++
			next := path + ".next"
			if err := os.WriteFile(next, []byte(bodies[i%2]), 0o600); err != nil {
				return
			}
			if err := os.Chmod(next, 0o600); err != nil {
				return
			}
			if err := os.Rename(next, path); err != nil {
				return
			}
			app.ReloadAuthTokens()
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = app.authSecrets()
			_ = app.tokensConfigured()
			_ = app.configuredTokens()
			for _, tok := range []string{aliceTok, bobTok} {
				res, _ := do(t, "GET", srv.URL+"/api/bots", nil, tok)
				if res.StatusCode != 200 && res.StatusCode != 401 {
					t.Errorf("status %d", res.StatusCode)
					return
				}
			}
		}
	}()
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
	writeTokenFile(t, dir, "bob:"+bobTok+"\n", 0o600)
	app.ReloadAuthTokens()
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, bobTok); res.StatusCode != 200 {
		t.Fatalf("bob %d", res.StatusCode)
	}
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, aliceTok); res.StatusCode != 401 {
		t.Fatalf("alice %d", res.StatusCode)
	}
}

func TestAuthTokensSymlinkedParent(t *testing.T) {
	body := "alice:" + aliceTok + "\n"
	t.Run("into workspace", func(t *testing.T) {
		dir := t.TempDir()
		ws := filepath.Join(dir, "workspace")
		if err := os.MkdirAll(ws, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "via")
		if err := os.Symlink(ws, link); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(link, "tokens")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		err := startTokens(t, dir, path, "")
		if err == nil || !strings.Contains(err.Error(), "AUTH_TOKENS_FILE") || strings.Contains(err.Error(), aliceTok) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("outside", func(t *testing.T) {
		dir := t.TempDir()
		real := t.TempDir()
		link := filepath.Join(t.TempDir(), "via")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(link, "tokens")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		app := newTokenApp(t, dir, path, "", "")
		raw, err := filepath.Abs(path)
		if err != nil {
			t.Fatal(err)
		}
		raw = filepath.Clean(raw)
		resolved, err := filepath.EvalSymlinks(raw)
		if err != nil {
			t.Fatal(err)
		}
		resolved = filepath.Clean(resolved)
		if raw == resolved {
			t.Fatalf("symlink parent %s resolved to itself", raw)
		}
		secrets := app.daemonSecrets()
		for _, p := range []string{raw, resolved} {
			if !coiListed(secrets, p) {
				t.Fatalf("secrets %v lack %s", secrets, p)
			}
		}
	})
}
