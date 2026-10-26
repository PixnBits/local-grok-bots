package daemon

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/store"
	"golang.org/x/sys/unix"
)

func TestOllamaOnlyNeedsNoToken(t *testing.T) {
	app := newApp(t, "", nil)
	if app.cfg.AuthToken != "" {
		t.Fatalf("ollama-only got a token")
	}
	if _, err := os.Stat(filepath.Join(app.cfg.DataDir, adminTokenFile)); err == nil {
		t.Fatalf("ollama-only wrote a token file")
	}
	srv := serve(t, app)
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, ""); res.StatusCode != 200 {
		t.Fatalf("ollama-only list %d", res.StatusCode)
	}
}

func TestCLIBackendRequiresGeneratedToken(t *testing.T) {
	t.Setenv("AUTH_TOKEN", "")
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	tok := app.cfg.AuthToken
	path := filepath.Join(dir, adminTokenFile)
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 || len(tok) != 64 {
		t.Fatalf("token file %v %v len %d", err, st, len(tok))
	}
	srv := serve(t, app)
	if res, _ := do(t, "GET", srv.URL+"/api/health", nil, ""); res.StatusCode != 200 {
		t.Fatalf("health %d", res.StatusCode)
	}
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, ""); res.StatusCode != 401 {
		t.Fatalf("no token %d", res.StatusCode)
	}
	if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, tok); res.StatusCode != 200 {
		t.Fatalf("bearer %d", res.StatusCode)
	}
	// A CLI on this host has no token, so it can't decide its own requests.
	if res, _ := do(t, "POST", srv.URL+"/api/bots/b/runs/r/permissions/q", map[string]string{"decision": "allow_once"}, ""); res.StatusCode != 401 {
		t.Fatalf("decision without token %d", res.StatusCode)
	}
	if res, _ := do(t, "GET", srv.URL+"/login?token=wrong", nil, ""); res.StatusCode != 401 {
		t.Fatalf("bad login %d", res.StatusCode)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(srv.URL + "/login?token=" + tok)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == authCookie {
			cookie = c
		}
	}
	if res.StatusCode != http.StatusSeeOther || cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("login %d cookie %+v", res.StatusCode, cookie)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/api/bots", nil)
	req.AddCookie(cookie)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("cookie %d", res.StatusCode)
	}

	// The same token is reused on restart.
	app.Shutdown()
	app2 := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	if app2.cfg.AuthToken != tok {
		t.Fatalf("token changed on restart")
	}
}

func TestExplicitAuthTokenWins(t *testing.T) {
	dir := t.TempDir()
	cfgTok := "explicit-token-explicit-token-explicit"
	tok, path, err := ensureAdminToken(dir, cfgTok, true)
	if err != nil || tok != cfgTok || path != "" {
		t.Fatalf("%q %q %v", tok, path, err)
	}
	if _, err := os.Stat(filepath.Join(dir, adminTokenFile)); err == nil {
		t.Fatalf("wrote a file despite AUTH_TOKEN")
	}
}

func TestCLIEnvNeverCarriesAdminToken(t *testing.T) {
	t.Setenv("AUTH_TOKEN", "")
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	tok := app.cfg.AuthToken
	fileTok := strings.Repeat("e", 32)
	app.authTokens.Store(&authTokenSet{toks: []namedToken{{name: "alice", val: fileTok}}})
	t.Setenv("AUTH_TOKEN", tok)
	t.Setenv("AUTH_TOKENS_FILE", filepath.Join(dir, "tokens"))
	t.Setenv("SSL_CERT_FILE", "/etc/ssl/"+fileTok+".pem")
	t.Setenv("LGB_TOKEN_COPY", "x"+tok)
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"claude", "grok"} {
		iso, err := app.cliIsolation(store.Bot{ID: "bot1"}, backend, ws, "run-1")
		if err != nil {
			t.Fatal(err)
		}
		for _, kv := range iso.Env {
			if strings.HasPrefix(kv, "AUTH_TOKEN=") || strings.HasPrefix(kv, "AUTH_TOKENS_FILE=") || strings.Contains(kv, tok) || strings.Contains(kv, fileTok) {
				t.Fatalf("%s env leaks token: %s", backend, kv)
			}
		}
	}
}

func TestAdminTokenSymlinkIsRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte(strings.Repeat("a", 64)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, adminTokenFile)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureAdminToken(dir, "", true); err == nil {
		t.Fatal("symlinked admin token was followed")
	}
	st, err := os.Stat(target)
	if err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("target touched: %v %v", st.Mode(), err)
	}
}

func TestAdminTokenRefusesLooseMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, adminTokenFile)
	body := []byte(strings.Repeat("a", 64) + "\n")
	writeExact(t, path, body, 0o640)
	_, _, err := ensureAdminToken(dir, "", true)
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "mode") || strings.Contains(err.Error(), strings.Repeat("a", 64)) {
		t.Fatalf("err %v", err)
	}
	st, statErr := os.Lstat(path)
	got, _ := os.ReadFile(path)
	if statErr != nil || st.Mode().Perm() != 0o640 || string(got) != string(body) {
		t.Fatalf("mode %v body %q err %v", st.Mode(), got, statErr)
	}
}

func TestAdminTokenRefusesFIFO(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, adminTokenFile)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, _, err := ensureAdminToken(dir, "", true)
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "regular") || !strings.Contains(err.Error(), path) {
			t.Fatalf("err %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("admin token open blocked on a FIFO")
	}
}

func TestAdminTokenRefusesHardLink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, adminTokenFile)
	body := []byte(strings.Repeat("b", 64) + "\n")
	writeExact(t, path, body, 0o600)
	if err := os.Link(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	_, _, err := ensureAdminToken(dir, "", true)
	if err == nil || !strings.Contains(err.Error(), "hard link") || !strings.Contains(err.Error(), path) || strings.Contains(err.Error(), strings.Repeat("b", 64)) {
		t.Fatalf("err %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(body) {
		t.Fatalf("overwritten %q", got)
	}
}

func TestAdminTokenRefusesOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, adminTokenFile)
	body := []byte(strings.Repeat("c", adminTokenMax+1))
	writeExact(t, path, body, 0o600)
	_, _, err := ensureAdminToken(dir, "", true)
	if err == nil || !strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "cccc") {
		t.Fatalf("err %v", err)
	}
	got, _ := os.ReadFile(path)
	if len(got) != len(body) {
		t.Fatalf("len %d", len(got))
	}
}

func TestAdminTokenRefusesEmptyShortAndNonASCII(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"short", "short-token\n"},
		{"non-ascii", strings.Repeat("d", 32) + "é\n"},
		{"leading nbsp", "\u00A0" + strings.Repeat("e", 32) + "\n"},
		{"trailing nbsp", strings.Repeat("f", 32) + "\u00A0\n"},
		{"em space", strings.Repeat("g", 32) + "\u2003\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, adminTokenFile)
			writeExact(t, path, []byte(tc.body), 0o600)
			_, _, err := ensureAdminToken(dir, "", true)
			secret := strings.TrimRight(tc.body, "\n")
			if err == nil || !strings.Contains(err.Error(), path) || (secret != "" && strings.Contains(err.Error(), secret)) {
				t.Fatalf("err %v", err)
			}
			got, _ := os.ReadFile(path)
			if string(got) != tc.body {
				t.Fatalf("overwritten %q", got)
			}
		})
	}
}

func TestAdminTokenTrimsASCIISpace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, adminTokenFile)
	tok := strings.Repeat("h", 64)
	writeExact(t, path, []byte(" \t"+tok+" \t\r\n"), 0o600)
	got, gotPath, err := ensureAdminToken(dir, "", true)
	if err != nil || got != tok || gotPath != path {
		t.Fatalf("%q %q %v", got, gotPath, err)
	}
}

func TestAdminTokenGeneration(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "data")
	canary := filepath.Join(parent, "canary")
	if err := os.WriteFile(canary, []byte("canary-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The old predictable temp name must not be followed.
	if err := os.Symlink(canary, filepath.Join(dir, adminTokenFile+".tmp")); err != nil {
		t.Fatal(err)
	}
	tok, path, err := ensureAdminToken(dir, "", true)
	if err != nil || len(tok) != 64 || path != filepath.Join(dir, adminTokenFile) {
		t.Fatalf("%q %q %v", tok, path, err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st, err)
	}
	var ust unix.Stat_t
	if err := unix.Stat(path, &ust); err != nil || ust.Nlink != 1 {
		t.Fatalf("nlink %d %v", ust.Nlink, err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp left behind: %s", e.Name())
		}
	}
	raw, _ := os.ReadFile(canary)
	if string(raw) != "canary-bytes" {
		t.Fatalf("old temp name was followed: %q", raw)
	}
	dst, err := os.Lstat(dir)
	if err != nil || !dst.IsDir() || dst.Mode().Perm()&0o022 != 0 {
		t.Fatalf("data dir %v %v", dst.Mode(), err)
	}
}

func TestAdminTokenTempSymlinkIsNotFollowed(t *testing.T) {
	dir := t.TempDir()
	canary := filepath.Join(t.TempDir(), "canary")
	if err := os.WriteFile(canary, []byte("canary-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, adminTokenFile+".tmp-fixed")
	if err := os.Symlink(canary, tmp); err != nil {
		t.Fatal(err)
	}
	prev := adminTokenTempPath
	adminTokenTempPath = func(string) (string, error) { return tmp, nil }
	t.Cleanup(func() { adminTokenTempPath = prev })
	if _, _, err := ensureAdminToken(dir, "", true); err == nil {
		t.Fatal("temp symlink was followed")
	}
	raw, err := os.ReadFile(canary)
	if err != nil || string(raw) != "canary-bytes" {
		t.Fatalf("canary %q %v", raw, err)
	}
	lst, err := os.Lstat(tmp)
	if err != nil || lst.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("temp symlink replaced: %v %v", lst, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, adminTokenFile)); err == nil {
		t.Fatal("admin token written through the temp symlink")
	}
}

func TestAdminTokenDataDirRefused(t *testing.T) {
	t.Run("group writable", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o775); err != nil {
			t.Fatal(err)
		}
		_, _, err := ensureAdminToken(dir, "", true)
		if err == nil || !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "writable") {
			t.Fatalf("err %v", err)
		}
		if _, statErr := os.Lstat(filepath.Join(dir, adminTokenFile)); !os.IsNotExist(statErr) {
			t.Fatalf("token file created: %v", statErr)
		}
		st, statErr := os.Lstat(dir)
		if statErr != nil || st.Mode().Perm() != 0o775 {
			t.Fatalf("dir mode %v %v", st.Mode(), statErr)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		real := t.TempDir()
		parent := t.TempDir()
		link := filepath.Join(parent, "data")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		_, _, err := ensureAdminToken(link, "", true)
		if err == nil || !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("err %v", err)
		}
		if _, statErr := os.Lstat(filepath.Join(real, adminTokenFile)); !os.IsNotExist(statErr) {
			t.Fatalf("wrote through DATA_DIR symlink: %v", statErr)
		}
	})
}

func writeExact(t *testing.T, path string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
