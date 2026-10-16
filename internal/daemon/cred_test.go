package daemon

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

type captureTrip func(*http.Request) (*http.Response, error)

func (f captureTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGrokIsolationUsesLoopbackProxy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	real := filepath.Join(home, ".grok", "auth.json")
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	const marker = "unit-real-marker-value"
	body := `{"https://auth.x.ai::x":{"key":"` + marker + `","refresh_token":"unit-refresh-value","expires_at":"2099-01-01T00:00:00Z"}}`
	if err := os.WriteFile(real, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	app.noGrokProxy = false
	var gotAuth string
	var calls atomic.Int32
	app.grokTrip = captureTrip(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		gotAuth = r.Header.Get("Authorization")
		if r.Header.Get("Cookie") != "" || r.Header.Get("X-Secret") != "" {
			t.Errorf("forwarded a stripped header")
		}
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	t.Setenv("XAI_API_KEY", marker)
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	iso, err := app.cliIsolation(store.Bot{ID: "b1"}, "grok", ws, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if iso.ReleaseGate != nil {
		t.Cleanup(iso.ReleaseGate)
	}
	env := strings.Join(iso.Env, "\n")
	if strings.Contains(env, marker) {
		t.Fatal("real marker reached the cli env")
	}
	key := envValue(iso.Env, "XAI_API_KEY")
	if len(key) < 16 || key == marker || key == clisession.GrokPlaceholderToken || strings.Contains(key, "unit-refresh") {
		t.Fatalf("gate %q", key)
	}
	base := envValue(iso.Env, "GROK_CLI_CHAT_PROXY_BASE_URL")
	for _, name := range []string{"GROK_XAI_API_BASE_URL", "XAI_API_BASE_URL"} {
		v := envValue(iso.Env, name)
		if v == "" || !strings.HasPrefix(v, "http://127.0.0.1:") || !strings.HasSuffix(v, "/v1") {
			t.Fatalf("%s=%q", name, v)
		}
	}
	if !strings.HasPrefix(base, "http://127.0.0.1:") || !strings.HasSuffix(base, "/v1") {
		t.Fatalf("chat base %q", base)
	}
	fi, err := os.Stat(real)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		t.Fatalf("nlink %v", st)
	}
	botAuth := filepath.Join(dir, "cli", "b1", "home", ".grok", "auth.json")
	dst, err := os.Lstat(botAuth)
	if err != nil || dst.Mode()&os.ModeSymlink != 0 || os.SameFile(fi, dst) {
		t.Fatalf("bot auth %v %v", dst, err)
	}
	got, err := os.ReadFile(botAuth)
	if err != nil || strings.Contains(string(got), marker) || strings.Contains(string(got), clisession.GrokPlaceholderToken) || !strings.Contains(string(got), key) {
		t.Fatal("bot auth is not the per-run placeholder")
	}
	user, err := os.ReadFile(real)
	if err != nil || string(user) != body {
		t.Fatal("user login changed")
	}
	origin := strings.TrimSuffix(base, "/v1")
	client := &http.Client{Timeout: 2 * time.Second}
	for _, auth := range []string{"", "Bearer " + clisession.GrokPlaceholderToken, "Bearer " + marker, "Bearer nope-not-the-gate"} {
		code, respBody := proxyDo(t, client, origin+"/v1/ping", auth)
		if code != http.StatusForbidden || strings.Contains(respBody, marker) || strings.Contains(respBody, key) {
			t.Fatalf("auth %q status %d body %s", auth, code, respBody)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("rejected client reached upstream")
	}
	code, respBody := proxyDo(t, client, origin+"/admin", "Bearer "+key)
	if code != http.StatusForbidden || calls.Load() != 0 {
		t.Fatalf("admin %d calls %d body %s", code, calls.Load(), respBody)
	}
	code, respBody = proxyDo(t, client, origin+"/v1/ping", "Bearer "+key)
	if code != http.StatusNoContent || calls.Load() != 1 {
		t.Fatalf("allow %d calls %d body %s", code, calls.Load(), respBody)
	}
	if gotAuth != "Bearer "+marker || strings.Contains(gotAuth, key) {
		t.Fatalf("upstream auth %q", gotAuth)
	}
	iso.ReleaseGate()
	code, _ = proxyDo(t, client, origin+"/v1/ping", "Bearer "+key)
	if code != http.StatusForbidden || calls.Load() != 1 {
		t.Fatalf("revoked %d calls %d", code, calls.Load())
	}
}

func TestGrokProxyGateIsPerBotRun(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	real := filepath.Join(home, ".grok", "auth.json")
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	const marker = "unit-real-marker-value"
	body := `{"https://auth.x.ai::x":{"key":"` + marker + `","expires_at":"2099-01-01T00:00:00Z"}}`
	if err := os.WriteFile(real, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	app.noGrokProxy = false
	var calls atomic.Int32
	app.grokTrip = captureTrip(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+marker {
			t.Errorf("upstream auth %q", r.Header.Get("Authorization"))
		}
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	first, err := app.cliIsolation(store.Bot{ID: "b1"}, "grok", ws, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.cliIsolation(store.Bot{ID: "b2"}, "grok", ws, "run-2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if first.ReleaseGate != nil {
			first.ReleaseGate()
		}
		if second.ReleaseGate != nil {
			second.ReleaseGate()
		}
	})
	k1 := envValue(first.Env, "XAI_API_KEY")
	k2 := envValue(second.Env, "XAI_API_KEY")
	if k1 == "" || k2 == "" || k1 == k2 || k1 == clisession.GrokPlaceholderToken {
		t.Fatalf("gates %q %q", k1, k2)
	}
	origin1 := strings.TrimSuffix(envValue(first.Env, "GROK_CLI_CHAT_PROXY_BASE_URL"), "/v1")
	origin2 := strings.TrimSuffix(envValue(second.Env, "GROK_CLI_CHAT_PROXY_BASE_URL"), "/v1")
	if origin1 == origin2 || !strings.Contains(origin1, "/bots/b1/runs/run-1") || !strings.Contains(origin2, "/bots/b2/runs/run-2") {
		t.Fatalf("origins %q %q", origin1, origin2)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	if code, _ := proxyDo(t, client, origin1+"/v1/ping", "Bearer "+k1); code != http.StatusNoContent {
		t.Fatalf("first %d", code)
	}
	if code, _ := proxyDo(t, client, origin2+"/v1/ping", "Bearer "+k2); code != http.StatusNoContent {
		t.Fatalf("second %d", code)
	}
	if code, _ := proxyDo(t, client, origin2+"/v1/ping", "Bearer "+k1); code != http.StatusForbidden {
		t.Fatalf("first secret on second run %d", code)
	}
	if code, _ := proxyDo(t, client, origin1+"/v1/ping", "Bearer "+k2); code != http.StatusForbidden {
		t.Fatalf("second secret on first run %d", code)
	}
	first.ReleaseGate()
	if code, _ := proxyDo(t, client, origin1+"/v1/ping", "Bearer "+k1); code != http.StatusForbidden {
		t.Fatalf("first still admitted %d", code)
	}
	if code, _ := proxyDo(t, client, origin2+"/v1/ping", "Bearer "+k2); code != http.StatusNoContent {
		t.Fatalf("second revoked with first %d", code)
	}
	if calls.Load() != 3 {
		t.Fatalf("upstream calls %d", calls.Load())
	}
}

func envValue(env []string, name string) string {
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if k == name {
			return v
		}
	}
	return ""
}

func proxyDo(t *testing.T, client *http.Client, url, auth string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestStartupRemovesStaleGrokLogin(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	real := filepath.Join(home, ".grok", "auth.json")
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"https://auth.x.ai::x":{"key":"unit-real-marker-value","refresh_token":"unit-refresh-value"}}`)
	if err := os.WriteFile(real, body, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	hard := filepath.Join(dir, "cli", "old", "home", ".grok", "auth.json")
	sym := filepath.Join(dir, "cli", "old2", "grok-home", "auth.json")
	if err := os.MkdirAll(filepath.Dir(hard), 0o700); err != nil || os.MkdirAll(filepath.Dir(sym), 0o700) != nil {
		t.Fatal("mkdir")
	}
	if err := os.Link(real, hard); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, sym); err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(dir, "cli", "old3", "home", ".grok", "auth.json")
	keep := filepath.Join(dir, "cli", "keep", "home", ".grok", "auth.json")
	if err := os.MkdirAll(filepath.Dir(copied), 0o700); err != nil || os.MkdirAll(filepath.Dir(keep), 0o700) != nil {
		t.Fatal("mkdir")
	}
	if err := os.WriteFile(copied, []byte(`{"note":"unit-refresh-value leaked"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keep, []byte(clisession.GrokPlaceholderAuth), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = newApp(t, dir, nil)
	if _, err := os.Lstat(hard); !os.IsNotExist(err) {
		t.Fatalf("hardlink remains: %v", err)
	}
	if _, err := os.Lstat(sym); !os.IsNotExist(err) {
		t.Fatalf("symlink remains: %v", err)
	}
	if _, err := os.Lstat(copied); !os.IsNotExist(err) {
		t.Fatalf("copy remains: %v", err)
	}
	kept, err := os.ReadFile(keep)
	if err != nil || string(kept) != clisession.GrokPlaceholderAuth {
		t.Fatalf("placeholder removed: %q %v", kept, err)
	}
	fi, err := os.Stat(real)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		t.Fatalf("nlink %v", st)
	}
	got, err := os.ReadFile(real)
	if err != nil || string(got) != string(body) {
		t.Fatal("user login changed")
	}
}

func TestDeleteBotRemovesGrokLogin(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	real := filepath.Join(home, ".grok", "auth.json")
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("not-json-but-regular\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	app := newApp(t, "", nil)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Cred")
	hard := filepath.Join(app.cfg.DataDir, "cli", bot.ID, "home", ".grok", "auth.json")
	sym := filepath.Join(app.cfg.DataDir, "cli", bot.ID, "grok-home", "auth.json")
	if err := os.MkdirAll(filepath.Dir(hard), 0o700); err != nil || os.MkdirAll(filepath.Dir(sym), 0o700) != nil {
		t.Fatal("mkdir")
	}
	if err := os.Link(real, hard); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, sym); err != nil {
		t.Fatal(err)
	}
	res, b := do(t, http.MethodDelete, srv.URL+"/api/bots/"+bot.ID, nil, "")
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete %d %s", res.StatusCode, b)
	}
	for _, p := range []string{hard, sym} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("%s remains: %v", p, err)
		}
	}
	fi, err := os.Stat(real)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		t.Fatalf("nlink %v", st)
	}
	if _, err := os.Lstat(filepath.Join(app.cfg.DataDir, "cli", bot.ID)); !os.IsNotExist(err) {
		t.Fatalf("cli dir remains: %v", err)
	}
}

func TestDeleteBotDropsSymlinkWithoutFollowing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	app := newApp(t, "", nil)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Cred")
	outside := t.TempDir()
	canary := filepath.Join(outside, "canary")
	if err := os.WriteFile(canary, []byte("canary-keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	botDir := filepath.Join(app.cfg.DataDir, "cli", bot.ID)
	if err := os.MkdirAll(filepath.Join(botDir, "home", ".grok"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(botDir, "home", ".grok", "auth.json"), []byte("placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(botDir, "linked")); err != nil {
		t.Fatal(err)
	}
	res, b := do(t, http.MethodDelete, srv.URL+"/api/bots/"+bot.ID, nil, "")
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete %d %s", res.StatusCode, b)
	}
	if _, err := os.Lstat(botDir); !os.IsNotExist(err) {
		t.Fatalf("cli dir remains: %v", err)
	}
	got, err := os.ReadFile(canary)
	if err != nil || string(got) != "canary-keep" {
		t.Fatalf("canary %q %v", got, err)
	}
	if _, err := os.Lstat(outside); err != nil {
		t.Fatal(err)
	}
}

func TestSymlinkParentIsAudited(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	outside := t.TempDir()
	canary := filepath.Join(outside, "canary")
	if err := os.WriteFile(canary, []byte("canary-keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	botHome := filepath.Join(dir, "cli", "b1", "home")
	if err := os.MkdirAll(filepath.Dir(botHome), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, botHome); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = app.cliIsolation(store.Bot{ID: "b1"}, "grok", ws, "run-9")
	if !errors.Is(err, clisession.ErrCredSymlink) {
		t.Fatalf("err %v", err)
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"event":"cli_cred_symlink_refused"`) || !strings.Contains(text, `"bot_id":"b1"`) || !strings.Contains(text, `"run_id":"run-9"`) {
		t.Fatalf("audit %s", text)
	}
	if strings.Contains(text, outside) || strings.Contains(text, "canary-keep") {
		t.Fatalf("audit names the link: %s", text)
	}
	got, err := os.ReadFile(canary)
	if err != nil || string(got) != "canary-keep" {
		t.Fatalf("canary %q %v", got, err)
	}
}

func TestExpiredGrokLoginRefusesProxy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	real := filepath.Join(home, ".grok", "auth.json")
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"https://auth.x.ai::x":{"key":"unit-real-marker-value","expires_at":"2000-01-01T00:00:00Z"}}`)
	if err := os.WriteFile(real, body, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	app.noGrokProxy = false
	logPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	ws := filepath.Join(dir, "ws")
	_ = os.MkdirAll(ws, 0o755)
	if _, err := app.cliIsolation(store.Bot{ID: "b1"}, "grok", ws, "run-1"); err == nil {
		t.Fatal("expired login started a turn")
	}
	evs, err := app.st.ListLog("b1", "cli_proxy_unavailable", "", 10)
	if err != nil || len(evs) != 1 {
		t.Fatalf("log %v %v", evs, err)
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(raw), `"event":"cli_proxy_unavailable"`) || strings.Contains(string(raw), "unit-real-marker-value") {
		t.Fatalf("audit %s %v", raw, err)
	}
	got, _ := os.ReadFile(real)
	if string(got) != string(body) {
		t.Fatal("expired login was rewritten")
	}
}
