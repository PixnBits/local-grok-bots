package daemon

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

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
	t.Setenv("XAI_API_KEY", marker)
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	iso, err := app.cliIsolation(store.Bot{ID: "b1"}, "grok", ws)
	if err != nil {
		t.Fatal(err)
	}
	env := strings.Join(iso.Env, "\n")
	if strings.Contains(env, marker) {
		t.Fatal("real marker reached the cli env")
	}
	if !strings.Contains("\n"+env+"\n", "\nXAI_API_KEY="+clisession.GrokPlaceholderToken+"\n") {
		t.Fatal("placeholder key missing")
	}
	var base string
	for _, kv := range iso.Env {
		k, v, _ := strings.Cut(kv, "=")
		if k == "GROK_CLI_CHAT_PROXY_BASE_URL" {
			base = v
		}
		if k == "GROK_XAI_API_BASE_URL" || k == "XAI_API_BASE_URL" {
			if v == "" || !strings.HasPrefix(v, "http://127.0.0.1:") || !strings.HasSuffix(v, "/v1") {
				t.Fatalf("%s=%q", k, v)
			}
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
	if err != nil || string(got) != clisession.GrokPlaceholderAuth || strings.Contains(string(got), marker) {
		t.Fatal("bot auth is not the placeholder")
	}
	user, err := os.ReadFile(real)
	if err != nil || string(user) != body {
		t.Fatal("user login changed")
	}
	resp, err := http.Get(strings.TrimSuffix(base, "/v1") + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin %d", resp.StatusCode)
	}
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
	if _, err := app.cliIsolation(store.Bot{ID: "b1"}, "grok", ws); err == nil {
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
