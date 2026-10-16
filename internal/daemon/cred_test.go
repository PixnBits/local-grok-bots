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
