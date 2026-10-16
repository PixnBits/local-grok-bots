package coi

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestReadBearerDoesNotWrite(t *testing.T) {
	if clisession.GrokPlaceholderToken != PlaceholderToken {
		t.Fatal("placeholder token drifted")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	body := []byte(`{"https://auth.x.ai::x":{"key":"live-access-token","refresh_token":"live-refresh-token","expires_at":"2099-01-01T00:00:00Z"}}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	tok, err := ReadBearer(path)
	if err != nil || tok != "live-access-token" {
		t.Fatalf("bearer err=%v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(body) {
		t.Fatal("read rewrote the login file")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("left a temp file")
	}
	expired := []byte(`{"https://auth.x.ai::x":{"key":"live-access-token","refresh_token":"live-refresh-token","expires_at":"2000-01-01T00:00:00Z"}}`)
	if err := os.WriteFile(path, expired, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBearer(path); !errors.Is(err, ErrLoginUnusable) {
		t.Fatalf("expired err=%v", err)
	}
	got, _ = os.ReadFile(path)
	if string(got) != string(expired) {
		t.Fatal("expired read rewrote the login file")
	}
}

func TestJailCredentialGate(t *testing.T) {
	tool := policy.CLITool{
		CredentialFiles: []string{".grok/auth.json"},
		FixedArgs:       []string{"--always-approve"},
	}
	if err := JailCredentialGate(tool); err != ErrJailCredentials {
		t.Fatal(err)
	}
	tool.AllowJailCredentials = true
	if err := JailCredentialGate(tool); err != nil {
		t.Fatal(err)
	}
	tool.AllowJailCredentials = false
	tool.ProxyHosts = []string{"api.x.ai"}
	if err := JailCredentialGate(tool); err != nil {
		t.Fatal(err)
	}
	if UsesJailCredentials(tool) {
		t.Fatal("proxy mode copied credentials")
	}
}

func TestPlaceholderOmitsSecret(t *testing.T) {
	root := t.TempDir()
	cred := filepath.Join(root, "cred")
	if err := os.MkdirAll(filepath.Join(cred, ".grok"), 0o700); err != nil {
		t.Fatal(err)
	}
	secret := "hunter2-hunter2-secret"
	if err := os.WriteFile(filepath.Join(cred, ".grok", "auth.json"), []byte(`{"key":"`+secret+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	home, err := prepareJailHome(root, policy.CLITool{
		Name: "grok", CredentialHome: cred, CredentialFiles: []string{".grok/auth.json"},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	if !strings.HasPrefix(home, filepath.Join(root, "coi", "homes")+string(os.PathSeparator)) {
		t.Fatalf("home %s", home)
	}
	b, err := os.ReadFile(filepath.Join(home, ".grok", "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) || !strings.Contains(string(b), PlaceholderToken) {
		t.Fatalf("placeholder %s", b)
	}
	if _, err := os.Stat(filepath.Join(home, ".grok", "sandbox.toml")); !os.IsNotExist(err) {
		t.Fatal("wrote sandbox.toml")
	}
	st, err := os.Stat(filepath.Dir(home))
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("homes mode %v", st)
	}
}

func TestCleanStaleHomes(t *testing.T) {
	root := t.TempDir()
	dir := HomesDir(root)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "coi-home-old")
	keep := filepath.Join(dir, "keep")
	sibling := filepath.Join(root, "coi", "coi-home-sibling")
	if err := os.MkdirAll(stale, 0o700); err != nil || os.MkdirAll(keep, 0o700) != nil || os.MkdirAll(sibling, 0o700) != nil {
		t.Fatal(err)
	}
	hostStale := filepath.Join(os.TempDir(), "coi-home-leave-"+filepath.Base(root))
	if err := os.MkdirAll(hostStale, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(hostStale) })
	CleanStaleHomes(root)
	CleanStaleHomes("")
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale home remains")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sibling); err != nil {
		t.Fatal("cleaned outside the homes directory")
	}
	if _, err := os.Stat(hostStale); err != nil {
		t.Fatal("cleaned the host temp directory")
	}
}

func TestRefreshReplacesExpiredToken(t *testing.T) {
	var sawGrant bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := ioRead(r)
		sawGrant = strings.Contains(b, "grant_type=refresh_token")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access-token","refresh_token":"new-refresh-token","expires_in":3600}`))
	}))
	defer ts.Close()
	prev := tokenEndpoint
	tokenEndpoint = ts.URL
	t.Cleanup(func() { tokenEndpoint = prev })

	root := t.TempDir()
	cred := filepath.Join(root, "cred")
	if err := os.MkdirAll(filepath.Join(cred, ".grok"), 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{"https://auth.x.ai::00000000-0000-4000-8000-000000000001":{"key":"old-access-token","refresh_token":"old-refresh-token","expires_at":"2000-01-01T00:00:00Z","oidc_client_id":"client"}}`
	path := filepath.Join(cred, ".grok", "auth.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	tool := policy.CLITool{CredentialHome: cred, CredentialFiles: []string{".grok/auth.json"}, ProxyHosts: []string{"api.test"}}
	if err := ProxyPreflight(tool); err != nil {
		t.Fatal(err)
	}
	tok, err := AccessToken(tool)
	if err != nil || tok != "new-access-token" || !sawGrant {
		t.Fatalf("token err=%v grant=%v", err, sawGrant)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "old-access-token") || !strings.Contains(string(got), "new-access-token") {
		t.Fatal("credential file was not updated")
	}
	if strings.Contains(string(got), "old-refresh-token") {
		t.Fatal("refresh token was not rotated")
	}
}

func ioRead(r *http.Request) (string, error) {
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	return string(b), err
}
