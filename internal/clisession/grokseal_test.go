package clisession

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSealGrokHomeCreatesKnownNames(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "gh")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SealGrokHome(root, home); err != nil {
		t.Fatal(err)
	}
	if err := SealGrokHome(root, home); err != nil {
		t.Fatalf("second seal: %v", err)
	}
	cfg, err := os.ReadFile(filepath.Join(home, "config.toml"))
	if err != nil || string(cfg) != grokPermissionTOML() {
		t.Fatalf("config %q %v", cfg, err)
	}
	for _, name := range []string{"requirements.toml", "trusted_folders.toml", "managed_config.toml", "hooks-paths"} {
		b, err := os.ReadFile(filepath.Join(home, name))
		if err != nil || string(b) != grokSealMarker {
			t.Fatalf("%s %q %v", name, b, err)
		}
	}
	for _, name := range []string{"hooks", "plugins", "skills", "agents"} {
		b, err := os.ReadFile(filepath.Join(home, name, grokSealDirEntry))
		if err != nil || string(b) != grokSealMarker {
			t.Fatalf("%s %q %v", name, b, err)
		}
	}
	sess := filepath.Join(home, "sessions")
	if err := os.MkdirAll(sess, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sess, "n"), []byte("n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SealGrokHome(root, home); err != nil {
		t.Fatalf("session dir blocked a seal: %v", err)
	}
}

func TestSealGrokHomeLeavesForeignFile(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "gh")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	planted := []byte("planted\n")
	path := filepath.Join(home, "requirements.toml")
	if err := os.WriteFile(path, planted, 0o600); err != nil {
		t.Fatal(err)
	}
	err := SealGrokHome(root, home)
	var ue *UntrustedConfigError
	if !errors.As(err, &ue) || len(ue.Names) != 1 || ue.Names[0] != "requirements.toml" {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), "planted") {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(planted) {
		t.Fatalf("overwrote %q %v", got, err)
	}
}

func TestSealGrokHomeRefusesSymlink(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "gh")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "hooks")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	err := SealGrokHome(root, home)
	var ue *UntrustedConfigError
	if !errors.As(err, &ue) || len(ue.Names) != 1 || ue.Names[0] != "hooks" {
		t.Fatal(err)
	}
	st, err := os.Lstat(link)
	if err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replaced: %v", err)
	}
}

func TestPrepareIsolationSealsGrokHome(t *testing.T) {
	user := t.TempDir()
	state := t.TempDir()
	home := filepath.Join(state, "home")
	iso, err := PrepareIsolation(IsolationOptions{Backend: "grok", StateDir: state, Home: home, UserHome: user})
	if err != nil {
		t.Fatal(err)
	}
	gh := filepath.Join(home, ".grok")
	if _, err := os.Stat(filepath.Join(gh, "requirements.toml")); err != nil {
		t.Fatal(err)
	}
	iso, err = PrepareIsolation(IsolationOptions{Backend: "grok", StateDir: state, Home: home, UserHome: user, Grants: Grants{Net: true}})
	if err != nil {
		t.Fatalf("second prepare: %v", err)
	}
	if !strings.Contains(strings.Join(iso.GrokTools, ","), "web_fetch") {
		t.Fatalf("tools %v", iso.GrokTools)
	}
	_, err = PrepareIsolation(IsolationOptions{
		Backend: "grok", StateDir: state, Home: home, UserHome: user,
		Extra: map[string]string{"GROK_CONFIG": "x"},
	})
	if err == nil || !strings.Contains(err.Error(), "GROK_CONFIG") {
		t.Fatal(err)
	}
}

func TestRefuseHostConfig(t *testing.T) {
	if err := RefuseHostConfig(false, nil); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "absent.toml")
	if err := RefuseHostConfig(false, []string{missing}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.toml")
	if err := os.WriteFile(path, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, filepath.Join(dir, "link.toml")); err != nil {
		t.Fatal(err)
	}
	err := RefuseHostConfig(false, []string{path, filepath.Join(dir, "link.toml")})
	var ue *UntrustedConfigError
	if !errors.As(err, &ue) || len(ue.Names) != 2 {
		t.Fatal(err)
	}
	if err := RefuseHostConfig(true, []string{path}); err != nil {
		t.Fatal(err)
	}
	if got := PresentHostConfig([]string{path, missing}); len(got) != 1 || got[0] != path {
		t.Fatalf("present %v", got)
	}
}
