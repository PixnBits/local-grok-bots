package clisession

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPermissionBodyUpgrades(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "gh")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "config.toml")
	if err := os.WriteFile(path, []byte(grokPermissionTOMLPrevious()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SealGrokHome(root, home); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != grokPermissionTOML() || !strings.Contains(string(got), "disable_web_search = true") {
		t.Fatalf("upgraded %q %v", got, err)
	}
	planted := []byte("nope\n")
	if err := os.WriteFile(path, planted, 0o600); err != nil {
		t.Fatal(err)
	}
	err = SealGrokHome(root, home)
	var ue *UntrustedConfigError
	if !errors.As(err, &ue) || len(ue.Names) != 1 || ue.Names[0] != "config.toml" {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), "nope") {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil || string(got) != string(planted) {
		t.Fatalf("overwrote %q %v", got, err)
	}
}

func TestGrokHomeNamesAllowlist(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "gh")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SealGrokHome(root, home); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"auth.json", "sandbox.toml", "version.json"} {
		if err := os.WriteFile(filepath.Join(home, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(home, "cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "managed_config.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SealGrokHome(root, home); err != nil {
		t.Fatal(err)
	}
	planted := []byte("{\n")
	lsp := filepath.Join(home, "lsp.json")
	if err := os.WriteFile(lsp, planted, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, "commands"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "AGENTS.md"), []byte("#\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "config.toml"), filepath.Join(home, "version-link")); err != nil {
		t.Fatal(err)
	}
	err := SealGrokHome(root, home)
	var ue *UntrustedConfigError
	if !errors.As(err, &ue) {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), "lsp") || strings.Contains(err.Error(), "{") {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, n := range ue.Names {
		names[n] = true
	}
	for _, want := range []string{"lsp.json", "commands", "AGENTS.md", "version-link"} {
		if !names[want] {
			t.Fatalf("names %v", ue.Names)
		}
	}
	got, err := os.ReadFile(lsp)
	if err != nil || string(got) != string(planted) {
		t.Fatalf("overwrote %q %v", got, err)
	}
}

func TestWorkspacePermissionPlaceholder(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "gh")
	ws := filepath.Join(root, "a.b dir")
	if err := os.MkdirAll(home, 0o700); err != nil || os.MkdirAll(ws, 0o700) != nil {
		t.Fatal(err)
	}
	if err := SealGrokHome(root, home); err != nil {
		t.Fatal(err)
	}
	if err := ensureWorkspacePermission(root, home, ws); err != nil {
		t.Fatal(err)
	}
	key := url.PathEscape(ws)
	if strings.Contains(key, "/") || !strings.Contains(key, "%2F") {
		t.Fatal(key)
	}
	path := filepath.Join(home, "sessions", key, "permission.toml")
	st, err := os.Stat(path)
	if err != nil || st.Size() != 0 || st.Mode().Perm()&0o222 != 0 {
		t.Fatalf("placeholder %v %v", st, err)
	}
	binds, err := sessionPermissionBinds(home)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(binds, "\n")
	if !strings.Contains(joined, "--ro-bind\n"+path+"\n"+path) {
		t.Fatalf("binds %s", joined)
	}
	if _, err := os.Stat(filepath.Join(home, "sessions", "missing", "permission.toml")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(grokSealMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SealGrokHome(root, home); err != nil {
		t.Fatal(err)
	}
	planted := []byte(" \n")
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, planted, 0o600); err != nil {
		t.Fatal(err)
	}
	err = SealGrokHome(root, home)
	var ue *UntrustedConfigError
	if !errors.As(err, &ue) || len(ue.Names) != 1 || !strings.HasSuffix(ue.Names[0], "permission.toml") {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(planted) {
		t.Fatalf("overwrote %q %v", got, err)
	}
}

func TestHomeConfigSeals(t *testing.T) {
	home := t.TempDir()
	if err := prepareHomeSeals(home); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{
		".gitconfig",
		filepath.Join(".cursor", "mcp.json"),
		filepath.Join(".claude", grokSealDirEntry),
		filepath.Join(".agents", "skills", grokSealDirEntry),
	} {
		got, err := os.ReadFile(filepath.Join(home, rel))
		if err != nil || len(got) != 0 {
			t.Fatalf("%s %q %v", rel, got, err)
		}
	}
	other := filepath.Join(home, ".cursor", "hooks.json")
	if err := os.WriteFile(other, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareHomeSeals(home); err != nil {
		t.Fatal(err)
	}
	binds, err := homeSealBinds(home)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(binds, "\n")
	for _, rel := range []string{".gitconfig", filepath.Join(".cursor", "mcp.json"), ".claude", filepath.Join(".agents", "skills")} {
		p := filepath.Join(home, rel)
		if !strings.Contains(joined, "--ro-bind\n"+p+"\n"+p) {
			t.Fatalf("missing %s\n%s", rel, joined)
		}
	}
	planted := []byte("[user]\n")
	path := filepath.Join(home, ".gitconfig")
	if err := os.WriteFile(path, planted, 0o600); err != nil {
		t.Fatal(err)
	}
	err = prepareHomeSeals(home)
	var ue *UntrustedConfigError
	if !errors.As(err, &ue) || len(ue.Names) != 1 || ue.Names[0] != ".gitconfig" {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(planted) {
		t.Fatalf("overwrote %q %v", got, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, path); err != nil {
		t.Fatal(err)
	}
	err = prepareHomeSeals(home)
	ue = nil
	if !errors.As(err, &ue) {
		t.Fatal(err)
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replaced %v", err)
	}
}
