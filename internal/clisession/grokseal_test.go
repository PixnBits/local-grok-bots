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
	req, err := os.ReadFile(filepath.Join(home, "requirements.toml"))
	if err != nil || string(req) != grokRequirementsTOML() || !strings.Contains(string(req), "[ui]") || !strings.Contains(string(req), "remember_tool_approvals = false") {
		t.Fatalf("requirements %q %v", req, err)
	}
	for _, name := range []string{"trusted_folders.toml", "managed_config.toml", "hooks-paths"} {
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

func TestHostConfigIncludesManagedConfig(t *testing.T) {
	var saw bool
	for _, p := range HostConfigPaths {
		if p == "/etc/grok/managed_config.toml" {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("paths %v", HostConfigPaths)
	}
}

func TestSealSessionPermissionFile(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "gh")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, "sessions", "proj")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ok := filepath.Join(dir, "permission.toml")
	client := filepath.Join(dir, "permission_client.toml")
	note := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(ok, []byte(grokSealMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(client, []byte(grokSealMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(note, []byte("n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SealGrokHome(root, home); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, "sessions", "missing", "permission.toml")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	binds, err := sessionPermissionBinds(home)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(binds, "\n")
	if !strings.Contains(joined, "--ro-bind\n"+ok+"\n"+ok) || !strings.Contains(joined, "--ro-bind\n"+client+"\n"+client) {
		t.Fatalf("binds %s", joined)
	}
	if strings.Contains(joined, note) {
		t.Fatalf("note bound %s", joined)
	}
}

func TestSealRefusesForeignSessionPermission(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "gh")
	dir := filepath.Join(home, "sessions", "proj")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "permission.toml")
	planted := []byte("planted\n")
	if err := os.WriteFile(path, planted, 0o600); err != nil {
		t.Fatal(err)
	}
	err := SealGrokHome(root, home)
	var ue *UntrustedConfigError
	if !errors.As(err, &ue) || len(ue.Names) != 1 || ue.Names[0] != filepath.Join("sessions", "proj", "permission.toml") {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), "planted") {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(planted) {
		t.Fatalf("overwrote %q %v", got, err)
	}
	link := filepath.Join(dir, "permission_link.toml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	err = SealGrokHome(root, home)
	ue = nil
	if !errors.As(err, &ue) {
		t.Fatal(err)
	}
	st, err := os.Lstat(link)
	if err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replaced: %v", err)
	}
}

func TestRequirementsMarkerUpgrades(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "gh")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "requirements.toml")
	if err := os.WriteFile(path, []byte(grokSealMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SealGrokHome(root, home); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != grokRequirementsTOML() {
		t.Fatalf("upgraded %q %v", got, err)
	}
	if err := SealGrokHome(root, home); err != nil {
		t.Fatalf("second seal: %v", err)
	}
}

func TestSealRefusesExtraLink(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "gh")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "requirements.toml")
	if err := os.WriteFile(path, []byte(grokRequirementsTOML()), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(home, "requirements-link.toml")
	if err := os.Link(path, other); err != nil {
		t.Skip(err)
	}
	err := SealGrokHome(root, home)
	var ue *UntrustedConfigError
	if !errors.As(err, &ue) || len(ue.Names) != 1 || ue.Names[0] != "requirements.toml" {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != grokRequirementsTOML() {
		t.Fatalf("changed %q %v", got, err)
	}
}

func TestShellStartupFileRefusedWhenForeign(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".bashrc")
	planted := []byte("planted\n")
	if err := os.WriteFile(path, planted, 0o600); err != nil {
		t.Fatal(err)
	}
	err := prepareShellRC(home)
	var ue *UntrustedConfigError
	if !errors.As(err, &ue) || len(ue.Names) != 1 || ue.Names[0] != ".bashrc" {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), "planted") {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(planted) {
		t.Fatalf("overwrote %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(home, ".profile")); !os.IsNotExist(err) {
		t.Fatalf("later startup file created: %v", err)
	}
}

func TestShellStartupPlaceholder(t *testing.T) {
	home := t.TempDir()
	if err := prepareShellRC(home); err != nil {
		t.Fatal(err)
	}
	for _, name := range shellRCNames {
		b, err := os.ReadFile(filepath.Join(home, name))
		if err != nil || string(b) != grokSealMarker {
			t.Fatalf("%s %q %v", name, b, err)
		}
	}
	if err := prepareShellRC(home); err != nil {
		t.Fatalf("second prepare: %v", err)
	}
	binds, err := shellRCBinds(home)
	if err != nil {
		t.Fatal(err)
	}
	rc := filepath.Join(home, ".bashrc")
	if !strings.Contains(strings.Join(binds, "\n"), "--ro-bind\n"+rc+"\n"+rc) {
		t.Fatalf("binds %v", binds)
	}
}
