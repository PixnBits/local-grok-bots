package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeNodeBin(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "node")
	body := "#!/bin/sh\nprintf '%s\\n' node-ok\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSandboxNodePolicy(t *testing.T) {
	bin := writeNodeBin(t, t.TempDir())
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	body := "[backend]\nbackend = \"ollama\"\n[sandbox]\nnode = " + quoteTOML(bin) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if p.NodePath != bin {
		t.Fatalf("node = %q", p.NodePath)
	}

	linkDir := t.TempDir()
	link := filepath.Join(linkDir, "node-link")
	if err := os.Symlink(bin, link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[sandbox]\nnode = "+quoteTOML(link)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err = Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if p.NodePath != bin {
		t.Fatalf("resolved node = %q", p.NodePath)
	}
}

func TestSandboxNodePolicyFailClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	plain := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []string{
		"node = \"relative/node\"\n",
		"node = \"/no/such/node\"\n",
		"node = " + quoteTOML(dir) + "\n",
		"node = " + quoteTOML(plain) + "\n",
		"node = \"\"\n",
	}
	for _, snippet := range cases {
		if err := os.WriteFile(path, []byte("[sandbox]\n"+snippet), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := Load(Options{Path: path})
		if err == nil || !strings.Contains(err.Error(), "sandbox.node") {
			t.Fatalf("%s: %v", snippet, err)
		}
	}
}

func TestSandboxNodeManagedWins(t *testing.T) {
	localBin := writeNodeBin(t, t.TempDir())
	managedBin := writeNodeBin(t, t.TempDir())
	dir := t.TempDir()
	local := filepath.Join(dir, "policy.toml")
	managed := filepath.Join(dir, "managed.toml")
	if err := os.WriteFile(local, []byte("[sandbox]\nnode = "+quoteTOML(localBin)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managed, []byte("[sandbox]\nnode = "+quoteTOML(managedBin)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if p.NodePath != managedBin {
		t.Fatalf("node = %q want managed", p.NodePath)
	}
}

func quoteTOML(s string) string {
	return "\"" + strings.ReplaceAll(s, "\\", "\\\\") + "\""
}
