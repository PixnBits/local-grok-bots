package clisession

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlaceBinaryRewritesLoginDir(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	ws := filepath.Join(root, "ws")
	binDir := filepath.Join(home, ".grok", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(binDir, "grok")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	argv0, mounts, err := placeBinary(bin, ws, home)
	if err != nil {
		t.Fatal(err)
	}
	if argv0 != "/lgb-home/.grok/bin/grok" {
		t.Fatalf("argv0 %s", argv0)
	}
	if len(mounts) != 0 {
		t.Fatalf("mounts %+v", mounts)
	}
}

func TestPlaceBinaryBindsForeignDir(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	opt := filepath.Join(root, "opt")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(opt, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(opt, "grok")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	argv0, mounts, err := placeBinary(bin, ws, filepath.Join(root, "home"))
	if err != nil {
		t.Fatal(err)
	}
	if argv0 != bin {
		t.Fatalf("argv0 %s", argv0)
	}
	if len(mounts) != 1 || mounts[0].src != opt || !mounts[0].ro {
		t.Fatalf("mounts %+v", mounts)
	}
}

func TestConfinedCommandEnvIsMinimal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XAI_API_KEY", "supersecret")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	cmd, cleanup, err := confinedCommand("/bin/true", []string{"-p", "x"}, dir)
	if cleanup != nil {
		t.Cleanup(cleanup)
	}
	if err != nil {
		t.Fatal(err)
	}
	blob := strings.Join(cmd.Env, "\n")
	if strings.Contains(blob, "supersecret") || strings.Contains(blob, "SSH_AUTH_SOCK") || strings.Contains(blob, "XAI_API_KEY") {
		t.Fatal(cmd.Env)
	}
	if len(cmd.Env) == 0 || !strings.HasPrefix(cmd.Env[0], "PATH=") {
		t.Fatalf("env %v", cmd.Env)
	}
}
