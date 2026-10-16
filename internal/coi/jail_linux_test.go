//go:build linux

package coi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxBwrapArgsBindBinaryNotHome(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	home := filepath.Join(root, "home")
	bin := filepath.Join(root, "bin", "tool")
	cred := filepath.Join(root, "cred")
	for _, d := range []string{ws, home, filepath.Dir(bin), cred} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	args, err := linuxBwrapArgs(jailSpec{
		Bin: bin, Args: []string{"--version"}, Workspace: ws, Home: home,
		Env: []string{"HOME=" + home, "PATH=/usr/bin:/bin", "GROK_HOME=" + filepath.Join(home, ".grok")},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\n")
	if !strings.Contains(joined, bin) || !strings.Contains(joined, ws) {
		t.Fatalf("missing binds:\n%s", joined)
	}
	if strings.Contains(joined, cred) {
		t.Fatalf("credential home bound:\n%s", joined)
	}
	if strings.Contains(joined, "--disable-userns") {
		t.Fatal("user namespaces disabled")
	}
	if strings.Contains(joined, "--unshare-net") {
		t.Fatal("network unshared")
	}
	wantHome := false
	for i, a := range args {
		if a == "--setenv" && i+1 < len(args) && args[i+1] == "HOME" {
			if i+2 >= len(args) || args[i+2] != jailHomeInside {
				t.Fatalf("HOME %v", args[i+2])
			}
			wantHome = true
		}
	}
	if !wantHome {
		t.Fatal("HOME not remapped")
	}
}
