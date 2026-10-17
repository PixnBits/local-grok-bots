//go:build linux && !lgbtest

package clisession

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGrokJailOmitsHostLogBinds(t *testing.T) {
	if _, err := os.Stat("/usr/bin"); err != nil {
		t.Skip(err)
	}
	ws := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "argv.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(ws, "grok")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	args, err := grokBwrapArgs(bin, []string{"-p", "hi"}, Spec{
		Workspace: ws,
		Isolate: &Isolation{Env: []string{
			"HOME=" + t.TempDir(),
			"LGB_ARGV_LOG=" + logPath,
			"LGB_ENV_LOG=" + logPath,
			"LGB_FIXTURE=" + logPath,
			"LGB_AUTH_LOG=" + logPath,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(args, "\n"), "--bind\n"+logPath+"\n"+logPath) {
		t.Fatal("production jail bind-mounted a test log")
	}
}
