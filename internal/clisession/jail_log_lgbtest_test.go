//go:build linux && lgbtest

package clisession

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGrokJailBindsHostLogs(t *testing.T) {
	ws := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "argv.log")
	bin := filepath.Join(ws, "grok")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	args, err := grokBwrapArgs(bin, []string{"-p", "hi"}, Spec{
		Workspace: ws,
		Isolate:   &Isolation{Env: []string{"LGB_ARGV_LOG=" + logPath, "LGB_FIXTURE=" + logPath}},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\n")
	if !strings.Contains(joined, "--bind\n"+logPath+"\n"+logPath) {
		t.Fatalf("missing log bind:\n%s", joined)
	}
}
