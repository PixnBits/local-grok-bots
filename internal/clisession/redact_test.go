package clisession

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStderrSecretsAreRedacted(t *testing.T) {
	ant := "sk-ant-api03-abc123xyz-456def789ghij_klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopAA"
	xai := "xai-" + strings.Repeat("ab12cd34", 5)
	lgbr := "lgbr_" + strings.Repeat("ab", 32)
	admin := strings.Repeat("cd", 32)
	dir := t.TempDir()
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '{"type":"result","result":"","session_id":"s"}'
printf '%%s\n' 'startup failed: %s %s %s %s' >&2
exit 1
`, ant, xai, lgbr, admin)
	bin := filepath.Join(dir, "claude")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := (ExecRunner{HasTTY: func() bool { return false }}).Run(context.Background(), Spec{
		Backend: "claude", Bin: bin, PermissionMode: "default",
		Fresh: true, Prompt: "hi", Workspace: dir,
	}, nil)
	if err == nil {
		t.Fatal("expected a CLI error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "startup failed") || !strings.Contains(msg, "[redacted]") {
		t.Fatalf("error %q", msg)
	}
	for _, secret := range []string{ant, xai, lgbr, admin} {
		if strings.Contains(msg, secret) {
			t.Fatalf("stderr leaked %s in %q", secret, msg)
		}
	}
}
