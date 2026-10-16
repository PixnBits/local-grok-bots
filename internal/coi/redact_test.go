package coi

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactOutputHidesCredentialHome(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "auth.json"), []byte(`{"token":"hunter2-hunter2"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secrets, err := ReadSecrets(root)
	if err != nil {
		t.Fatal(err)
	}
	token := "lgbr_" + strings.Repeat("cd", 32)
	out := RedactOutput("home "+root+" token hunter2-hunter2 "+token, []string{root}, secrets)
	if strings.Contains(out, root) || strings.Contains(out, "hunter2-hunter2") || strings.Contains(out, token) {
		t.Fatalf("leaked: %s", out)
	}
	if !strings.Contains(out, "[credential-home]") || !strings.Contains(out, "[redacted]") {
		t.Fatalf("output %s", out)
	}
}

// A real grok home is larger than a few hundred files after one launch.
// The secret in the last file has to be collected, or the next call is denied
// or the value leaks.
func TestReadSecretsScansPastAFreshCLIHome(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 300; i++ {
		dir := filepath.Join(root, "bundled", fmt.Sprintf("d%d", i%20))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d.txt", i)), []byte("plain\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "auth.json"), []byte("{\"token\":\"hunter2-hunter2\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bundled", "late.env"), []byte("password=late-secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secrets, err := ReadSecrets(root)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(secrets, "\n")
	if !strings.Contains(got, "hunter2-hunter2") || !strings.Contains(got, "late-secret-value") {
		t.Fatalf("missing secrets from a home larger than 256 files (%d collected)", len(secrets))
	}
}
