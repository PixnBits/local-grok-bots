package coi

import (
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
