package dlp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestScanOffAllowsContent(t *testing.T) {
	if err := Scan(context.Background(), policy.Default(), "SSN 123-45-6789"); err != nil {
		t.Fatal(err)
	}
}

func TestPatternAndBlocklistAllowAndDeny(t *testing.T) {
	pol := policy.Default()
	pol.DLPPatterns = []string{`(?i)\bssn\b`}
	if err := Scan(context.Background(), pol, "hello"); err != nil {
		t.Fatal(err)
	}
	if err := Scan(context.Background(), pol, "ssn 123"); err == nil || !strings.Contains(err.Error(), "blocked by pattern") {
		t.Fatal(err)
	}
	if strings.Contains(errText(Scan(context.Background(), pol, "ssn 123")), "123") {
		t.Fatal("pattern error included the content")
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "block.txt")
	body := "# comment\nproject-secret\nre:(?i)\\btoken-[0-9]+\\b\n"
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	filePol := policy.Default()
	filePol.DLPFile = file
	if err := Scan(context.Background(), filePol, "nothing to see"); err != nil {
		t.Fatal(err)
	}
	if err := Scan(context.Background(), filePol, "see Project-Secret now"); err == nil {
		t.Fatal("literal was allowed")
	}
	if err := Scan(context.Background(), filePol, "token-99"); err == nil {
		t.Fatal("regex line was allowed")
	}
	if strings.Contains(errText(Scan(context.Background(), filePol, "token-99")), "token-99") {
		t.Fatal("blocklist error included the content")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := Scan(context.Background(), filePol, "token-99"); err == nil || !strings.Contains(err.Error(), "rules unreadable") || strings.Contains(err.Error(), "token-99") {
		t.Fatal(err)
	}
}

func TestScanTooLargeFailsClosed(t *testing.T) {
	pol := policy.Default()
	pol.DLPPatterns = []string{"nomatch"}
	err := Scan(context.Background(), pol, strings.Repeat("a", (1<<20)+1))
	if err == nil || !strings.Contains(err.Error(), "too large") || strings.Contains(err.Error(), "aaa") {
		t.Fatal(err)
	}
}

func TestCommandAllowAndDeny(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "scan.sh")
	body := "#!/bin/sh\nif [ -n \"$XAI_API_KEY\" ] || [ -n \"$SSH_AUTH_SOCK\" ]; then exit 9; fi\ndata=$(cat)\ncase \"$data\" in *BLOCK*) exit 3;; esac\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XAI_API_KEY", "supersecret")
	pol := policy.Default()
	pol.DLPCommand = script
	if err := Scan(context.Background(), pol, "hello"); err != nil {
		t.Fatal(err)
	}
	err := Scan(context.Background(), pol, "please BLOCK this")
	if err == nil || !strings.Contains(err.Error(), "blocked by scanner") || strings.Contains(err.Error(), "BLOCK") {
		t.Fatal(err)
	}
	missing := pol
	missing.DLPCommand = filepath.Join(dir, "missing")
	if err := Scan(context.Background(), missing, "hello"); err == nil || !strings.Contains(err.Error(), "scanner failed") {
		t.Fatal(err)
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
