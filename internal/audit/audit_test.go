package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileSinkRedacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(map[string]any{"event": "cli_start", "session_id": "s", "note": "ANTHROPIC_API_KEY=abcd"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"event":"cli_start"`) || strings.Contains(string(b), "abcd") {
		t.Fatalf("audit %s", b)
	}
}
