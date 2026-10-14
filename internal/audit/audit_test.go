package audit

import (
	"encoding/json"
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

func TestRedactValueHidesKeysAndTokens(t *testing.T) {
	got := RedactValue(map[string]any{
		"command": "echo sk-supersecretvalue12",
		"api_key": "sk-supersecretvalue12",
		"nested":  []any{"ghp_abcdefghijklmnop"},
	}).(map[string]any)
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "sk-supersecretvalue12") || strings.Contains(string(b), "ghp_abcdefghijklmnop") {
		t.Fatalf("secret leaked: %s", b)
	}
	if got["api_key"] != "[redacted]" {
		t.Fatalf("key %#v", got["api_key"])
	}
}
