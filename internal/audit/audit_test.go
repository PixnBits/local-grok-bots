package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileSinkRedactsAndRejectsRelative(t *testing.T) {
	if _, err := Open("audit.log"); err == nil {
		t.Fatal("relative audit path was accepted")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(map[string]any{
		"event":  "net_decision",
		"action": "allow",
		"host":   "allowed.test",
		"port":   443,
		"grant":  "net",
		"detail": "via http://user:s3cret@proxy.example:8080 XAI_API_KEY=supersecret",
	})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, bad := range []string{"s3cret", "supersecret"} {
		if strings.Contains(text, bad) {
			t.Fatalf("audit line leaked %s: %s", bad, text)
		}
	}
	for _, want := range []string{`"event":"net_decision"`, `"action":"allow"`, `"host":"allowed.test"`, `"port":443`, `"grant":"net"`, "redacted"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s in %s", want, text)
		}
	}
}

func TestDisabledLoggerDropsEvents(t *testing.T) {
	l, err := Open("")
	if err != nil || l.Enabled() {
		t.Fatal(err)
	}
	l.Write(map[string]any{"event": "cli_start", "detail": "XAI_API_KEY=supersecret"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}
