//go:build darwin

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSeatbeltJail runs the real sandbox-exec. It needs a Mac.
func TestSeatbeltJail(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "notes.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("TOPSECRET\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := Run(ctx, Request{Workspace: ws, Grants: []string{"net"}, Command: "cat notes.txt; echo ok > made.txt; " +
		"(cat " + outside + " || echo no-secret); (echo x > " + outside + ".w || echo no-write); " +
		"(mkdir -p .git/hooks && echo x > .git/hooks/pre-commit || echo no-hook); " +
		"(cat /etc/passwd >/dev/null 2>&1 || echo no-passwd); " +
		"(/usr/bin/nc -z -G 2 1.1.1.1 443 || echo no-net)"})
	t.Logf("err=%v\nstdout:\n%s\nstderr:\n%s\nevents=%+v", err, res.Stdout, res.Stderr, res.Events)
	for _, want := range []string{"hello", "no-secret", "no-write", "no-hook", "no-passwd", "no-net"} {
		if !strings.Contains(res.Stdout, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if _, err := os.Stat(filepath.Join(ws, "made.txt")); err != nil {
		t.Fatal("workspace write failed")
	}
	if _, ok := findEventDarwin(res.Events, "grant_denied", "net"); !ok {
		t.Fatal("net grant was not denied")
	}
}

func findEventDarwin(events []Event, kind, grant string) (Event, bool) {
	for _, e := range events {
		if e.Kind == kind && e.Grant == grant {
			return e, true
		}
	}
	return Event{}, false
}
