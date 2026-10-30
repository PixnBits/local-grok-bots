//go:build linux

package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestUnshareFallbackHidesProc runs a command in the unshare jail and
// checks that the fallback plan did not mount the host process tree.
func TestUnshareFallbackHidesProc(t *testing.T) {
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare is not installed")
	}
	probe := exec.Command("unshare", "--user", "--map-root-user", "--mount", "true")
	if err := probe.Run(); err != nil {
		t.Skip("unprivileged user namespaces are unavailable")
	}
	preferUnshare = true
	t.Cleanup(func() { preferUnshare = false })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := Run(ctx, Request{
		Workspace: t.TempDir(),
		Command:   "if test -e /proc; then echo HASPROC; else echo NOPROC; fi",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(res.Stdout) != "NOPROC" {
		t.Fatalf("stdout %q stderr %q", res.Stdout, res.Stderr)
	}
}
