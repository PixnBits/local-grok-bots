//go:build linux

package daemon

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenat2ENOSYSUsesComponentWalk(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
	prev := openat2Fn
	openat2Fn = func(int, string, *unix.OpenHow) (int, error) {
		return -1, unix.ENOSYS
	}
	t.Cleanup(func() { openat2Fn = prev })

	ws := t.TempDir()
	proj := filepath.Join(ws, "sub", "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	writeRepo(t, proj, "readme.txt", "walk-bytes\n", "walk-subject")
	h := holdRepo(t, ws, "sub/proj")
	if !sameRepo(h, proj) {
		t.Fatal("walk resolved a different directory")
	}
	mirror, err := copyGitMirror(context.Background(), t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(mirror) })
	log := strings.TrimSpace(gitRepoOut(t, mirror, "--git-dir", mirror, "log", "--all", "--format=%s"))
	if log != "walk-subject" {
		t.Fatalf("log %q", log)
	}
	if err := os.Symlink("proj", filepath.Join(ws, "sub", "link")); err != nil {
		t.Fatal(err)
	}
	if reason := resolveReason(ws, "sub/link"); reason != "symlink" {
		t.Fatalf("symlink through the walk: %q", reason)
	}
}
