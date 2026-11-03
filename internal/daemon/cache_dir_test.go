package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

func TestSandboxCacheDirFollowsDataDir(t *testing.T) {
	dir := t.TempDir()
	_ = newApp(t, dir, fakeModel{})
	got := sandbox.CacheDir()
	want := filepath.Join(dir, "cache", "sandbox")
	if got != want {
		t.Fatalf("cache dir %s", got)
	}
	fi, err := os.Lstat(got)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v %v", fi, err)
	}
}
