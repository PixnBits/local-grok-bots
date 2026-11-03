package sandbox

import (
	"bytes"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBinaryCacheRejectsSwappedFile(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc unavailable")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bins := []struct {
		ensure func(string) ([]byte, error)
		dest   func(string) string
	}{
		{ensureNetBridgeIn, func(dir string) string { return netBridgeBin().dest(dir) }},
		{ensureBridgeIn, func(dir string) string { return ghBridgeBin().dest(dir) }},
		{ensurePreloadIn, func(dir string) string { return preloadBin().dest(dir) }},
	}
	planted := []byte("planted-binary-contents-not-a-real-executable")
	for _, bin := range bins {
		first, err := bin.ensure(dir)
		if err != nil {
			t.Fatal(err)
		}
		path := bin.dest(dir)
		if err := os.WriteFile(path, planted, 0o700); err != nil {
			t.Fatal(err)
		}
		again, err := bin.ensure(dir)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(again, planted) || bytes.Contains(again, []byte("planted-binary")) {
			t.Fatal("planted bytes were returned")
		}
		if !bytes.Equal(again, first) {
			t.Fatalf("returned bytes changed for %s", path)
		}
		side, err := os.ReadFile(path + ".sha256")
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(first)
		if string(side) != hexEncode(sum[:])+"\n" && string(side) != hexEncode(sum[:]) {
			t.Fatalf("sidecar %q", side)
		}
	}
}

func TestBinaryCacheRejectsBadMode(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc unavailable")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := ensureNetBridgeIn(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := netBridgeBin().dest(dir)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	again, err := ensureNetBridgeIn(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, first) || bytes.Equal(again, nil) {
		t.Fatal("group-writable file changed the returned bytes")
	}
}

func TestBinaryCacheRejectsSymlink(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc unavailable")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := ensureNetBridgeIn(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := netBridgeBin().dest(dir)
	planted := filepath.Join(dir, "planted")
	if err := os.WriteFile(planted, []byte("planted-via-symlink"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(planted, path); err != nil {
		t.Fatal(err)
	}
	again, err := ensureNetBridgeIn(dir)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(again, []byte("planted-via-symlink")) || !bytes.Equal(again, first) {
		t.Fatal("symlink target was used")
	}
	target, err := os.ReadFile(planted)
	if err != nil || string(target) != "planted-via-symlink" {
		t.Fatalf("symlink target changed: %q %v", target, err)
	}
}

func TestBinaryCacheDirMode(t *testing.T) {
	parent := t.TempDir()
	created := filepath.Join(parent, "cache")
	if err := prepareCacheDir(created); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(created)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("created mode %v", fi.Mode())
	}
	loose := t.TempDir()
	if err := os.Chmod(loose, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := prepareCacheDir(loose); err != nil {
		t.Fatal(err)
	}
	fi, err = os.Lstat(loose)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("group-writable dir mode %v", fi.Mode())
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(created, link); err != nil {
		t.Fatal(err)
	}
	if err := prepareCacheDir(link); err == nil {
		t.Fatal("accepted a symlink cache dir")
	}
	if os.Geteuid() == 0 {
		return
	}
	foreign := "/usr"
	before, err := os.Lstat(foreign)
	if err != nil {
		t.Fatal(err)
	}
	mode := before.Mode()
	if err := prepareCacheDir(foreign); err == nil {
		t.Fatal("accepted a foreign cache dir")
	}
	after, err := os.Lstat(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode() != mode {
		t.Fatalf("foreign dir mode changed %v -> %v", mode, after.Mode())
	}
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = digits[c>>4]
		out[i*2+1] = digits[c&0x0f]
	}
	return string(out)
}
