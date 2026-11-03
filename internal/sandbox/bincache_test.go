package sandbox

import (
	"bytes"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
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
	bins := []func(string) (string, error){ensureNetBridgeIn, ensureBridgeIn, ensurePreloadIn}
	planted := []byte("planted-binary-contents-not-a-real-executable")
	for _, ensure := range bins {
		path, err := ensure(dir)
		if err != nil {
			t.Fatal(err)
		}
		first, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		ino := fileIno(t, path)
		if err := os.WriteFile(path, planted, 0o700); err != nil {
			t.Fatal(err)
		}
		again, err := ensure(dir)
		if err != nil {
			t.Fatal(err)
		}
		if again != path {
			t.Fatalf("path %s %s", path, again)
		}
		body, err := os.ReadFile(again)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(body, planted) || bytes.Contains(body, []byte("planted-binary")) {
			t.Fatal("planted bytes were returned")
		}
		if !bytes.Equal(body, first) {
			t.Fatalf("rebuild hash changed for %s", path)
		}
		if fileIno(t, again) == ino {
			t.Fatalf("reused inode for %s", path)
		}
		side, err := os.ReadFile(again + ".sha256")
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		if string(side) != hexEncode(sum[:])+"\n" && string(side) != hexEncode(sum[:]) {
			t.Fatalf("sidecar %q", side)
		}
		fi, err := os.Lstat(again)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o022 != 0 {
			t.Fatalf("mode %v", fi.Mode())
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
	path, err := ensureNetBridgeIn(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ino := fileIno(t, path)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	again, err := ensureNetBridgeIn(dir)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(again)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, first) {
		t.Fatal("rebuilt bytes differ")
	}
	if fileIno(t, again) == ino {
		t.Fatal("group-writable file was reused")
	}
	fi, err := os.Lstat(again)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		t.Fatalf("mode %v", fi.Mode())
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
	path, err := ensureNetBridgeIn(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
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
	fi, err := os.Lstat(again)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		t.Fatalf("still a symlink: %v", fi.Mode())
	}
	body, err := os.ReadFile(again)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("planted-via-symlink")) || !bytes.Equal(body, first) {
		t.Fatal("symlink target was used")
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

func fileIno(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		t.Fatal("no stat")
	}
	return uint64(st.Ino)
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
