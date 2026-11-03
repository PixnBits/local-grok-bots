package sandbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func stubBin(name string) cachedBin {
	return cachedBin{
		name: name,
		src:  "stub-src-" + name,
		build: func() ([]byte, error) {
			return []byte("built-" + name), nil
		},
	}
}

func TestBinaryCacheFreshProcessIgnoresPlantedFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	b := stubBin("restart")
	dest := b.dest(dir)
	planted := []byte("planted-not-built!!")
	if err := os.WriteFile(dest, planted, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(planted)
	if err := os.WriteFile(dest+".sha256", []byte(hex.EncodeToString(sum[:])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resetBinaryCache()
	got, err := ensureCachedIn(dir, b)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, planted) || !bytes.Equal(got, []byte("built-restart")) {
		t.Fatalf("returned %q", got)
	}
}

func TestBinaryCacheSwappedFileKeepsMemoryBytes(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	b := stubBin("swapped")
	resetBinaryCache()
	first, err := ensureCachedIn(dir, b)
	if err != nil {
		t.Fatal(err)
	}
	dest := b.dest(dir)
	swapped := []byte("swapped-after-verify")
	if err := os.WriteFile(dest, swapped, 0o700); err != nil {
		t.Fatal(err)
	}
	again, err := ensureCachedIn(dir, b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, first) || bytes.Equal(again, swapped) {
		t.Fatalf("returned %q", again)
	}
}

func TestBinaryCacheReplacesSymlinkDest(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("via-link"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := stubBin("linkdest")
	dest := b.dest(dir)
	if err := os.Symlink(outside, dest); err != nil {
		t.Fatal(err)
	}
	resetBinaryCache()
	got, err := ensureCachedIn(dir, b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("built-linkdest")) {
		t.Fatalf("returned %q", got)
	}
	fi, err := os.Lstat(dest)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		t.Fatalf("dest %v %v", fi, err)
	}
	target, err := os.ReadFile(outside)
	if err != nil || string(target) != "via-link" {
		t.Fatalf("outside %q %v", target, err)
	}
}

func TestBinaryCacheRefusesSymlinkDir(t *testing.T) {
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(real, "canary")
	if err := os.WriteFile(canary, []byte("stay"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := prepareCacheDir(link); err == nil {
		t.Fatal("accepted a symlink cache dir")
	}
	body, err := os.ReadFile(canary)
	if err != nil || string(body) != "stay" {
		t.Fatalf("canary %q %v", body, err)
	}
}

func TestBinaryCacheReplacesFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	b := stubBin("fifo")
	dest := b.dest(dir)
	if err := syscall.Mkfifo(dest, 0o600); err != nil {
		t.Fatal(err)
	}
	resetBinaryCache()
	done := make(chan error, 1)
	go func() {
		_, err := ensureCachedIn(dir, b)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked on a non-regular cache file")
	}
	fi, err := os.Lstat(dest)
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("dest %v %v", fi, err)
	}
	body, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(body, []byte("built-fifo")) {
		t.Fatalf("file %q %v", body, err)
	}
}

func TestBinaryCacheTempSymlinkNotFollowed(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := stubBin("nofollow")
	tmp := b.dest(dir) + ".fixedtmp"
	if err := os.Symlink(outside, tmp); err != nil {
		t.Fatal(err)
	}
	prev := cacheTempPath
	cacheTempPath = func(string) string { return tmp }
	t.Cleanup(func() { cacheTempPath = prev })
	resetBinaryCache()
	_, err := ensureCachedIn(dir, b)
	if !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("err %v", err)
	}
	body, rerr := os.ReadFile(outside)
	if rerr != nil || string(body) != "outside-bytes" {
		t.Fatalf("outside %q %v", body, rerr)
	}
}

func TestBinaryCacheWrongFileOwner(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	b := stubBin("fileowner")
	dest := b.dest(dir)
	if err := os.WriteFile(dest, []byte("planted-owner"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := cacheFileUID
	cacheFileUID = func(fi os.FileInfo) (uint32, bool) {
		if fi.IsDir() {
			return prev(fi)
		}
		return uint32(os.Geteuid() + 1), true
	}
	t.Cleanup(func() { cacheFileUID = prev })
	resetBinaryCache()
	if _, err := ensureCachedIn(dir, b); err == nil {
		t.Fatal("accepted a file owned by someone else")
	}
	body, err := os.ReadFile(dest)
	if err != nil || string(body) != "planted-owner" {
		t.Fatalf("file %q %v", body, err)
	}
}

func TestBinaryCacheWrongDirOwner(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	prev := cacheFileUID
	cacheFileUID = func(fi os.FileInfo) (uint32, bool) {
		if fi.IsDir() {
			return uint32(os.Geteuid() + 1), true
		}
		return prev(fi)
	}
	t.Cleanup(func() { cacheFileUID = prev })
	if err := prepareCacheDir(dir); err == nil {
		t.Fatal("accepted a directory owned by someone else")
	}
	fi, err := os.Lstat(dir)
	if err != nil || fi.Mode().Perm() != 0o770 {
		t.Fatalf("mode %v %v", fi.Mode(), err)
	}
}

func TestBinaryCacheCreatesMissingDir(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "newcache")
	b := stubBin("missing")
	resetBinaryCache()
	got, err := ensureCachedIn(dir, b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("built-missing")) {
		t.Fatalf("returned %q", got)
	}
	fi, err := os.Lstat(dir)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir %v %v", fi, err)
	}
	side, err := os.ReadFile(b.dest(dir) + ".sha256")
	if err != nil || len(side) == 0 {
		t.Fatalf("sidecar %q %v", side, err)
	}
	file, err := os.Lstat(b.dest(dir))
	if err != nil || !file.Mode().IsRegular() || file.Mode().Perm()&0o022 != 0 {
		t.Fatalf("file %v %v", file, err)
	}
}
