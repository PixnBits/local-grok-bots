package coi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpoolMountUsesIdentity(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	real := filepath.Join(ws, "real-spool")
	decoy := filepath.Join(ws, ".lgb")
	if err := os.MkdirAll(real, 0o700); err != nil || os.MkdirAll(decoy, 0o700) != nil {
		t.Fatal(err)
	}
	dev, ino, err := DirIdentity(real)
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := spoolMounts(ws, real, dev, ino)
	if err != nil || len(mounts) != 1 || mounts[0] != real {
		t.Fatalf("mounts %v %v", mounts, err)
	}
	if err := os.RemoveAll(real); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := spoolMounts(ws, real, dev, ino); err == nil {
		t.Fatal("replaced directory was accepted")
	}
	alias := filepath.Join(ws, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	dev, ino, err = DirIdentity(alias)
	if err != nil {
		t.Fatal(err)
	}
	mounts, err = spoolMounts(ws, alias, dev, ino)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range mounts {
		if m == real {
			found = true
		}
		if strings.HasSuffix(m, ".lgb") {
			t.Fatalf("masked the decoy name: %v", mounts)
		}
	}
	if !found {
		t.Fatalf("resolved spool missing: %v", mounts)
	}
}
