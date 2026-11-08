//go:build linux

package permbroker

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseMountinfoIDs(t *testing.T) {
	raw := []byte("10 1 8:1 / / rw - ext4 /dev/sda1 rw\n20 10 8:1 /sub /work/bound rw - ext4 /dev/sda1 rw\n")
	ents, ok := parseMountinfo(raw)
	if !ok {
		t.Fatal("parse")
	}
	id, ok := mountIDFor(ents, "/work/bound/f")
	if !ok || id != 20 {
		t.Fatalf("bound %d %v", id, ok)
	}
	id, ok = mountIDFor(ents, "/work/plain")
	if !ok || id != 10 {
		t.Fatalf("root %d %v", id, ok)
	}
	spaced := []byte("11 1 8:1 / /work/my\\040dir rw - ext4 /dev/sda1 rw\n")
	ents, ok = parseMountinfo(spaced)
	if !ok {
		t.Fatal("spaced parse")
	}
	id, ok = mountIDFor(ents, "/work/my dir/f")
	if !ok || id != 11 {
		t.Fatalf("space %d %v", id, ok)
	}
	if _, ok := parseMountinfo([]byte("not a mount line\n")); ok {
		t.Fatal("malformed accepted")
	}
}

func TestMountinfoUnreadableAsks(t *testing.T) {
	old := mountinfoPath
	mountinfoPath = filepath.Join(t.TempDir(), "no-such-mountinfo")
	t.Cleanup(func() { mountinfoPath = old })
	ws := t.TempDir()
	plain := filepath.Join(ws, "plain.txt")
	mustWrite(t, plain, "p\n")
	for _, ceiling := range []Level{LevelMedium, LevelCritical} {
		wantAsk(t, evalWrite(testEngine(t), ceiling, ws, ws, "Write", plain))
	}
}

func TestCeilingSameFSBind(t *testing.T) {
	if os.Getenv("LGB_SAME_BIND_CHILD") == "1" {
		sameFSBindChild(t)
		return
	}
	runUnshareTest(t, "^TestCeilingSameFSBind$", "LGB_SAME_BIND_CHILD")
}

func sameFSBindChild(t *testing.T) {
	ws := t.TempDir()
	sub := filepath.Join(ws, "sub")
	bound := filepath.Join(ws, "bound")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bound, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(sub, bound, "", unix.MS_BIND, ""); err != nil {
		t.Skip("bind: " + err.Error())
	}
	t.Cleanup(func() { _ = unix.Unmount(bound, unix.MNT_DETACH) })
	target := filepath.Join(bound, "f.txt")
	mustWrite(t, target, "x\n")
	plain := filepath.Join(ws, "plain.txt")
	mustWrite(t, plain, "p\n")
	rootDev, okR := pathDevice(ws)
	dev, okD := pathDevice(target)
	if !okR || !okD || rootDev != dev {
		t.Fatalf("devices root %d/%v target %d/%v", rootDev, okR, dev, okD)
	}
	differ, ok := mountMismatch(target, ws)
	if !ok || !differ {
		t.Fatalf("mount differ %v ok %v", differ, ok)
	}
	wantAsk(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", target))
	wantAsk(t, evalWrite(testEngine(t), LevelCritical, ws, ws, "Edit", target))
	wantCeilingAllow(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", plain))
}
