//go:build linux

package permbroker

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestCeilingSameFileBind is the SameFile kill. A bind mount shares the
// inode and leaves Nlink at 1, so dropping the SameFile check allows the
// write. A hardlink cannot make that split: its Nlink is above 1.
func TestCeilingSameFileBind(t *testing.T) {
	if os.Getenv("LGB_BIND_CHILD") == "1" {
		sameFileBindChild(t)
		return
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare is not installed")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unshare", "-rm", exe,
		"-test.run", "^TestCeilingSameFileBind$",
		"-test.count=1", "-test.v", "-test.timeout", "60s")
	cmd.Env = append(os.Environ(), "LGB_BIND_CHILD=1")
	out, err := cmd.CombinedOutput()
	if bytes.Contains(out, []byte("--- SKIP:")) {
		t.Skipf("bind child skipped:\n%s", out)
	}
	if err != nil || !bytes.Contains(out, []byte("--- PASS:")) {
		t.Fatalf("bind child: %v\n%s", err, out)
	}
}

func sameFileBindChild(t *testing.T) {
	ws := t.TempDir()
	cfg := filepath.Join(ws, ".git", "config")
	mustWrite(t, cfg, "[core]\n\trepositoryformatversion = 0\n")
	decoy := filepath.Join(ws, "notes.txt")
	mustWrite(t, decoy, "notes\n")
	if err := unix.Mount(cfg, decoy, "", unix.MS_BIND, ""); err != nil {
		t.Skip("bind mount: " + err.Error())
	}
	t.Cleanup(func() { _ = unix.Unmount(decoy, unix.MNT_DETACH) })
	st, err := os.Lstat(decoy)
	if err != nil {
		t.Fatal(err)
	}
	n, ok := nlinkOf(st)
	if !ok || n != 1 {
		t.Fatalf("nlink %d ok %v", n, ok)
	}
	cfgSt, err := os.Lstat(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(st, cfgSt) {
		t.Fatal("bind mount did not share the inode")
	}
	wantAsk(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", decoy))
	wantAsk(t, evalWrite(testEngine(t), LevelCritical, ws, ws, "Edit", decoy))
	plain := filepath.Join(ws, "plain.txt")
	mustWrite(t, plain, "plain\n")
	wantCeilingAllow(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", plain))
}
