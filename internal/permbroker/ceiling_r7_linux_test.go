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

func TestCeilingCrossDevice(t *testing.T) {
	if os.Getenv("LGB_BIND_CHILD") == "1" {
		crossDeviceChild(t)
		return
	}
	runUnshareTest(t, "^TestCeilingCrossDevice$", "LGB_BIND_CHILD")
}

func TestCeilingBindHook(t *testing.T) {
	if os.Getenv("LGB_HOOK_BIND_CHILD") == "1" {
		bindHookChild(t)
		return
	}
	runUnshareTest(t, "^TestCeilingBindHook$", "LGB_HOOK_BIND_CHILD")
}

func runUnshareTest(t *testing.T, run, envKey string) {
	t.Helper()
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare is not installed")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unshare", "-rm", exe,
		"-test.run", run, "-test.count=1", "-test.v", "-test.timeout", "60s")
	cmd.Env = append(os.Environ(), envKey+"=1")
	out, err := cmd.CombinedOutput()
	if bytes.Contains(out, []byte("--- SKIP:")) {
		t.Skipf("child skipped:\n%s", out)
	}
	if err != nil || !bytes.Contains(out, []byte("--- PASS:")) {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

func crossDeviceChild(t *testing.T) {
	ws := t.TempDir()
	sub := filepath.Join(ws, "other")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", sub, "tmpfs", 0, ""); err != nil {
		t.Skip("tmpfs: " + err.Error())
	}
	t.Cleanup(func() { _ = unix.Unmount(sub, unix.MNT_DETACH) })
	target := filepath.Join(sub, "f.txt")
	mustWrite(t, target, "x\n")
	rootDev, ok := pathDevice(ws)
	got, ok2 := pathDevice(target)
	if !ok || !ok2 || rootDev == got {
		t.Fatalf("devices root %d/%v target %d/%v", rootDev, ok, got, ok2)
	}
	wantAsk(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", target))
	wantAsk(t, evalWrite(testEngine(t), LevelCritical, ws, ws, "Edit", target))
	plain := filepath.Join(ws, "plain.txt")
	mustWrite(t, plain, "plain\n")
	wantCeilingAllow(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", plain))
}

func bindHookChild(t *testing.T) {
	ws := t.TempDir()
	hook := filepath.Join(ws, ".git", "hooks", "pre-commit")
	mustWrite(t, hook, "#!/bin/sh\n")
	decoy := filepath.Join(ws, "notes.txt")
	mustWrite(t, decoy, "notes\n")
	if err := unix.Mount(hook, decoy, "", unix.MS_BIND, ""); err != nil {
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
	hookSt, err := os.Lstat(hook)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(st, hookSt) {
		t.Fatal("bind mount did not share the inode")
	}
	wantAsk(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", decoy))
	wantAsk(t, evalWrite(testEngine(t), LevelCritical, ws, ws, "Edit", decoy))
}
