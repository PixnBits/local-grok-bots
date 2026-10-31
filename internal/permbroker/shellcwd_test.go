package permbroker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShellCwdAfterStaysInside(t *testing.T) {
	ws := t.TempDir()
	s1 := filepath.Join(ws, "s1")
	s2 := filepath.Join(ws, "s2")
	if err := os.Mkdir(s1, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s2, 0o755); err != nil {
		t.Fatal(err)
	}
	next, reject, update := ShellCwdAfter(ws, ws, "cd s1")
	if reject || !update || next != s1 {
		t.Fatalf("cd s1 next %s reject %v update %v", next, reject, update)
	}
	again, reject, update := ShellCwdAfter(ws, s1, "echo hi")
	if reject || update || again != s1 {
		t.Fatalf("echo stays %s reject %v update %v", again, reject, update)
	}
	other, reject, update := ShellCwdAfter(ws, s1, "cd ../s2")
	if reject || !update || other != s2 {
		t.Fatalf("cd s2 next %s reject %v update %v", other, reject, update)
	}
	home, reject, update := ShellCwdAfter(ws, s2, "cd")
	if reject || !update || home != ws {
		t.Fatalf("cd home %s reject %v update %v", home, reject, update)
	}
	if _, reject, update = ShellCwdAfter(ws, ws, "cd .."); !reject || update {
		t.Fatal("cd .. was allowed")
	}
	if _, reject, update = ShellCwdAfter(ws, ws, "cd /tmp"); !reject || update {
		t.Fatal("absolute cd was allowed")
	}
	if _, reject, _ = ShellCwdAfter(ws, s1, "cd -"); !reject {
		t.Fatal("cd - was allowed")
	}
	missing, reject, update := ShellCwdAfter(ws, ws, "cd missing")
	if reject || update || missing != ws {
		t.Fatalf("missing dest %s reject %v update %v", missing, reject, update)
	}
	compound, reject, update := ShellCwdAfter(ws, ws, "cd s1 && echo hi")
	if reject || update || compound != ws {
		t.Fatalf("compound %s reject %v update %v", compound, reject, update)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(ws, "out")); err != nil {
		t.Fatal(err)
	}
	if _, reject, update = ShellCwdAfter(ws, ws, "cd out"); !reject || update {
		t.Fatal("symlink escape was allowed")
	}
	inside := filepath.Join(ws, "inside")
	if err := os.Mkdir(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(inside, filepath.Join(ws, "link")); err != nil {
		t.Fatal(err)
	}
	linked, reject, update := ShellCwdAfter(ws, ws, "cd link")
	if reject || !update || linked != inside {
		t.Fatalf("inside symlink %s reject %v update %v", linked, reject, update)
	}
}

func TestDriftReasonHookOnly(t *testing.T) {
	stored := []byte("v1\nhooks abc\nrepo-config x\n")
	hook := []byte("v1\nhooks def\nrepo-config x\n")
	if got := driftReason(stored, hook); got != gitReasonHook {
		t.Fatalf("hook drift %q", got)
	}
	both := []byte("v1\nhooks def\nrepo-config y\n")
	if got := driftReason(stored, both); got != gitReasonConfig {
		t.Fatalf("mixed drift %q", got)
	}
}
