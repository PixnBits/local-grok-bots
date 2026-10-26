package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSelectBuildBinds(t *testing.T) {
	ws := t.TempDir()
	normal := t.TempDir()
	if err := os.WriteFile(filepath.Join(normal, "tool.txt"), []byte("toolchain\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	secretDir := t.TempDir()
	const canary = "CANARY-SECRET-BYTES"
	secret := filepath.Join(secretDir, "tokens")
	if err := os.WriteFile(secret, []byte(canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	bind := filepath.Join(parent, "tools")
	if err := os.Mkdir(bind, 0o755); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Lstat(bind); err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("startup bind %v %v", st, err)
	}
	if err := os.Remove(bind); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secretDir, bind); err != nil {
		t.Fatal(err)
	}

	normalResolved, err := filepath.EvalSymlinks(normal)
	if err != nil {
		t.Fatal(err)
	}
	normalResolved = filepath.Clean(normalResolved)
	mounts, events, applied := selectBuildBinds(ws, []string{bind, normal}, []string{secret})
	for _, m := range mounts {
		if m.Src == bind || m.Dst == bind || m.Src == secretDir || m.Dst == secret || m.Src == secret {
			t.Fatalf("protected bind mounted: %+v", mounts)
		}
	}
	if len(applied) != 1 || applied[0] != normal {
		t.Fatalf("applied %v", applied)
	}
	found := false
	for _, ev := range events {
		if ev.Kind != "sandbox_block" {
			continue
		}
		found = true
		if !strings.Contains(ev.Detail, bind) || strings.Contains(ev.Detail, canary) || strings.Contains(ev.Detail, secret) {
			t.Fatalf("event %+v", ev)
		}
	}
	if !found {
		t.Fatalf("events %+v", events)
	}
	args := mountArgs(mounts)
	joined := strings.Join(args, "\n")
	if !strings.Contains(joined, "--ro-bind\n"+normalResolved+"\n"+normalResolved) {
		t.Fatalf("bwrap args:\n%s", joined)
	}
	if strings.Contains(joined, bind) || strings.Contains(joined, secretDir) || strings.Contains(joined, canary) {
		t.Fatalf("bwrap args include the refused bind:\n%s", joined)
	}

	t.Run("unresolved", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "gone")
		mounts, events, applied := selectBuildBinds(ws, []string{missing}, nil)
		if len(mounts) != 0 || len(applied) != 0 {
			t.Fatalf("mounted missing %+v %v", mounts, applied)
		}
		if len(events) != 1 || events[0].Kind != "sandbox_block" || !strings.Contains(events[0].Detail, missing) {
			t.Fatalf("events %+v", events)
		}
	})
}
