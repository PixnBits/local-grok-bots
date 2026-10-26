package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
)

func TestShellProtectIncludesDataDir(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(real, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "link", "data")
	app := newApp(t, data, fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	got := app.shellProtect()
	raw := filepath.Clean(data)
	resolved, err := filepath.EvalSymlinks(data)
	if err != nil {
		t.Fatal(err)
	}
	resolved = filepath.Clean(resolved)
	if raw == resolved {
		t.Fatal("fixture path did not differ from its resolution")
	}
	if !containsPath(got, raw) || !containsPath(got, resolved) {
		t.Fatalf("protect %v want %s and %s", got, raw, resolved)
	}
	for _, p := range got {
		if p == "" || p == "." || p == "/" {
			t.Fatalf("empty protect entry %q in %v", p, got)
		}
	}
}

func TestGuardBuildBindsEmptyProtect(t *testing.T) {
	for _, protect := range [][]string{nil, {}, {""}, {" "}, {"."}, {"/"}} {
		binds, ev := guardBuildBinds(protect, []string{"/opt/tool", " ", "/opt/b"})
		if len(binds) != 0 || len(ev) != 2 {
			t.Fatalf("protect %#v binds %v events %+v", protect, binds, ev)
		}
		if ev[0].Kind != "sandbox_block" || ev[0].Untrusted || !strings.Contains(ev[0].Detail, "/opt/tool") {
			t.Fatalf("event %+v", ev[0])
		}
		if ev[1].Kind != "sandbox_block" || !strings.Contains(ev[1].Detail, "/opt/b") {
			t.Fatalf("event %+v", ev[1])
		}
	}
	kept, ev := guardBuildBinds([]string{"/data"}, []string{"/opt/tool"})
	if len(ev) != 0 || len(kept) != 1 || kept[0] != "/opt/tool" {
		t.Fatalf("kept %v events %+v", kept, ev)
	}
}

func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}
