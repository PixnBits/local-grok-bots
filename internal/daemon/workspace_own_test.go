package daemon

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

type ownCall struct {
	path string
	uid  int
	gid  int
}

func TestWorkspaceOwnedForJail(t *testing.T) {
	var calls []ownCall
	oldC, oldE := sandbox.Chown, sandbox.EUID
	sandbox.Chown = func(path string, uid, gid int) error {
		calls = append(calls, ownCall{path, uid, gid})
		return nil
	}
	sandbox.EUID = func() int { return 0 }
	t.Cleanup(func() { sandbox.Chown, sandbox.EUID = oldC, oldE })

	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	uid, gid := sandbox.JailIDs()
	assertOwned(t, calls, app.ws, uid, gid, 0o750)

	if _, err := app.toolWriteFile("bot", map[string]any{"path": "sub/dir/note.txt", "content": "hi"}); err != nil {
		t.Fatal(err)
	}
	assertOwned(t, calls, filepath.Join(app.ws, "sub"), uid, gid, 0o700)
	assertOwned(t, calls, filepath.Join(app.ws, "sub", "dir"), uid, gid, 0o700)
	got, err := os.ReadFile(filepath.Join(app.ws, "sub", "dir", "note.txt"))
	if err != nil || string(got) != "hi" {
		t.Fatalf("file %q %v", got, err)
	}
	if err := filepath.WalkDir(app.ws, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		st, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("symlink dir %s", path)
		}
		if st.Mode().Perm()&0o002 != 0 {
			t.Fatalf("world-writable %s mode %o", path, st.Mode().Perm())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertOwned(t *testing.T, calls []ownCall, path string, uid, gid int, mode os.FileMode) {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !st.IsDir() || st.Mode().Perm() != mode || st.Mode().Perm()&0o002 != 0 {
		t.Fatalf("%s mode %o", path, st.Mode().Perm())
	}
	for _, c := range calls {
		if c.path == path && c.uid == uid && c.gid == gid {
			return
		}
	}
	t.Fatalf("no chown of %s to %d:%d in %v", path, uid, gid, calls)
}

func TestWorkspaceNonRootSkipsChown(t *testing.T) {
	var calls []ownCall
	oldC, oldE := sandbox.Chown, sandbox.EUID
	sandbox.Chown = func(path string, uid, gid int) error {
		calls = append(calls, ownCall{path, uid, gid})
		return nil
	}
	sandbox.EUID = func() int { return 1000 }
	t.Cleanup(func() { sandbox.Chown, sandbox.EUID = oldC, oldE })

	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	if _, err := app.toolWriteFile("bot", map[string]any{"path": "sub/dir/note.txt", "content": "hi"}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatalf("chown calls %v", calls)
	}
	assertDirMode(t, app.ws, 0o750)
	assertDirMode(t, filepath.Join(app.ws, "sub"), 0o700)
	assertDirMode(t, filepath.Join(app.ws, "sub", "dir"), 0o700)
	if err := filepath.WalkDir(app.ws, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		st, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("symlink dir %s", path)
		}
		if st.Mode().Perm()&0o002 != 0 {
			t.Fatalf("world-writable %s mode %o", path, st.Mode().Perm())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertDirMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !st.IsDir() || st.Mode().Perm() != mode || st.Mode().Perm()&0o002 != 0 {
		t.Fatalf("%s mode %o", path, st.Mode().Perm())
	}
}
