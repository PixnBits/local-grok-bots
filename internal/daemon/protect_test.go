package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

func TestRefreshProtectSnapshot(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	sec := filepath.Join(app.cfg.DataDir, "secrets")
	before := inodeAt(t, app.protectInodes(), sec)
	if !before.IsDir {
		t.Fatalf("snapshot missing %s in %+v", sec, app.protectInodes())
	}
	if err := os.Rename(sec, sec+"-away"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sec, 0o700); err != nil {
		t.Fatal(err)
	}
	app.RefreshProtectSnapshot()
	after := inodeAt(t, app.protectInodes(), sec)
	if !after.IsDir || (after.Dev == before.Dev && after.Ino == before.Ino) {
		t.Fatalf("snapshot did not follow the new directory: before %+v after %+v", before, after)
	}
}

func inodeAt(t *testing.T, snap []sandbox.ProtectInode, path string) sandbox.ProtectInode {
	t.Helper()
	path = filepath.Clean(path)
	for _, ent := range snap {
		if ent.Path == path {
			return ent
		}
	}
	t.Fatalf("path %s not in snapshot", path)
	return sandbox.ProtectInode{}
}
