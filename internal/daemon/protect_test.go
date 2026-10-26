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
	data := filepath.Clean(app.cfg.DataDir)
	sec := filepath.Join(data, "secrets")
	if err := os.MkdirAll(sec, 0o700); err != nil {
		t.Fatal(err)
	}
	app.RefreshProtectSnapshot()
	beforeData := inodeAt(t, app.protectInodes(), data)
	beforeSec := inodeAt(t, app.protectInodes(), sec)
	if !beforeData.IsDir || !beforeSec.IsDir {
		t.Fatalf("snapshot %+v", app.protectInodes())
	}
	if err := os.Rename(sec, sec+"-away"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sec, 0o700); err != nil {
		t.Fatal(err)
	}
	app.RefreshProtectSnapshot()
	afterData := inodeAt(t, app.protectInodes(), data)
	afterSec := inodeAt(t, app.protectInodes(), sec)
	if afterData != beforeData || afterSec != beforeSec {
		t.Fatalf("baseline replaced data %+v -> %+v secrets %+v -> %+v", beforeData, afterData, beforeSec, afterSec)
	}
	if app.protectBlockReason() != "" {
		t.Fatal(app.protectBlockReason())
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
