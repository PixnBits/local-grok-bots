package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestEditAndDeleteFile(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	bot, err := app.st.CreateBot("IO", "stay", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if _, err := app.dispatchTool(ctx, bot, "write_file", map[string]any{"path": "notes/a.txt", "content": "one one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.dispatchTool(ctx, bot, "edit_file", map[string]any{"path": "notes/a.txt", "old_string": "missing", "new_string": "x"}); err == nil {
		t.Fatal("zero matches accepted")
	}
	if _, err := app.dispatchTool(ctx, bot, "edit_file", map[string]any{"path": "notes/a.txt", "old_string": "one", "new_string": "two"}); err == nil {
		t.Fatal("non-unique match accepted")
	}
	out, err := app.dispatchTool(ctx, bot, "edit_file", map[string]any{
		"path": "notes/a.txt", "old_string": "one", "new_string": "two", "expected_count": float64(2),
	})
	if err != nil || !strings.Contains(out, `"replacements":2`) {
		t.Fatalf("edit %v %s", err, out)
	}
	got, err := os.ReadFile(filepath.Join(app.botWorkspace(bot.ID), "notes", "a.txt"))
	if err != nil || string(got) != "two two" {
		t.Fatalf("file %q %v", got, err)
	}
	if _, err := app.dispatchTool(ctx, bot, "edit_file", map[string]any{
		"path": "notes/a.txt", "old_string": "two", "new_string": "x", "expected_count": float64(0),
	}); err == nil {
		t.Fatal("expected_count 0 accepted")
	}
	if _, err := app.dispatchTool(ctx, bot, "delete_file", map[string]any{"path": "notes"}); err == nil {
		t.Fatal("directory delete accepted")
	}
	if _, err := app.dispatchTool(ctx, bot, "delete_file", map[string]any{"path": "notes/a.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(app.botWorkspace(bot.ID), "notes", "a.txt")); !os.IsNotExist(err) {
		t.Fatalf("file still present: %v", err)
	}
}

func TestGolden_NativeFileToolsPerBotRoot(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	ctx := t.Context()
	botA := store.Bot{ID: "botA", Name: "A"}
	botB := store.Bot{ID: "botB", Name: "B"}
	if _, err := app.dispatchTool(ctx, botB, "write_file", map[string]any{"path": "secret.txt", "content": "from-b"}); err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(app.botWorkspace(botB.ID), "secret.txt")
	out, err := app.dispatchTool(ctx, botA, "read_file", map[string]any{"path": "secret.txt"})
	if strings.Contains(out, "from-b") {
		t.Fatalf("read relative leaked: %v %s", err, out)
	}
	for _, path := range []string{abs, filepath.Join("..", "botB", "secret.txt")} {
		out, err = app.dispatchTool(ctx, botA, "read_file", map[string]any{"path": path})
		if err == nil || strings.Contains(out, "from-b") {
			t.Fatalf("read %s leaked: %v %s", path, err, out)
		}
		out, err = app.dispatchTool(ctx, botA, "write_file", map[string]any{"path": path, "content": "pwn"})
		if err == nil || strings.Contains(out, "from-b") {
			t.Fatalf("write %s: %v %s", path, err, out)
		}
	}
	if _, err := app.dispatchTool(ctx, botA, "write_file", map[string]any{"path": "mine.txt", "content": "mine"}); err != nil {
		t.Fatal(err)
	}
	got, err := app.dispatchTool(ctx, botA, "read_file", map[string]any{"path": "mine.txt"})
	if err != nil || got != "mine" {
		t.Fatalf("own file %q %v", got, err)
	}
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(app.botWorkspace(botA.ID), "leaf")); err != nil {
		t.Fatal(err)
	}
	out, err = app.dispatchTool(ctx, botA, "read_file", map[string]any{"path": "leaf"})
	if err == nil || strings.Contains(out, "secret-bytes") {
		t.Fatalf("symlink read %v %s", err, out)
	}
	if _, err := app.dispatchTool(ctx, botA, "write_file", map[string]any{"path": "leaf", "content": "pwn"}); err == nil {
		t.Fatal("symlink write")
	}
	b, err := os.ReadFile(secret)
	if err != nil || string(b) != "secret-bytes" {
		t.Fatalf("outside changed %q %v", b, err)
	}
	kept, err := os.ReadFile(abs)
	if err != nil || string(kept) != "from-b" {
		t.Fatalf("bot B changed %q %v", kept, err)
	}
}

func TestFileToolsRefuseSymlinks(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	bot := store.Bot{ID: "bot", Name: "IO"}
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := app.shellWorkspace(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "leaf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "jump")); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	for _, call := range []struct {
		name string
		args map[string]any
	}{
		{"read_file", map[string]any{"path": "leaf"}},
		{"read_file", map[string]any{"path": "jump/secret.txt"}},
		{"write_file", map[string]any{"path": "leaf", "content": "pwn"}},
		{"write_file", map[string]any{"path": "jump/pwn.txt", "content": "pwn"}},
		{"delete_file", map[string]any{"path": "leaf"}},
		{"delete_file", map[string]any{"path": "jump/secret.txt"}},
		{"edit_file", map[string]any{"path": "leaf", "old_string": "secret", "new_string": "pwn"}},
	} {
		out, err := app.dispatchTool(ctx, bot, call.name, call.args)
		if err == nil || strings.Contains(out, "secret-bytes") || strings.Contains(err.Error(), "secret-bytes") {
			t.Fatalf("%s %#v leaked or succeeded: %v %s", call.name, call.args["path"], err, out)
		}
		if strings.Contains(err.Error(), "cli credential") {
			t.Fatalf("internal wording: %v", err)
		}
	}
	b, err := os.ReadFile(secret)
	if err != nil || string(b) != "secret-bytes" {
		t.Fatalf("outside file changed: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "pwn.txt")); !os.IsNotExist(err) {
		t.Fatal("write escaped through the symlink")
	}
}
