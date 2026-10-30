//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

func TestGolden_JailMountsBwrap(t *testing.T) {
	app := newApp(t, t.TempDir(), nil)
	botWS, err := app.shellWorkspace("ada")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(app.ws, "bots", "ada")
	if botWS != want {
		t.Fatalf("shell workspace %s", botWS)
	}
	other := filepath.Join(app.ws, "bots", "bob")
	if err := os.MkdirAll(other, 0o750); err != nil {
		t.Fatal(err)
	}
	hookDir := filepath.Join(t.TempDir(), "hooks")
	if err := os.MkdirAll(hookDir, 0o755); err != nil {
		t.Fatal(err)
	}
	data := app.cfg.DataDir
	secrets := []string{
		filepath.Join(data, "permbroker"),
		filepath.Join(data, "admin-token"),
		other,
		hookDir,
		data,
		app.ws,
	}
	args, err := sandbox.BwrapArgv(sandbox.Request{Workspace: botWS, Command: "true"})
	if err != nil {
		t.Fatal(err)
	}
	if !bindPair(args, botWS, "/work") {
		t.Fatalf("workspace bind missing\n%s", strings.Join(args, "\n"))
	}
	for _, secret := range secrets {
		if src := bindExposes(args, secret); src != "" {
			t.Fatalf("bind %s exposes %s\n%s", src, secret, strings.Join(args, "\n"))
		}
	}
}

func bindPair(args []string, src, dst string) bool {
	src = filepath.Clean(src)
	for i := 0; i+2 < len(args); i++ {
		if (args[i] == "--bind" || args[i] == "--ro-bind") && filepath.Clean(args[i+1]) == src && args[i+2] == dst {
			return true
		}
	}
	return false
}

func bindExposes(args []string, secret string) string {
	secret = filepath.Clean(secret)
	for i := 0; i+2 < len(args); i++ {
		if args[i] != "--bind" && args[i] != "--ro-bind" {
			continue
		}
		src := filepath.Clean(args[i+1])
		if src == "" {
			continue
		}
		if pathHolds(src, secret) {
			return src
		}
	}
	return ""
}

func pathHolds(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
