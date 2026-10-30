package permbroker

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookCommandPOSIXQuote(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".lgb-quote-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "hook $x `id` o'q"
	path := filepath.Join(dir, name)
	body := "#!/bin/sh\nprintf '%s\\n' \"$0\"\nprintf '%s\\n' \"$1\"\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "sock $y `z` 'q'")
	cmd := HookCommand(path, sock)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(lines) != 2 || lines[0] != path || lines[1] != sock {
		t.Fatalf("argv %q\ncommand %s", lines, cmd)
	}
}

func TestCheckHookBinaryParents(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".lgb-hookbin-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "hook")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckHookBinary(path, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := CheckHookBinary(path, nil); err == nil || !strings.Contains(err.Error(), "group or world writable") {
		t.Fatalf("parent %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	tmp, err := os.CreateTemp("", "lgb-hook-tmp-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	t.Cleanup(func() { _ = os.Remove(tmpPath) })
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckHookBinary(tmpPath, nil); err == nil || !strings.Contains(err.Error(), "group or world writable") {
		t.Fatalf("tmp parent %v", err)
	}
}
