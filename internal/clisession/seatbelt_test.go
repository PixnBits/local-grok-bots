package clisession

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLISeatbeltWritesLoginDirsOnly(t *testing.T) {
	ws := t.TempDir()
	home := t.TempDir()
	tmp := t.TempDir()
	sb := cliSeatbelt(ws, home, tmp, filepath.Join(home, "bin"))
	for _, p := range sb.Write {
		if p == home || p == filepath.Join(home, ".ssh") {
			t.Fatalf("write path %s", p)
		}
	}
	text, err := sb.Render()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "(deny default)") || !strings.Contains(text, "(allow network-outbound)\n") {
		t.Fatal(text)
	}
	if !strings.Contains(text, filepath.Join(home, ".grok")) || !strings.Contains(text, filepath.Join(home, ".claude")) {
		t.Fatal(text)
	}
	if strings.Contains(text, "(subpath \""+home+"\")") {
		t.Fatalf("whole home is writable:\n%s", text)
	}
	if strings.Contains(text, ".ssh") {
		t.Fatal(text)
	}
	env := cliChildEnv(home, tmp)
	blob := strings.Join(env, "\n")
	if !strings.Contains(blob, "HOME="+home) || strings.Contains(blob, "SSH_AUTH_SOCK") {
		t.Fatal(blob)
	}
	_ = os.Unsetenv("SSH_AUTH_SOCK")
}
