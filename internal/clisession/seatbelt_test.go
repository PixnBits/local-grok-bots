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
	sb := cliSeatbelt(ws, home, tmp, filepath.Join(home, "bin"), cliNet{Open: true})
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
	closed := cliSeatbelt(ws, home, tmp, "", cliNet{})
	closedText, err := closed.Render()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(closedText, "(allow network-outbound)\n") {
		t.Fatal(closedText)
	}
	proxied := cliSeatbelt(ws, home, tmp, "", cliNet{ProxySock: filepath.Join(tmp, "proxy.sock")})
	proxyText, err := proxied.Render()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(proxyText, "(allow network-outbound)\n") || !strings.Contains(proxyText, "proxy.sock") {
		t.Fatal(proxyText)
	}
	shared := filepath.Join(t.TempDir(), "shared-data")
	ro := cliSeatbelt(ws, home, tmp, "", cliNet{Open: true, ROBinds: []string{shared}})
	for _, p := range ro.Write {
		if p == shared {
			t.Fatalf("ro bind is writable: %s", p)
		}
	}
	found := false
	for _, p := range ro.Read {
		if p == shared {
			found = true
		}
	}
	if !found {
		t.Fatalf("read paths %v", ro.Read)
	}
	roText, err := ro.Render()
	if err != nil {
		t.Fatal(err)
	}
	readAt := strings.Index(roText, "(allow file-read*\n")
	if readAt < 0 {
		t.Fatal(roText)
	}
	writeAt := strings.Index(roText[readAt:], "(allow file-read* file-write*")
	pathAt := strings.Index(roText, shared)
	if writeAt < 0 || pathAt < readAt || pathAt > readAt+writeAt {
		t.Fatalf("path is not read-only:\n%s", roText)
	}
	bad := cliSeatbelt(ws, home, tmp, "", cliNet{ROBinds: []string{`/tmp/has"quote`}})
	if _, err := bad.Render(); err == nil {
		t.Fatal("seatbelt accepted a path it cannot quote")
	}

	env := cliChildEnv(home, tmp)
	blob := strings.Join(env, "\n")
	if !strings.Contains(blob, "HOME="+home) || strings.Contains(blob, "SSH_AUTH_SOCK") {
		t.Fatal(blob)
	}
	_ = os.Unsetenv("SSH_AUTH_SOCK")
}
