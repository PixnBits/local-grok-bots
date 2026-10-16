package coi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestForwardGrokUsesPlaceholderKey(t *testing.T) {
	const hostKey = "xai-supersecretvalue123456"
	t.Setenv("XAI_API_KEY", hostKey)
	root := t.TempDir()
	out := filepath.Join(root, "key")
	script := filepath.Join(root, "show")
	body := "#!/bin/sh\nprintf '%s\\n' \"$XAI_API_KEY\" > " + out + "\nprintf '%s\\n' \"$GROK_CLI_CHAT_PROXY_BASE_URL\" >> " + out + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	code := RunForward([]string{
		"--sock", filepath.Join(root, "missing"),
		"--env", "GROK_CLI_CHAT_PROXY_BASE_URL",
		"--prefix", "/v1",
		"--", script,
	})
	if code != 0 {
		t.Fatalf("forward %d", code)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) != 2 || lines[0] != PlaceholderToken {
		t.Fatal("placeholder key was not set")
	}
	if strings.Contains(text, hostKey) {
		t.Fatal("child saw the host api key")
	}
	if !strings.HasPrefix(lines[1], "http://127.0.0.1:") || !strings.HasSuffix(lines[1], "/v1") {
		t.Fatal("base url was not set")
	}
}

func TestMain(m *testing.M) {
	if HandleForward(os.Args[1:]) {
		return
	}
	os.Exit(m.Run())
}
