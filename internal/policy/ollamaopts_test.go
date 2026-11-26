package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOllamaOptionsPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	body := `
[ollama]
think = true
num_ctx = 8192

[ollama.model_options."qwen3.6:35b"]
think = false
num_ctx = 262144
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	botThink := true
	cliThink := false
	think, n := ResolveChatOptions(p, "qwen3.6:35b", &botThink, 1024, &cliThink, 2048)
	if think == nil || *think != false || n != 262144 {
		t.Fatalf("per-model think %v num %d", think, n)
	}
	think, n = ResolveChatOptions(p, "other", &botThink, 1024, &cliThink, 2048)
	if think == nil || *think != true || n != 8192 {
		t.Fatalf("default over bot think %v num %d", think, n)
	}
	empty := Policy{}
	think, n = ResolveChatOptions(empty, "other", &botThink, 1024, &cliThink, 2048)
	if think == nil || *think != true || n != 1024 {
		t.Fatalf("bot over cli think %v num %d", think, n)
	}
	think, n = ResolveChatOptions(empty, "other", nil, 0, &cliThink, 2048)
	if think == nil || *think != false || n != 2048 {
		t.Fatalf("cli think %v num %d", think, n)
	}
	think, n = ResolveChatOptions(empty, "other", nil, 0, nil, 0)
	if think != nil || n != 0 {
		t.Fatalf("unset think %v num %d", think, n)
	}
}

func TestOllamaNumCtxRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	for _, body := range []string{
		"[ollama]\nnum_ctx = 0\n",
		"[ollama]\nnum_ctx = -1\n",
		"[ollama]\nnum_ctx = 1048577\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(Options{Path: path}); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}
