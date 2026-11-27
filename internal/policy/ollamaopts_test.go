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
	botNo := false
	think, n = ResolveChatOptions(p, "other", &botNo, 1024, &cliThink, 2048)
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

func TestOllamaManagedBeatsLocal(t *testing.T) {
	dir := t.TempDir()
	localPath := filepath.Join(dir, "policy.toml")
	managedPath := filepath.Join(dir, "managed.toml")
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	load := func() Policy {
		t.Helper()
		p, err := Load(Options{Path: localPath, ManagedPath: managedPath})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	no := false
	yes := true
	check := func(p Policy, model string, botThink *bool, botNum int, cliThink *bool, cliNum int, wantThink *bool, wantNum int) {
		t.Helper()
		think, n := ResolveChatOptions(p, model, botThink, botNum, cliThink, cliNum)
		if wantNum != n || (wantThink == nil) != (think == nil) || (wantThink != nil && *wantThink != *think) {
			t.Fatalf("model %s think %v num %d, want think %v num %d", model, think, n, wantThink, wantNum)
		}
	}

	// Distinct values at every layer. think alternates. num_ctx does not repeat.
	// managed per-model false/1101, managed default true/2202,
	// local per-model false/3303, local default true/4404, bot false/5505, CLI true/6606.
	const (
		managedPer = `
[ollama]
think = true
num_ctx = 2202

[ollama.model_options."m"]
think = false
num_ctx = 1101
`
		managedDefault = `
[ollama]
think = true
num_ctx = 2202
`
		managedThinkOnly = `
[ollama]
think = true
num_ctx = 2202

[ollama.model_options."m"]
think = false
`
		managedSilent = "# none\n"
		localPer      = `
[ollama]
think = true
num_ctx = 4404

[ollama.model_options."m"]
think = false
num_ctx = 3303
`
		localDefault = `
[ollama]
think = true
num_ctx = 4404
`
		localSilent = "# none\n"
	)

	write(managedPath, managedPer)
	write(localPath, localPer)
	p := load()
	check(p, "m", &no, 5505, &yes, 6606, &no, 1101)
	check(p, "other", &no, 5505, &yes, 6606, &yes, 2202)

	write(managedPath, managedDefault)
	p = load()
	check(p, "m", &no, 5505, &yes, 6606, &yes, 2202)

	write(managedPath, managedThinkOnly)
	p = load()
	check(p, "m", &no, 5505, &yes, 6606, &no, 2202)

	write(managedPath, `
[ollama]
think = true
`)
	p = load()
	check(p, "m", &no, 5505, &yes, 6606, &yes, 3303)

	write(managedPath, managedSilent)
	p = load()
	check(p, "m", &no, 5505, &yes, 6606, &no, 3303)

	write(localPath, localDefault)
	p = load()
	check(p, "m", &no, 5505, &yes, 6606, &yes, 4404)

	write(localPath, localSilent)
	p = load()
	check(p, "m", &no, 5505, &yes, 6606, &no, 5505)
	check(p, "m", nil, 0, &yes, 6606, &yes, 6606)
	check(p, "m", nil, 0, nil, 0, nil, 0)
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
