package coi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestRunFakeCLIRedactsAndScrubs(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	cred := filepath.Join(root, "cred")
	binDir := filepath.Join(root, "bin")
	for _, d := range []string{ws, cred, binDir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cred, "auth.json"), []byte(`{"token":"hunter2-hunter2"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(binDir, "fake")
	body := "#!/bin/sh\nenv > \"$PWD/child.env\"\necho \"HOME=$HOME\"\ncat \"$HOME/auth.json\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	token := "lgbr_" + strings.Repeat("ab", 32)
	res := Run(context.Background(), Call{
		Tool: policy.CLITool{
			Name: "fake", Path: script, CredentialHome: cred,
			AllowedArgs: []string{"--version"}, CredentialFiles: []string{"auth.json"},
			Timeout: time.Second, MaxOutput: 4096,
		},
		Args:      []string{"--version"},
		Workspace: ws,
		BaseEnv: []string{
			"PATH=" + os.Getenv("PATH"),
			"LANG=C",
			"HOME=/home/someone",
			"LGB_TOKEN=" + token,
			"XAI_API_KEY=xai-supersecretvalue123456",
		},
	})
	if res.Status != StatusOK || res.Code != 0 {
		t.Fatalf("result %+v", res)
	}
	if strings.Contains(res.Output, cred) || strings.Contains(res.Output, "hunter2-hunter2") || strings.Contains(res.Output, token) {
		t.Fatalf("output leaked: %s", res.Output)
	}
	if !strings.Contains(res.Output, "[redacted]") {
		t.Fatalf("output %s", res.Output)
	}
	env, err := os.ReadFile(filepath.Join(ws, "child.env"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(env)
	if strings.Contains(text, token) || strings.Contains(text, "xai-supersecret") || strings.Contains(text, "HOME=/home/someone") || strings.Contains(text, cred) {
		t.Fatalf("child env leaked:\n%s", text)
	}
	if !strings.Contains(text, "HOME=") || strings.Contains(text, "HOME="+cred) {
		t.Fatalf("child home:\n%s", text)
	}
	if strings.Contains(text, "PATH="+ws) || strings.Contains(text, ws+"/bin") {
		t.Fatalf("workspace on PATH:\n%s", text)
	}
}

func TestRunFailClosed(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	cred := filepath.Join(root, "cred")
	if err := os.MkdirAll(ws, 0o755); err != nil || os.MkdirAll(cred, 0o755) != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "fake")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho ran > \"$PWD/ran\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	base := policy.CLITool{
		Name: "fake", Path: script, CredentialHome: cred,
		AllowedArgs: []string{"--version"}, Timeout: time.Second, MaxOutput: 1024,
	}
	inside := base
	inside.CredentialHome = filepath.Join(ws, "secret")
	if err := os.Mkdir(inside.CredentialHome, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := base
	missing.Path = filepath.Join(root, "missing")
	plain := base
	plain.Path = filepath.Join(root, "plain")
	if err := os.WriteFile(plain.Path, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fileHome := base
	fileHome.CredentialHome = script
	limits := base
	limits.Timeout = 0
	cases := []policy.CLITool{inside, missing, plain, fileHome, limits}
	for _, tool := range cases {
		res := Run(context.Background(), Call{Tool: tool, Args: []string{"--version"}, Workspace: ws})
		if res.Status != StatusDenied {
			t.Fatalf("%+v status %s", tool, res.Status)
		}
	}
	if _, err := os.Stat(filepath.Join(ws, "ran")); !os.IsNotExist(err) {
		t.Fatal("denied call ran the cli")
	}
}

func TestRunPromptTimeoutAndOutputLimit(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	cred := filepath.Join(root, "cred")
	if err := os.MkdirAll(ws, 0o755); err != nil || os.MkdirAll(cred, 0o755) != nil {
		t.Fatal(err)
	}
	prompted := 0
	prompt := writeExe(t, root, "ask", "#!/bin/sh\necho 'do you want to allow this command?'\nsleep 30\n")
	start := time.Now()
	res := Run(context.Background(), Call{
		Tool: policy.CLITool{
			Name: "ask", Path: prompt, CredentialHome: cred,
			AllowedArgs: []string{"--version"}, Timeout: 5 * time.Second, MaxOutput: 4096,
		},
		Args: []string{"--version"}, Workspace: ws,
		OnPrompt: func(context.Context) { prompted++ },
	})
	if res.Status != StatusDenied || res.Err != "permission prompt denied" || prompted != 1 {
		t.Fatalf("prompt %+v calls %d", res, prompted)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("permission prompt hung")
	}
	slow := writeExe(t, root, "slow", "#!/bin/sh\nsleep 30\n")
	start = time.Now()
	res = Run(context.Background(), Call{
		Tool: policy.CLITool{
			Name: "slow", Path: slow, CredentialHome: cred,
			AllowedArgs: []string{"--version"}, Timeout: 200 * time.Millisecond, MaxOutput: 1024,
		},
		Args: []string{"--version"}, Workspace: ws,
	})
	if res.Status != StatusError || res.Err != "timed out" || time.Since(start) > 3*time.Second {
		t.Fatalf("timeout %+v after %s", res, time.Since(start))
	}
	chatty := writeExe(t, root, "chatty", "#!/bin/sh\nwhile true; do printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; done\n")
	start = time.Now()
	res = Run(context.Background(), Call{
		Tool: policy.CLITool{
			Name: "chatty", Path: chatty, CredentialHome: cred,
			AllowedArgs: []string{"--version"}, Timeout: 5 * time.Second, MaxOutput: 64,
		},
		Args: []string{"--version"}, Workspace: ws,
	})
	if res.Status != StatusOK || !strings.Contains(res.Output, "[output truncated]") || len(res.Output) > 200 {
		t.Fatalf("limit %+v", res)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("output limit hung")
	}
}

func writeExe(t *testing.T, root, name, body string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunSandboxHidesCredentialHome(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	cred := filepath.Join(root, "cred")
	if err := os.MkdirAll(ws, 0o755); err != nil || os.MkdirAll(cred, 0o755) != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cred, "auth.json"), []byte("hunter2-hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := writeExe(t, root, "probe", "#!/bin/sh\nif [ -e \""+cred+"/auth.json\" ]; then echo LEAK; fi\ncat \"$HOME/auth.json\"\n")
	res := Run(context.Background(), Call{
		Tool: policy.CLITool{
			Name: "probe", Path: script, CredentialHome: cred,
			AllowedArgs: []string{"--version"}, CredentialFiles: []string{"auth.json"},
			Timeout: time.Second, MaxOutput: 4096,
		},
		Args: []string{"--version"}, Workspace: ws,
	})
	if res.Status != StatusOK || res.Code != 0 {
		t.Fatalf("result %+v", res)
	}
	if strings.Contains(res.Output, "LEAK") || strings.Contains(res.Output, "hunter2-hunter2") || strings.Contains(res.Output, cred) {
		t.Fatalf("sandbox leaked credential home: %s", res.Output)
	}
	if !strings.Contains(res.Output, "[redacted]") {
		t.Fatalf("copy was not readable: %s", res.Output)
	}
}

func TestRunSandboxUnavailable(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	cred := filepath.Join(root, "cred")
	if err := os.MkdirAll(ws, 0o755); err != nil || os.MkdirAll(cred, 0o755) != nil {
		t.Fatal(err)
	}
	script := writeExe(t, root, "fake", "#!/bin/sh\necho ran > \"$PWD/ran\"\n")
	res := Run(context.Background(), Call{
		Tool: policy.CLITool{
			Name: "fake", Path: script, CredentialHome: cred,
			AllowedArgs: []string{"--version"}, SandboxBin: filepath.Join(root, "no-bwrap"),
			Timeout: time.Second, MaxOutput: 1024,
		},
		Args: []string{"--version"}, Workspace: ws,
	})
	if res.Status != StatusDenied || res.Err != ErrSandboxUnavailable.Error() {
		t.Fatalf("result %+v", res)
	}
	if _, err := os.Stat(filepath.Join(ws, "ran")); !os.IsNotExist(err) {
		t.Fatal("cli ran without a sandbox")
	}
}

func TestSeatbeltProfileHidesHome(t *testing.T) {
	prof, err := coiSeatbeltProfile("/work", "/tmp/coi-home-1", "/usr/bin/grok")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prof, `(subpath "/work")`) || !strings.Contains(prof, `(subpath "/tmp/coi-home-1")`) {
		t.Fatalf("writable roots missing:\n%s", prof)
	}
	if !strings.Contains(prof, `(literal "/usr/bin/grok")`) {
		t.Fatalf("binary not readable:\n%s", prof)
	}
	if strings.Contains(prof, "/.grok") || strings.Contains(prof, "/Users") {
		t.Fatalf("opened a host home:\n%s", prof)
	}
	if !strings.Contains(prof, "(allow network-outbound)") {
		t.Fatal("API network missing")
	}
}
