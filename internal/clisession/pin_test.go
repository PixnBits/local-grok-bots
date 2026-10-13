package clisession

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestPinMatchesAndMismatchDoesNotRun(t *testing.T) {
	dir := t.TempDir()
	ran := filepath.Join(dir, "ran")
	envOut := filepath.Join(dir, "version-env")
	script := filepath.Join(dir, "fake-grok.sh")
	body := "#!/bin/sh\n" +
		"if [ \"$1\" = \"--version\" ]; then\n" +
		"  env > \"" + envOut + "\"\n" +
		"  echo fake 1.2.3\n" +
		"  exit 0\n" +
		"fi\n" +
		"touch \"" + ran + "\"\n" +
		"printf '%s\\n' '{\"type\":\"text\",\"data\":\"Hi\"}' '{\"type\":\"end\",\"stopReason\":\"end_turn\",\"sessionId\":\"abc123\"}'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	hash := hex.EncodeToString(sum[:])
	t.Setenv("XAI_API_KEY", "supersecret")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")

	var logs []string
	okPol := policy.Default()
	okPol.CLIPins = []policy.CLIPin{{
		Backend: "grok", Path: script, SHA256: hash, Version: "1.2.3",
	}}
	if err := okPol.Validate("http://127.0.0.1:11434", true); err != nil {
		t.Fatal(err)
	}
	res, err := ExecRunner{Policy: okPol, PinLog: func(backend, path, result string) {
		logs = append(logs, backend+" "+path+" "+result)
	}}.Run(context.Background(), Spec{
		Backend: "grok", Bin: script, Fresh: true, SessionID: "abc123",
		Prompt: "ping", Workspace: dir,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Text != "Hi" || len(logs) != 1 || !strings.Contains(logs[0], " ok") {
		t.Fatalf("res %+v logs %v", res, logs)
	}
	envText, err := os.ReadFile(envOut)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(envText), "supersecret") || strings.Contains(string(envText), "SSH_AUTH_SOCK") {
		t.Fatalf("version check saw secrets: %s", envText)
	}
	if _, err := os.Stat(ran); err != nil {
		t.Fatal("pinned binary did not run the turn")
	}

	_ = os.Remove(ran)
	bad := okPol
	bad.CLIPins = []policy.CLIPin{{Backend: "grok", SHA256: strings.Repeat("ab", 32)}}
	logs = nil
	_, err = ExecRunner{Policy: bad, PinLog: func(backend, path, result string) {
		logs = append(logs, result)
	}}.Run(context.Background(), Spec{
		Backend: "grok", Bin: script, Fresh: true, SessionID: "abc123",
		Prompt: "ping", Workspace: dir,
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatal(err)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "hash mismatch") {
		t.Fatalf("logs %v", logs)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("mismatched binary was executed")
	}

	logs = nil
	wrongPath := policy.Default()
	wrongPath.CLIPins = []policy.CLIPin{{Backend: "grok", Path: filepath.Join(dir, "other")}}
	if err := os.WriteFile(wrongPath.CLIPins[0].Path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = ExecRunner{Policy: wrongPath, PinLog: func(backend, path, result string) {
		logs = append(logs, result)
	}}.Run(context.Background(), Spec{
		Backend: "grok", Bin: script, Fresh: true, SessionID: "abc123",
		Prompt: "ping", Workspace: dir,
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "path mismatch") {
		t.Fatal(err)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("path mismatch still executed the binary")
	}

	logs = nil
	wrongVer := policy.Default()
	wrongVer.CLIPins = []policy.CLIPin{{Backend: "grok", Version: "9.9.9"}}
	_, err = ExecRunner{Policy: wrongVer, PinLog: func(backend, path, result string) {
		logs = append(logs, result)
	}}.Run(context.Background(), Spec{
		Backend: "grok", Bin: script, Fresh: true, SessionID: "abc123",
		Prompt: "ping", Workspace: dir,
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "version mismatch") {
		t.Fatal(err)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("version mismatch still executed the turn")
	}
}

func TestUnpinnedBinaryDoesNotLog(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-grok.sh")
	body := "#!/bin/sh\nprintf '%s\\n' '{\"type\":\"text\",\"data\":\"Hi\"}' '{\"type\":\"end\",\"stopReason\":\"end_turn\",\"sessionId\":\"abc123\"}'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	logged := false
	_, err := ExecRunner{PinLog: func(string, string, string) { logged = true }}.Run(context.Background(), Spec{
		Backend: "grok", Bin: script, Fresh: true, SessionID: "abc123",
		Prompt: "ping", Workspace: dir,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if logged {
		t.Fatal("unpinned launch was logged as a pin check")
	}
}
