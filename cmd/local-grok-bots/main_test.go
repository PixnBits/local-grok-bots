package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("LGB_HELP_CHECK") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestHelpExitsBeforeStartup(t *testing.T) {
	for _, flag := range []string{"-h", "--help", "-help"} {
		t.Run(flag, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], flag)
			cmd.Dir = dir
			cmd.Env = []string{
				"LGB_HELP_CHECK=1",
				"PATH=" + os.Getenv("PATH"),
				"HOME=" + dir,
				"TMPDIR=" + dir,
				"BIND_ADDR=127.0.0.1:0",
				"DATA_DIR=" + filepath.Join(dir, "data"),
			}
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()
			if err != nil {
				t.Fatalf("exit %v\nstderr: %s", err, stderr.String())
			}
			if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 0 {
				t.Fatalf("exit %v", cmd.ProcessState)
			}
			out := stdout.String()
			for _, needle := range []string{
				"local-grok-bots",
				"DATA_DIR", "./data",
				"BIND_ADDR", "127.0.0.1:8080",
				"A policy.toml bind overrides BIND_ADDR.",
				"POLICY_PATH", "policy.toml",
				"OLLAMA_URL", "http://127.0.0.1:11434",
				"OLLAMA_MODEL", "llama3.2",
				"AUTH_TOKEN", "unset",
				"AUTH_TOKENS_FILE",
				"name:token",
				"SIGHUP",
				"ignored",
				"SANDBOX_BUILD_BINDS",
			} {
				if !strings.Contains(out, needle) {
					t.Fatalf("stdout missing %q:\n%s", needle, out)
				}
			}
			if strings.Contains(stderr.String(), "listening") {
				t.Fatalf("stderr: %s", stderr.String())
			}
			ents, rerr := os.ReadDir(dir)
			if rerr != nil {
				t.Fatal(rerr)
			}
			if len(ents) != 0 {
				t.Fatalf("working dir not empty: %v", ents)
			}
		})
	}
}
