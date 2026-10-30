package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/permbroker"
)

func TestApprovalTTLBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("[backend]\nbackend = \"ollama\"\n")
	p, err := Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveApprovalTTL() != permbroker.DefaultApprovalTTL {
		t.Fatalf("default %s", p.EffectiveApprovalTTL())
	}
	for _, c := range []struct {
		body string
		want time.Duration
	}{
		{"[backend]\nbackend = \"ollama\"\n[cli.permission]\napproval_ttl = \"1m\"\n", time.Minute},
		{"[backend]\nbackend = \"ollama\"\n[cli.permission]\napproval_ttl = \"15m\"\n", 15 * time.Minute},
		{"[backend]\nbackend = \"ollama\"\n[cli.permission]\napproval_ttl = \"24h\"\n", 24 * time.Hour},
	} {
		write(c.body)
		p, err = Load(Options{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		if !p.CLIPermitted || p.ApprovalTTL != c.want || p.EffectiveApprovalTTL() != c.want {
			t.Fatalf("body %q ttl %s effective %s permitted %v warnings %v", c.body, p.ApprovalTTL, p.EffectiveApprovalTTL(), p.CLIPermitted, p.Warnings)
		}
	}
	for _, body := range []string{
		"[backend]\nbackend = \"ollama\"\n[cli.permission]\napproval_ttl = \"30s\"\n",
		"[backend]\nbackend = \"ollama\"\n[cli.permission]\napproval_ttl = \"25h\"\n",
	} {
		write(body)
		p, err = Load(Options{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		if p.CLIPermitted || !strings.Contains(strings.Join(p.Warnings, "\n"), "approval_ttl") {
			t.Fatalf("body %q permitted %v warnings %v", body, p.CLIPermitted, p.Warnings)
		}
	}
}
