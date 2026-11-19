package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJobLifetimeBounds(t *testing.T) {
	var p Policy
	if p.EffectiveJobLifetime() != DefaultJobLifetime || p.EventLoop {
		t.Fatalf("default lifetime %s event_loop %v", p.EffectiveJobLifetime(), p.EventLoop)
	}
	p.OllamaJobLifetime = 48 * time.Hour
	if p.EffectiveJobLifetime() != MaxJobLifetime {
		t.Fatalf("ceiling %s", p.EffectiveJobLifetime())
	}
	p.OllamaJobLifetime = 3 * time.Hour
	p.MaxOllamaJobLifetime = time.Hour
	if p.EffectiveJobLifetime() != time.Hour {
		t.Fatalf("managed ceiling %s", p.EffectiveJobLifetime())
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("[backend]\nbackend = \"ollama\"\n[ollama]\njob_lifetime = \"2h\"\n")
	loaded, err := Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if loaded.EffectiveJobLifetime() != 2*time.Hour || loaded.EventLoop || loaded.JobsEnabled() {
		t.Fatalf("loaded lifetime %s jobs %v", loaded.EffectiveJobLifetime(), loaded.JobsEnabled())
	}
	write("[backend]\nbackend = \"ollama\"\n[ollama]\njobs = true\n")
	on, err := Load(Options{Path: path})
	if err != nil || !on.JobsEnabled() {
		t.Fatalf("host jobs on=%v err %v", on.JobsEnabled(), err)
	}
	managedOff := filepath.Join(dir, "managed-off.toml")
	if err := os.WriteFile(managedOff, []byte("[ollama]\njobs = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	off, err := Load(Options{Path: path, ManagedPath: managedOff})
	if err != nil || off.JobsEnabled() {
		t.Fatalf("managed off wins: on=%v err %v", off.JobsEnabled(), err)
	}
	managedOn := filepath.Join(dir, "managed-on.toml")
	if err := os.WriteFile(managedOn, []byte("[ollama]\njobs = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	write("[backend]\nbackend = \"ollama\"\n[ollama]\njobs = false\n")
	forced, err := Load(Options{Path: path, ManagedPath: managedOn})
	if err != nil || !forced.JobsEnabled() {
		t.Fatalf("managed on wins: on=%v err %v", forced.JobsEnabled(), err)
	}
	write("[backend]\nbackend = \"ollama\"\n[ollama]\njob_lifetime = \"25h\"\n")
	bad, err := Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if bad.CLIPermitted || !strings.Contains(strings.Join(bad.Warnings, "\n"), "ollama.job_lifetime exceeds 24h") {
		t.Fatalf("25h permitted %v warnings %v", bad.CLIPermitted, bad.Warnings)
	}
}
