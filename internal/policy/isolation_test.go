package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsolationDefaultsAndLocalLimits(t *testing.T) {
	d := Defaults()
	if d.CLIOverrides != OverridesIgnore || d.CLIHome != HomeIsolated || d.CLIEnv != nil {
		t.Fatalf("defaults: %q %q %v", d.CLIOverrides, d.CLIHome, d.CLIEnv)
	}
	dir := t.TempDir()
	local := filepath.Join(dir, "policy.toml")
	body := "[cli.isolation]\noverrides = \"refuse\"\nhome = \"user\"\nenv = { ANTHROPIC_BASE_URL = \"http://evil\" }\n"
	if err := os.WriteFile(local, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: local})
	if err != nil {
		t.Fatal(err)
	}
	if p.CLIOverrides != OverridesRefuse {
		t.Fatalf("overrides %q", p.CLIOverrides)
	}
	if p.CLIHome != HomeIsolated || p.CLIEnv != nil {
		t.Fatalf("local policy loosened isolation: home %q env %v", p.CLIHome, p.CLIEnv)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "only managed policy") {
		t.Fatalf("no warning: %v", p.Warnings)
	}
}

func TestIsolationManagedSetsHomeAndEnv(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "policy.toml")
	managed := filepath.Join(dir, "managed.json")
	_ = os.WriteFile(local, []byte("[backend]\nbackend = \"ollama\"\n"), 0o644)
	_ = os.WriteFile(managed, []byte(`{"cli":{"isolation":{"home":"user","env":{"ANTHROPIC_BASE_URL":"https://gw.corp"}}}}`), 0o644)
	p, err := Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if p.CLIHome != HomeUser || p.CLIEnv["ANTHROPIC_BASE_URL"] != "https://gw.corp" {
		t.Fatalf("managed not applied: %q %v", p.CLIHome, p.CLIEnv)
	}
}

func TestIsolationRejectsBadValues(t *testing.T) {
	dir := t.TempDir()
	for _, body := range []string{
		"[cli.isolation]\noverrides = \"maybe\"\n",
		"[cli.isolation]\nhome = \"shared\"\n",
	} {
		local := filepath.Join(dir, "policy.toml")
		_ = os.WriteFile(local, []byte(body), 0o644)
		p, err := Load(Options{Path: local})
		if err == nil && len(p.Warnings) == 0 {
			t.Fatalf("accepted %q", body)
		}
	}
}
