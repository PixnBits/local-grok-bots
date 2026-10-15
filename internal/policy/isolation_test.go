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

func TestClaudeHomePerOS(t *testing.T) {
	d := Defaults()
	if d.CLIClaudeHome != HomeAuto || !d.ClaudeUsesUserHome("darwin") || d.ClaudeUsesUserHome("linux") {
		t.Fatal("auto should be user on darwin, isolated on linux")
	}
	d.CLIClaudeHome = HomeIsolated
	if d.ClaudeUsesUserHome("darwin") {
		t.Fatal("isolated on darwin")
	}
	d.CLIClaudeHome = HomeAuto
	d.CLIHome = HomeUser
	if !d.ClaudeUsesUserHome("linux") {
		t.Fatal("home=user should win")
	}
	dir := t.TempDir()
	local := filepath.Join(dir, "policy.toml")
	_ = os.WriteFile(local, []byte("[cli.isolation]\nclaude_home = \"user\"\n"), 0o644)
	p, err := Load(Options{Path: local})
	if err != nil || p.CLIClaudeHome != HomeAuto || len(p.Warnings) == 0 {
		t.Fatalf("local claude_home=user: %q %v %v", p.CLIClaudeHome, p.Warnings, err)
	}
	_ = os.WriteFile(local, []byte("[cli.isolation]\nclaude_home = \"isolated\"\n"), 0o644)
	if p, _ = Load(Options{Path: local}); p.CLIClaudeHome != HomeIsolated {
		t.Fatalf("isolated: %q", p.CLIClaudeHome)
	}
	managed := filepath.Join(dir, "managed.json")
	_ = os.WriteFile(managed, []byte(`{"cli":{"isolation":{"claude_home":"user"}}}`), 0o644)
	if p, _ = Load(Options{Path: local, ManagedPath: managed}); p.CLIClaudeHome != HomeUser {
		t.Fatalf("managed: %q", p.CLIClaudeHome)
	}
}

func TestClaudeSandboxOffIsManagedOnly(t *testing.T) {
	if Defaults().CLIClaudeSandbox != SandboxRequired {
		t.Fatalf("default %q", Defaults().CLIClaudeSandbox)
	}
	dir := t.TempDir()
	local := filepath.Join(dir, "policy.toml")
	_ = os.WriteFile(local, []byte("[cli.isolation]\nclaude_sandbox = \"off\"\n"), 0o644)
	p, err := Load(Options{Path: local})
	if err != nil {
		t.Fatal(err)
	}
	if p.CLIClaudeSandbox != SandboxRequired || !strings.Contains(strings.Join(p.Warnings, "\n"), "claude_sandbox") {
		t.Fatalf("local off applied: %q %v", p.CLIClaudeSandbox, p.Warnings)
	}
	managed := filepath.Join(dir, "managed.json")
	_ = os.WriteFile(managed, []byte(`{"cli":{"isolation":{"claude_sandbox":"off"}}}`), 0o644)
	p, err = Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if p.CLIClaudeSandbox != SandboxOff {
		t.Fatalf("managed off not applied: %q", p.CLIClaudeSandbox)
	}
	_ = os.WriteFile(local, []byte("[cli.isolation]\nclaude_sandbox = \"sometimes\"\n"), 0o644)
	if p, err := Load(Options{Path: local}); err == nil && len(p.Warnings) == 0 {
		t.Fatal("bad value accepted")
	}
}

func TestLGBPolicyKeys(t *testing.T) {
	d := Defaults()
	if !d.CLILGB || d.CLILGBManageBots {
		t.Fatalf("defaults lgb=%v manage=%v", d.CLILGB, d.CLILGBManageBots)
	}
	dir := t.TempDir()
	local := filepath.Join(dir, "policy.toml")
	_ = os.WriteFile(local, []byte("[cli.isolation]\nlgb = false\nlgb_manage_bots = true\n"), 0o644)
	p, err := Load(Options{Path: local})
	if err != nil {
		t.Fatal(err)
	}
	if p.CLILGB || !p.CLILGBManageBots {
		t.Fatalf("lgb=%v manage=%v", p.CLILGB, p.CLILGBManageBots)
	}
}
