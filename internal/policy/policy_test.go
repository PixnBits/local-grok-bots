package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMissingPolicyFailClosed(t *testing.T) {
	p, err := Load(Options{Path: filepath.Join(t.TempDir(), "nope.toml")})
	if err != nil {
		t.Fatal(err)
	}
	if p.CLIPermitted || p.UsesCLI() || !p.DaemonJail || p.EffectiveBackend() != "ollama" {
		t.Fatalf("fail-closed %#v", p)
	}
	if len(p.Warnings) == 0 || !strings.Contains(p.Warnings[0], "fail-closed") {
		t.Fatalf("warnings %#v", p.Warnings)
	}
	if p.Idle != 30*time.Minute || p.Imminent != 2*time.Minute {
		t.Fatalf("idle defaults %s %s", p.Idle, p.Imminent)
	}
	if p.PermissionMode != "" {
		t.Fatalf("permission mode %q", p.PermissionMode)
	}
}

func TestUnparseableFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.toml")
	if err := os.WriteFile(path, []byte("backend = [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if p.CLIPermitted || p.Loaded || p.EffectiveBackend() != "ollama" || !p.DaemonJail {
		t.Fatalf("unparseable %#v warnings=%v", p.Backend, p.Warnings)
	}
}

func TestPolicySelectsCLIAndJailFollows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.toml")
	body := `
[daemon]
bind = "127.0.0.1:8787"

[backend]
backend = "claude"
allow = ["claude", "ollama"]

[ollama]
host = "http://127.0.0.1:11434"
model = "llama3.1"
models = ["llama3.1"]

[cli]
idle_timeout_minutes = 15
imminent_timer_minutes = 3
turn_timeout = "30m"

[timers]
enabled = true

[security]
fail_closed = true
conflict_policy = "refuse"
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: path, EnvBind: "0.0.0.0:8080"})
	if err != nil {
		t.Fatal(err)
	}
	if !p.UsesCLI() || p.DaemonJail || p.EffectiveBackend() != "claude" {
		t.Fatalf("backend %#v jail %v", p.Backend, p.DaemonJail)
	}
	if !p.HasBind || p.Bind != "127.0.0.1:8787" {
		t.Fatalf("bind %#v", p.Bind)
	}
	if p.Idle != 15*time.Minute || p.Imminent != 3*time.Minute || p.TurnTimeout != 30*time.Minute {
		t.Fatalf("times %s %s %s", p.Idle, p.Imminent, p.TurnTimeout)
	}
	if p.PermissionMode != "" {
		t.Fatalf("permission defaulted to %q", p.PermissionMode)
	}
	if err := p.AllowsModel("llama3.1"); err != nil {
		t.Fatal(err)
	}
	if err := p.AllowsModel("other"); err == nil {
		t.Fatal("model allow-list did not reject")
	}
	if !p.AllowsBackend("claude") || p.AllowsBackend("grok") {
		t.Fatalf("allow %v", p.Allow)
	}
	if len(p.Warnings) == 0 || !strings.Contains(p.Warnings[0], "BIND_ADDR") {
		t.Fatalf("expected env override warning, got %#v", p.Warnings)
	}
}

func TestManagedOverridesAndConflict(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "policy.toml")
	managed := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(local, []byte("[backend]\nbackend = \"ollama\"\n[cli]\npermission_mode = \"default\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managed, []byte(`{"backend":{"backend":"grok"},"daemon":{"bind":"127.0.0.1:9"},"cli":{"permission_mode":"bypassPermissions"},"security":{"conflict_policy":"refuse"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveBackend() != "grok" || p.DaemonJail || p.PermissionMode != "bypassPermissions" {
		t.Fatalf("managed did not win: backend %s jail %v mode %q", p.Backend, p.DaemonJail, p.PermissionMode)
	}
	_, err = Load(Options{Path: local, ManagedPath: managed, EnvBind: "0.0.0.0:8080"})
	if err == nil || !strings.Contains(err.Error(), "BIND_ADDR") {
		t.Fatalf("conflict err %v", err)
	}
}

func TestManagedConflictLogDoesNotRefuse(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "policy.toml")
	managed := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(local, []byte("[backend]\nbackend = \"ollama\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managed, []byte(`{"daemon":{"bind":"127.0.0.1:9"},"security":{"conflict_policy":"log"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: local, ManagedPath: managed, EnvBind: "0.0.0.0:1"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Bind != "127.0.0.1:9" {
		t.Fatalf("bind %s", p.Bind)
	}
	joined := strings.Join(p.Warnings, "\n")
	if !strings.Contains(joined, "conflict") {
		t.Fatalf("warnings %#v", p.Warnings)
	}
}

func TestSamplePolicy(t *testing.T) {
	p, err := Load(Options{Path: filepath.Join("..", "..", "policy.toml.sample")})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveBackend() != "ollama" || !p.DaemonJail || !p.CLIPermitted {
		t.Fatalf("sample %#v jail %v permitted %v", p.Backend, p.DaemonJail, p.CLIPermitted)
	}
	if p.Idle != 30*time.Minute || p.Imminent != 2*time.Minute || !p.TimersEnabled {
		t.Fatalf("sample cli %s %s timers %v", p.Idle, p.Imminent, p.TimersEnabled)
	}
	if p.Bind != "127.0.0.1:8787" || p.OllamaModel != "llama3.1" {
		t.Fatalf("sample bind %s model %s", p.Bind, p.OllamaModel)
	}
	if p.PermissionMode != "" {
		t.Fatalf("sample permission %q", p.PermissionMode)
	}
}

func TestExplicitPermissionMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.toml")
	if err := os.WriteFile(path, []byte("[backend]\nbackend = \"claude\"\n[cli]\npermission_mode = \"bypassPermissions\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if p.PermissionMode != "bypassPermissions" || !p.UsesCLI() {
		t.Fatalf("mode %q backend %s", p.PermissionMode, p.Backend)
	}
}
