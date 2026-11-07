package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/permbroker"
)

func TestGolden_PolicyCannotLowerShippedLevel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`
[backend]
backend = "ollama"
[cli.permission]
broker = "hook"
[[cli.permission.risk]]
tool = "run_shell"
argv = ["git", "status"]
level = "unclassified"
`)
	if _, err := Load(Options{Path: path}); !errors.Is(err, permbroker.ErrLevelLowered) {
		t.Fatalf("lower: %v", err)
	}
	write(`
[backend]
backend = "ollama"
[cli.permission]
broker = "sometimes"
`)
	if _, err := Load(Options{Path: path}); !errors.Is(err, errBrokerConfig) {
		t.Fatalf("broker: %v", err)
	}
	write(`
[backend]
backend = "ollama"
[cli.permission]
broker = "hook"
[[cli.permission.risk]]
tool = "run_shell"
argv = ["git", "status"]
level = "high"
`)
	p, err := Load(Options{Path: path})
	if err != nil || p.Broker != "hook" || len(p.BrokerRisks) != 1 || p.BrokerRisks[0].Level != permbroker.LevelHigh {
		t.Fatalf("raise err=%v policy=%+v", err, p.BrokerRisks)
	}
}

func TestAllowCeilingLoad(t *testing.T) {
	const bot = "11111111-1111-4111-8111-111111111111"
	const other = "22222222-2222-4222-8222-222222222222"
	const mixed = "aabbccdd-1111-4111-8111-111111111111"
	head := "[backend]\nbackend = \"ollama\"\n[cli.permission]\nbroker = \"hook\"\n"
	listed := head + "broker_bots = [\"" + bot + "\"]\n"
	sub := "\n[cli.permission.dangerouslyAllowAllPermissionRequestsUpThrough]\n"
	cases := []struct {
		name    string
		local   string
		managed string
		ok      bool
	}{
		{name: "local_layer", local: listed + sub + bot + " = \"medium\"\n"},
		{name: "local_empty_table", local: listed + sub},
		{name: "unknown_level", local: listed, managed: sub + bot + " = \"severe\"\n"},
		{name: "unclassified", local: listed, managed: sub + bot + " = \"unclassified\"\n"},
		{name: "upper_level", local: listed, managed: sub + bot + " = \"HIGH\"\n"},
		{name: "mixed_case_level", local: listed, managed: sub + bot + " = \"Low\"\n"},
		{name: "padded_level", local: listed, managed: sub + bot + " = \" low \"\n"},
		{name: "missing_or_empty_value", local: listed, managed: sub + bot + " = \"\"\n"},
		{name: "wildcard_key", local: listed, managed: sub + "\"*\" = \"low\"\n"},
		{name: "non_uuid_key", local: head + "broker_bots = [\"bot-id\"]\n", managed: sub + "bot-id = \"low\"\n"},
		{name: "non_map_value", local: listed, managed: listed + "dangerouslyAllowAllPermissionRequestsUpThrough = \"low\"\n"},
		{name: "bot_not_in_broker_bots", local: head + "broker_bots = [\"" + other + "\"]\n", managed: sub + bot + " = \"low\"\n"},
		{name: "duplicate_case", local: head + "broker_bots = [\"" + bot + "\", \"" + mixed + "\"]\n", managed: sub + mixed + " = \"low\"\n" + strings.ToUpper(mixed) + " = \"high\"\n"},
		{name: "folded_table_name", local: listed, managed: "\n[cli.permission.dangerouslyallowallpermissionrequestsupthrough]\n" + bot + " = \"low\"\n"},
		{name: "subtable", local: listed, managed: sub + bot + " = \"medium\"\n", ok: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "policy.toml")
			if err := os.WriteFile(path, []byte(tc.local), 0o600); err != nil {
				t.Fatal(err)
			}
			opts := Options{Path: path}
			if tc.managed != "" {
				mp := filepath.Join(dir, "managed.toml")
				if err := os.WriteFile(mp, []byte(tc.managed), 0o600); err != nil {
					t.Fatal(err)
				}
				opts.ManagedPath = mp
			}
			p, err := Load(opts)
			if tc.ok {
				if err != nil || !p.Loaded || p.AllowCeilings[bot] != permbroker.LevelMedium {
					t.Fatalf("err=%v loaded=%v ceilings=%v warnings=%v", err, p.Loaded, p.AllowCeilings, p.Warnings)
				}
				if p.Broker != "hook" || len(p.BrokerBots) != 1 || p.BrokerBots[0] != bot {
					t.Fatalf("broker %q bots %v", p.Broker, p.BrokerBots)
				}
				return
			}
			if err == nil || !errors.Is(err, errAllowCeiling) {
				t.Fatalf("err=%v loaded=%v warnings=%v", err, p.Loaded, p.Warnings)
			}
		})
	}
}

func TestAllowCeilingUntrustedApply(t *testing.T) {
	const bot = "11111111-1111-4111-8111-111111111111"
	broker := "hook"
	bots := []string{bot}
	doc := document{}
	doc.CLI.Permission = &cliPermDoc{
		Broker:       &broker,
		BrokerBots:   &bots,
		AllowThrough: map[string]any{bot: "low"},
	}
	p := Defaults()
	if err := p.apply(doc, false); !errors.Is(err, errAllowCeiling) {
		t.Fatalf("untrusted err=%v ceilings=%v", err, p.AllowCeilings)
	}
	p = Defaults()
	if err := p.apply(doc, true); err != nil || p.AllowCeilings[bot] != permbroker.LevelLow {
		t.Fatalf("trusted err=%v ceilings=%v", err, p.AllowCeilings)
	}
}

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

func TestPolicyBindOverridesUnsetEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.toml")
	if err := os.WriteFile(path, []byte("[daemon]\nbind = \"0.0.0.0:8080\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: path, EnvBind: ""})
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasBind || p.Bind != "0.0.0.0:8080" {
		t.Fatalf("bind %#v set %v", p.Bind, p.HasBind)
	}
	for _, w := range p.Warnings {
		if strings.Contains(w, "BIND_ADDR") {
			t.Fatalf("unset BIND_ADDR warned: %s", w)
		}
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
	if len(p.ServerTools) != 0 || p.ServerToolsSource != "default" {
		t.Fatalf("sample server tools %#v %s", p.ServerTools, p.ServerToolsSource)
	}
}

func TestExplicitPermissionMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.toml")
	if err := os.WriteFile(path, []byte("[backend]\nbackend = \"claude\"\n[cli]\npermission_mode = \"acceptEdits\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if p.PermissionMode != "acceptEdits" || p.ManagedBypass || !p.UsesCLI() {
		t.Fatalf("mode %q bypass %v backend %s", p.PermissionMode, p.ManagedBypass, p.Backend)
	}
	if p.PromptTimeout != DefaultPromptTimeout || p.AllowSessionGrants || p.UIPrompts {
		t.Fatalf("defaults timeout %s grants %v ui %v", p.PromptTimeout, p.AllowSessionGrants, p.UIPrompts)
	}
}

func TestUserPolicyCannotEnableBypassOrSessionGrants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.toml")
	body := `
[backend]
backend = "claude"

[cli]
permission_mode = "bypassPermissions"

[cli.permission]
mode = "always-allow"
allow = ["Read", "Bash(git status*)"]
deny = ["Bash(rm *)"]
ask = ["Bash(git push*)"]
ui_prompts = true
prompt_timeout = "45s"
allow_session_grants = true
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if p.PermissionMode != "" || p.ManagedBypass || p.AllowSessionGrants {
		t.Fatalf("user policy kept privileged settings: mode %q bypass %v grants %v", p.PermissionMode, p.ManagedBypass, p.AllowSessionGrants)
	}
	if !p.UIPrompts || p.PromptTimeout != 45*time.Second {
		t.Fatalf("ui %v timeout %s", p.UIPrompts, p.PromptTimeout)
	}
	if len(p.ToolAllow) != 2 || p.ToolAllow[1] != "Bash(git status*)" || p.ToolDeny[0] != "Bash(rm *)" || p.ToolAsk[0] != "Bash(git push*)" {
		t.Fatalf("rules allow %v deny %v ask %v", p.ToolAllow, p.ToolDeny, p.ToolAsk)
	}
	joined := strings.Join(p.Warnings, "\n")
	if !strings.Contains(joined, "always-allow") || !strings.Contains(joined, "allow_session_grants") {
		t.Fatalf("warnings %v", p.Warnings)
	}
	view := p.Permission()
	if view.AllowSessionGrants || view.Mode != "" || view.PromptTimeout != 45*time.Second || !view.UIPrompts {
		t.Fatalf("view %+v", view)
	}
}

func TestManagedPolicyHonorsBypassAndSessionGrants(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "policy.toml")
	managed := filepath.Join(dir, "managed.json")
	user := `
[backend]
backend = "claude"

[cli.permission]
mode = "default"
allow_session_grants = true
allow = ["Read"]
ui_prompts = false
`
	if err := os.WriteFile(local, []byte(user), 0o644); err != nil {
		t.Fatal(err)
	}
	body := `{
	  "cli": {
	    "permission": {
	      "mode": "bypassPermissions",
	      "allow_session_grants": true,
	      "ui_prompts": true,
	      "prompt_timeout": "30s",
	      "deny": ["Bash(rm *)"]
	    }
	  }
	}`
	if err := os.WriteFile(managed, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if p.PermissionMode != "bypassPermissions" || !p.ManagedBypass || !p.AllowSessionGrants {
		t.Fatalf("managed mode %q bypass %v grants %v", p.PermissionMode, p.ManagedBypass, p.AllowSessionGrants)
	}
	if !p.UIPrompts || p.PromptTimeout != 30*time.Second {
		t.Fatalf("ui %v timeout %s", p.UIPrompts, p.PromptTimeout)
	}
	if len(p.ToolAllow) != 1 || p.ToolAllow[0] != "Read" || len(p.ToolDeny) != 1 {
		t.Fatalf("rules survived overlay allow %v deny %v", p.ToolAllow, p.ToolDeny)
	}
	if !IsBypassMode(p.PermissionMode) || IsBypassMode("acceptEdits") || IsBypassMode("default") {
		t.Fatal("bypass classification")
	}
}

func TestClaudeTransportSelection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.toml")
	base := "[backend]\nbackend = \"claude\"\n[cli.permission]\nui_prompts = true\n"
	if err := os.WriteFile(path, []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if p.ClaudeTransport != TransportMCP || !p.CLIPermitted || p.DaemonJail {
		t.Fatalf("default transport %#v", p)
	}
	for _, want := range []string{TransportMCP, TransportStreamControl, TransportNone} {
		body := base + "claude_transport = \"" + want + "\"\n"
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		p, err = Load(Options{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		if p.ClaudeTransport != want || !p.CLIPermitted || !p.UIPrompts {
			t.Fatalf("transport %q got %#v", want, p.ClaudeTransport)
		}
	}
	if err := os.WriteFile(path, []byte(base+"claude_transport = \"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err = Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if p.ClaudeTransport != TransportMCP {
		t.Fatalf("empty transport %q", p.ClaudeTransport)
	}
}

func TestUnknownClaudeTransportFailClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	body := "[backend]\nbackend = \"claude\"\n[cli.permission]\nclaude_transport = \"websocket\"\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if p.CLIPermitted || p.Loaded || !p.DaemonJail || p.EffectiveBackend() != "ollama" {
		t.Fatalf("unknown transport did not fail closed: %#v", p)
	}
	if len(p.Warnings) == 0 || !strings.Contains(p.Warnings[0], "unparseable") || !strings.Contains(p.Warnings[0], "claude_transport") {
		t.Fatalf("warnings %#v", p.Warnings)
	}

	managed := filepath.Join(dir, "managed.json")
	local := filepath.Join(dir, "local.toml")
	if err := os.WriteFile(local, []byte("[backend]\nbackend = \"claude\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw := `{"backend":{"backend":"claude"},"cli":{"permission":{"claude_transport":"stdio"}}}`
	if err := os.WriteFile(managed, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err = Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if p.CLIPermitted || !p.DaemonJail || p.EffectiveBackend() != "ollama" {
		t.Fatalf("managed unknown transport did not fail closed: %#v", p)
	}
	if len(p.Warnings) == 0 || !strings.Contains(strings.Join(p.Warnings, " "), "claude_transport") {
		t.Fatalf("managed warnings %#v", p.Warnings)
	}
}
