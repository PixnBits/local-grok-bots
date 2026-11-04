package policy

import (
	"strings"
	"testing"
	"time"
)

func TestRunLimitDefaultsAndCeilings(t *testing.T) {
	p := Defaults()
	if p.EffectiveToolRounds() != DefaultOllamaToolRounds || p.EffectiveShellTimeout() != DefaultOllamaShellTimeout {
		t.Fatalf("defaults rounds=%d shell=%s", p.EffectiveToolRounds(), p.EffectiveShellTimeout())
	}
	n, src := p.ToolRoundsCeiling()
	if n != 8 || src != "the built-in default" || p.ToolRoundsCeilingKey() != "" {
		t.Fatalf("rounds ceiling %d %q key %q", n, src, p.ToolRoundsCeilingKey())
	}
	d, src := p.ShellTimeoutCeiling()
	if d != 30*time.Second || src != "the built-in default" || p.ShellTimeoutCeilingKey() != "" {
		t.Fatalf("shell ceiling %s %q key %q", d, src, p.ShellTimeoutCeilingKey())
	}
	d, src = p.RunTimeoutCeiling(false)
	if d != 10*time.Minute || src != "the built-in default" || p.RunTimeoutCeilingKey(false) != "" {
		t.Fatalf("ollama run ceiling %s %q key %q", d, src, p.RunTimeoutCeilingKey(false))
	}
	d, src = p.RunTimeoutCeiling(true)
	if d != 2*time.Hour || src != "the built-in default" || p.RunTimeoutCeilingKey(true) != "" {
		t.Fatalf("cli run ceiling %s %q key %q", d, src, p.RunTimeoutCeilingKey(true))
	}
}

func TestLocalRunLimitsAndManagedCeilings(t *testing.T) {
	local := writePol(t, "policy.toml", `
[ollama]
tool_rounds = 12
shell_timeout = "2m"
max_tool_rounds = 3
max_shell_timeout = "10s"
`)
	p, err := Load(Options{Path: local})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveToolRounds() != 12 || p.EffectiveShellTimeout() != 2*time.Minute {
		t.Fatalf("local rounds=%d shell=%s warnings=%v", p.EffectiveToolRounds(), p.EffectiveShellTimeout(), p.Warnings)
	}
	if p.MaxOllamaToolRounds != 0 || p.MaxOllamaShellTimeout != 0 {
		t.Fatalf("local ceilings applied: %+v", p)
	}
	if n := strings.Count(strings.Join(p.Warnings, "\n"), "only managed policy can set a timeout ceiling"); n != 2 {
		t.Fatalf("warnings %v", p.Warnings)
	}
	n, src := p.ToolRoundsCeiling()
	if n != 12 || src != "policy.toml" || p.ToolRoundsCeilingKey() != "ollama.tool_rounds" {
		t.Fatalf("local rounds ceiling %d %q key %q", n, src, p.ToolRoundsCeilingKey())
	}
	d, src := p.ShellTimeoutCeiling()
	if d != 2*time.Minute || src != "policy.toml" || p.ShellTimeoutCeilingKey() != "ollama.shell_timeout" {
		t.Fatalf("local shell ceiling %s %q key %q", d, src, p.ShellTimeoutCeilingKey())
	}

	managed := writePol(t, "managed.toml", `
[ollama]
max_tool_rounds = 4
max_shell_timeout = "45s"
`)
	p, err = Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveToolRounds() != 4 || p.EffectiveShellTimeout() != 45*time.Second {
		t.Fatalf("capped rounds=%d shell=%s", p.EffectiveToolRounds(), p.EffectiveShellTimeout())
	}
	n, src = p.ToolRoundsCeiling()
	if n != 4 || src != "your administrator" || p.ToolRoundsCeilingKey() != "ollama.max_tool_rounds" {
		t.Fatalf("managed rounds ceiling %d %q key %q", n, src, p.ToolRoundsCeilingKey())
	}
	d, src = p.ShellTimeoutCeiling()
	if d != 45*time.Second || src != "your administrator" || p.ShellTimeoutCeilingKey() != "ollama.max_shell_timeout" {
		t.Fatalf("managed shell ceiling %s %q key %q", d, src, p.ShellTimeoutCeilingKey())
	}
	warns := strings.Join(p.Warnings, "\n")
	for _, w := range []string{
		"ollama.tool_rounds 12 lowered to managed max_tool_rounds 4",
		"ollama.shell_timeout 2m lowered to managed max_shell_timeout 45s",
	} {
		if !strings.Contains(warns, w) {
			t.Fatalf("missing %q in %v", w, p.Warnings)
		}
	}

	replaced := writePol(t, "managed2.toml", "[ollama]\ntool_rounds = 3\nshell_timeout = \"15s\"\n")
	p, err = Load(Options{Path: local, ManagedPath: replaced})
	if err != nil || p.EffectiveToolRounds() != 3 || p.EffectiveShellTimeout() != 15*time.Second {
		t.Fatalf("managed value rounds=%d shell=%s %v", p.EffectiveToolRounds(), p.EffectiveShellTimeout(), err)
	}
	if strings.Contains(strings.Join(p.Warnings, "\n"), "lowered") {
		t.Fatalf("managed replace warned: %v", p.Warnings)
	}
}

func TestBadRunLimitsFailClosed(t *testing.T) {
	cases := []struct{ body, want string }{
		{"[backend]\nbackend = \"claude\"\n[ollama]\ntool_rounds = 0\n", "ollama.tool_rounds must be an integer from 1 to 100"},
		{"[backend]\nbackend = \"claude\"\n[ollama]\ntool_rounds = 101\n", "ollama.tool_rounds must be an integer from 1 to 100"},
		{"[backend]\nbackend = \"claude\"\n[ollama]\ntool_rounds = \"soon\"\n", "ollama.tool_rounds must be an integer from 1 to 100"},
		{"[backend]\nbackend = \"claude\"\n[ollama]\nshell_timeout = \"soon\"\n", "ollama.shell_timeout must be seconds or a Go duration"},
		{"[backend]\nbackend = \"claude\"\n[ollama]\nshell_timeout = \"500ms\"\n", "ollama.shell_timeout must be at least 1s"},
		{"[backend]\nbackend = \"claude\"\n[ollama]\nshell_timeout = \"1.5s\"\n", "ollama.shell_timeout must be a whole number of seconds, at least 1s"},
		{"[backend]\nbackend = \"claude\"\n[ollama]\nshell_timeout = \"90.001s\"\n", "ollama.shell_timeout must be a whole number of seconds, at least 1s"},
		{"[backend]\nbackend = \"claude\"\n[ollama]\nmax_shell_timeout = \"1.5s\"\n", "ollama.max_shell_timeout must be a whole number of seconds, at least 1s"},
		{"[backend]\nbackend = \"claude\"\n[ollama]\nshell_timeout = \"25h\"\n", "ollama.shell_timeout exceeds 24h"},
		{"[backend]\nbackend = \"claude\"\n[ollama]\nmax_tool_rounds = 0\n", "ollama.max_tool_rounds must be an integer from 1 to 100"},
		{"[backend]\nbackend = \"claude\"\n[ollama]\nmax_shell_timeout = \"0s\"\n", "ollama.max_shell_timeout must be positive"},
	}
	for _, c := range cases {
		p, err := Load(Options{Path: writePol(t, "bad.toml", c.body)})
		if err != nil {
			t.Fatal(err)
		}
		if p.CLIPermitted {
			t.Fatalf("accepted %q", c.body)
		}
		got := strings.Join(p.Warnings, "\n")
		if !strings.Contains(got, c.want) {
			t.Fatalf("body %q warning %q want %q", c.body, got, c.want)
		}
	}
}

func TestManagedMaxRunLimitsCapDefault(t *testing.T) {
	p, err := Load(Options{ManagedPath: writePol(t, "defcap.toml", "[ollama]\nmax_tool_rounds = 2\nmax_shell_timeout = \"5s\"\n")})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveToolRounds() != 2 || p.EffectiveShellTimeout() != 5*time.Second {
		t.Fatalf("default capped rounds=%d shell=%s", p.EffectiveToolRounds(), p.EffectiveShellTimeout())
	}
	n, src := p.ToolRoundsCeiling()
	if n != 2 || src != "your administrator" || p.ToolRoundsCeilingKey() != "ollama.max_tool_rounds" {
		t.Fatalf("default rounds ceiling %d %q key %q", n, src, p.ToolRoundsCeilingKey())
	}
	d, src := p.ShellTimeoutCeiling()
	if d != 5*time.Second || src != "your administrator" || p.ShellTimeoutCeilingKey() != "ollama.max_shell_timeout" {
		t.Fatalf("default shell ceiling %s %q key %q", d, src, p.ShellTimeoutCeilingKey())
	}
	if strings.Contains(strings.Join(p.Warnings, "\n"), "lowered") {
		t.Fatalf("warned a clamped default: %v", p.Warnings)
	}
}

func TestRunTimeoutCeilingCLIUsesTurnTimeout(t *testing.T) {
	local := writePol(t, "policy.toml", `
[cli]
turn_timeout = "30m"
[ollama]
run_timeout = "5m"
`)
	p, err := Load(Options{Path: local})
	if err != nil {
		t.Fatal(err)
	}
	d, src := p.RunTimeoutCeiling(true)
	if d != 30*time.Minute || src != "policy.toml" || p.RunTimeoutCeilingKey(true) != "cli.turn_timeout" {
		t.Fatalf("cli %s %q key %q", d, src, p.RunTimeoutCeilingKey(true))
	}
	d, src = p.RunTimeoutCeiling(false)
	if d != 5*time.Minute || src != "policy.toml" || p.RunTimeoutCeilingKey(false) != "ollama.run_timeout" {
		t.Fatalf("ollama %s %q key %q", d, src, p.RunTimeoutCeilingKey(false))
	}
	managed := writePol(t, "managed.toml", "[cli]\nmax_turn_timeout = \"10m\"\n")
	p, err = Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	d, src = p.RunTimeoutCeiling(true)
	if d != 10*time.Minute || src != "your administrator" || p.RunTimeoutCeilingKey(true) != "cli.max_turn_timeout" {
		t.Fatalf("cli capped %s %q key %q", d, src, p.RunTimeoutCeilingKey(true))
	}
}

func TestLocalRunLimitWithinCeilingIsNotWarned(t *testing.T) {
	p, err := Load(Options{
		Path:        writePol(t, "within.toml", "[ollama]\ntool_rounds = 3\nshell_timeout = \"10s\"\n"),
		ManagedPath: writePol(t, "max.toml", "[ollama]\nmax_tool_rounds = 8\nmax_shell_timeout = \"1m\"\n"),
	})
	if err != nil || p.EffectiveToolRounds() != 3 || p.EffectiveShellTimeout() != 10*time.Second {
		t.Fatalf("within rounds=%d shell=%s %v", p.EffectiveToolRounds(), p.EffectiveShellTimeout(), err)
	}
	if strings.Contains(strings.Join(p.Warnings, "\n"), "lowered") {
		t.Fatalf("warned within ceiling: %v", p.Warnings)
	}
	n, src := p.ToolRoundsCeiling()
	if n != 3 || src != "policy.toml" || p.ToolRoundsCeilingKey() != "ollama.tool_rounds" {
		t.Fatalf("within rounds ceiling %d %q key %q", n, src, p.ToolRoundsCeilingKey())
	}
}

func TestShellTimeoutWholeSecondsAndSignalCap(t *testing.T) {
	ok, err := Load(Options{Path: writePol(t, "whole.toml", "[ollama]\nshell_timeout = \"1m30s\"\nmax_shell_timeout = \"2h\"\n")})
	if err != nil {
		t.Fatal(err)
	}
	if ok.OllamaShellTimeout != 90*time.Second {
		t.Fatalf("stored %s", ok.OllamaShellTimeout)
	}
	UseShellSignal(func() bool { return false })
	t.Cleanup(func() { UseShellSignal(nil) })
	p, err := Load(Options{Path: writePol(t, "long.toml", "[ollama]\nshell_timeout = \"2m\"\n")})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveShellTimeout() != 30*time.Second {
		t.Fatalf("effective %s", p.EffectiveShellTimeout())
	}
	d, src := p.ShellTimeoutCeiling()
	if d != 30*time.Second || src != "this system" || p.ShellTimeoutCeilingKey() != "" {
		t.Fatalf("ceiling %s %q key %q", d, src, p.ShellTimeoutCeilingKey())
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "shell timeouts above 30s are unavailable on this system; the ceiling is 30s") {
		t.Fatalf("warnings %v", p.Warnings)
	}
	short, err := Load(Options{Path: writePol(t, "short.toml", "[ollama]\nshell_timeout = \"10s\"\n")})
	if err != nil {
		t.Fatal(err)
	}
	d, src = short.ShellTimeoutCeiling()
	if d != 10*time.Second || src != "policy.toml" || short.ShellTimeoutCeilingKey() != "ollama.shell_timeout" {
		t.Fatalf("short ceiling %s %q key %q", d, src, short.ShellTimeoutCeilingKey())
	}
	if !strings.Contains(strings.Join(short.Warnings, "\n"), "shell timeouts above 30s are unavailable on this system; the ceiling is 30s") {
		t.Fatalf("short warnings %v", short.Warnings)
	}
}
