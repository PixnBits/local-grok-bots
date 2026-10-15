package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writePol(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTimeoutDefaults(t *testing.T) {
	p := Defaults()
	if p.EffectiveTurnTimeout() != 2*time.Hour || p.EffectivePromptTimeout() != 10*time.Minute ||
		p.EffectiveOllamaRunTimeout() != 10*time.Minute || p.EffectiveOllamaModelTimeout() != 3*time.Minute ||
		p.Permission().PromptTimeout != 10*time.Minute {
		t.Fatalf("defaults %s %s %s %s", p.EffectiveTurnTimeout(), p.EffectivePromptTimeout(), p.EffectiveOllamaRunTimeout(), p.EffectiveOllamaModelTimeout())
	}
}

func TestLocalTimeoutsAndManagedCeilings(t *testing.T) {
	local := writePol(t, "policy.toml", `
[ollama]
run_timeout = "45m"
model_timeout = 600
max_run_timeout = "1m"
[cli]
turn_timeout = "6h"
max_turn_timeout = "1m"
[cli.permission]
prompt_timeout = "30m"
max_prompt_timeout = "1m"
`)
	p, err := Load(Options{Path: local})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveTurnTimeout() != 6*time.Hour || p.EffectivePromptTimeout() != 30*time.Minute ||
		p.EffectiveOllamaRunTimeout() != 45*time.Minute || p.EffectiveOllamaModelTimeout() != 10*time.Minute {
		t.Fatalf("local %s %s %s %s %v", p.EffectiveTurnTimeout(), p.EffectivePromptTimeout(), p.EffectiveOllamaRunTimeout(), p.EffectiveOllamaModelTimeout(), p.Warnings)
	}
	// A ceiling in the local file is ignored with a warning.
	if p.MaxTurnTimeout != 0 || p.MaxPromptTimeout != 0 || p.MaxOllamaRunTimeout != 0 {
		t.Fatalf("local ceilings applied: %+v", p)
	}
	if n := strings.Count(strings.Join(p.Warnings, "\n"), "only managed policy can set a timeout ceiling"); n != 3 {
		t.Fatalf("warnings %v", p.Warnings)
	}
	managed := writePol(t, "managed.toml", `
[ollama]
max_run_timeout = "20m"
max_model_timeout = "2m"
[cli]
max_turn_timeout = "3h"
[cli.permission]
max_prompt_timeout = "5m"
`)
	p, err = Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveTurnTimeout() != 3*time.Hour || p.EffectivePromptTimeout() != 5*time.Minute ||
		p.EffectiveOllamaRunTimeout() != 20*time.Minute || p.EffectiveOllamaModelTimeout() != 2*time.Minute ||
		p.Permission().PromptTimeout != 5*time.Minute {
		t.Fatalf("capped %s %s %s %s", p.EffectiveTurnTimeout(), p.EffectivePromptTimeout(), p.EffectiveOllamaRunTimeout(), p.EffectiveOllamaModelTimeout())
	}
	// Managed values win over local ones, the same as other keys.
	m2 := writePol(t, "managed2.toml", "[cli]\nturn_timeout = \"30m\"\n")
	p, err = Load(Options{Path: local, ManagedPath: m2})
	if err != nil || p.EffectiveTurnTimeout() != 30*time.Minute {
		t.Fatalf("managed value %s %v", p.EffectiveTurnTimeout(), err)
	}
}

func TestBadTimeoutFailsClosed(t *testing.T) {
	p, err := Load(Options{Path: writePol(t, "policy.toml", "[backend]\nbackend = \"claude\"\n[ollama]\nrun_timeout = \"soon\"\n")})
	if err != nil {
		t.Fatal(err)
	}
	if p.CLIPermitted || !strings.Contains(strings.Join(p.Warnings, " "), "ollama.run_timeout") {
		t.Fatalf("%v %v", p.CLIPermitted, p.Warnings)
	}
}
