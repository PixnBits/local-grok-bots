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
		p.EffectiveOllamaRunTimeout() != 10*time.Minute || p.EffectiveOllamaModelTimeout() != 10*time.Minute ||
		p.Permission().PromptTimeout != 10*time.Minute {
		t.Fatalf("defaults %s %s %s %s", p.EffectiveTurnTimeout(), p.EffectivePromptTimeout(), p.EffectiveOllamaRunTimeout(), p.EffectiveOllamaModelTimeout())
	}
	if p.EffectiveOllamaModelTimeout() != p.EffectiveOllamaRunTimeout() ||
		p.EffectiveOllamaFirstOutputTimeout() != 5*time.Minute ||
		p.EffectiveOllamaStallTimeout() != 2*time.Minute ||
		p.EffectiveOllamaStallRetries() != 1 ||
		p.EffectiveOllamaKeepAlive() != "30m" {
		t.Fatalf("ollama defaults model=%s first=%s stall=%s retries=%d keep=%v",
			p.EffectiveOllamaModelTimeout(), p.EffectiveOllamaFirstOutputTimeout(), p.EffectiveOllamaStallTimeout(),
			p.EffectiveOllamaStallRetries(), p.EffectiveOllamaKeepAlive())
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

func TestOllamaStallAndKeepAlive(t *testing.T) {
	local := writePol(t, "policy.toml", `
[ollama]
run_timeout = "45m"
first_output_timeout = "90s"
stall_timeout = 30
stall_retries = 0
keep_alive = "1h"
max_first_output_timeout = "1m"
max_stall_timeout = "1m"
max_stall_retries = 0
`)
	p, err := Load(Options{Path: local})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveOllamaRunTimeout() != 45*time.Minute ||
		p.EffectiveOllamaModelTimeout() != 45*time.Minute ||
		p.EffectiveOllamaFirstOutputTimeout() != 90*time.Second ||
		p.EffectiveOllamaStallTimeout() != 30*time.Second ||
		p.EffectiveOllamaStallRetries() != 0 ||
		p.EffectiveOllamaKeepAlive() != "1h" {
		t.Fatalf("local model=%s first=%s stall=%s retries=%d keep=%v",
			p.EffectiveOllamaModelTimeout(), p.EffectiveOllamaFirstOutputTimeout(), p.EffectiveOllamaStallTimeout(),
			p.EffectiveOllamaStallRetries(), p.EffectiveOllamaKeepAlive())
	}
	if p.MaxOllamaFirstOutputTimeout != 0 || p.MaxOllamaStallTimeout != 0 || p.MaxOllamaStallRetriesSet {
		t.Fatalf("local ceilings applied")
	}
	warns := strings.Join(p.Warnings, "\n")
	for _, key := range []string{"ollama.max_first_output_timeout", "ollama.max_stall_timeout", "ollama.max_stall_retries"} {
		if !strings.Contains(warns, key+" is ignored; only managed policy can set a timeout ceiling") {
			t.Fatalf("missing warning for %s in %v", key, p.Warnings)
		}
	}

	managed := writePol(t, "managed.toml", `
[ollama]
max_run_timeout = "20m"
max_model_timeout = "2m"
max_first_output_timeout = "1m"
max_stall_timeout = "10s"
max_stall_retries = 0
`)
	p, err = Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveOllamaRunTimeout() != 20*time.Minute ||
		p.EffectiveOllamaModelTimeout() != 2*time.Minute ||
		p.EffectiveOllamaFirstOutputTimeout() != time.Minute ||
		p.EffectiveOllamaStallTimeout() != 10*time.Second ||
		p.EffectiveOllamaStallRetries() != 0 {
		t.Fatalf("capped run=%s model=%s first=%s stall=%s retries=%d",
			p.EffectiveOllamaRunTimeout(), p.EffectiveOllamaModelTimeout(), p.EffectiveOllamaFirstOutputTimeout(),
			p.EffectiveOllamaStallTimeout(), p.EffectiveOllamaStallRetries())
	}

	// An explicit model_timeout stays a hard cap. Unset follows the run timeout.
	unset := writePol(t, "unset.toml", "[ollama]\nrun_timeout = \"12m\"\n")
	p, err = Load(Options{Path: unset, ManagedPath: writePol(t, "cap.toml", "[ollama]\nmax_model_timeout = \"2m\"\n")})
	if err != nil || p.EffectiveOllamaModelTimeout() != 2*time.Minute || p.EffectiveOllamaRunTimeout() != 12*time.Minute {
		t.Fatalf("unset model follows run then ceiling: %s %s %v", p.EffectiveOllamaModelTimeout(), p.EffectiveOllamaRunTimeout(), err)
	}

	forms := []struct {
		body string
		want any
	}{
		{"[ollama]\nkeep_alive = \"30m\"\n", "30m"},
		{"[ollama]\nkeep_alive = \"0s\"\n", "0s"},
		{"[ollama]\nkeep_alive = \"1h\"\n", "1h"},
		{"[ollama]\nkeep_alive = 0\n", int64(0)},
		{"[ollama]\nkeep_alive = -1\n", int64(-1)},
		{"[ollama]\nkeep_alive = \"30\"\n", int64(30)},
		{"[ollama]\nkeep_alive = \"-1\"\n", int64(-1)},
	}
	for _, f := range forms {
		p, err = Load(Options{Path: writePol(t, "keep.toml", f.body)})
		if err != nil || !p.CLIPermitted || p.EffectiveOllamaKeepAlive() != f.want {
			t.Fatalf("keep %q got %#v permitted %v err %v warns %v", f.body, p.EffectiveOllamaKeepAlive(), p.CLIPermitted, err, p.Warnings)
		}
	}
	retries := []struct {
		body string
		n    int
	}{
		{"[ollama]\nstall_retries = 0\n", 0},
		{"[ollama]\nstall_retries = 5\n", 5},
		{"[ollama]\nstall_retries = \"3\"\n", 3},
	}
	for _, f := range retries {
		p, err = Load(Options{Path: writePol(t, "retries.toml", f.body)})
		if err != nil || p.EffectiveOllamaStallRetries() != f.n {
			t.Fatalf("retries %q got %d %v", f.body, p.EffectiveOllamaStallRetries(), err)
		}
	}
	bad := []string{
		"[ollama]\nfirst_output_timeout = \"soon\"\n",
		"[ollama]\nstall_timeout = \"25h\"\n",
		"[ollama]\nfirst_output_timeout = \"0s\"\n",
		"[ollama]\nstall_timeout = -5\n",
		"[ollama]\nstall_retries = -1\n",
		"[ollama]\nstall_retries = 6\n",
		"[ollama]\nstall_retries = \"1.5\"\n",
		"[ollama]\nstall_retries = \"1m\"\n",
		"[ollama]\nkeep_alive = \"forever\"\n",
		"[ollama]\nkeep_alive = \"10x\"\n",
		"[ollama]\nkeep_alive = \"-5s\"\n",
		"[ollama]\nkeep_alive = \"-1s\"\n",
		"[ollama]\nmax_stall_retries = 9\n",
	}
	for _, body := range bad {
		p, err = Load(Options{Path: writePol(t, "bad.toml", body)})
		if err != nil {
			t.Fatal(err)
		}
		if p.CLIPermitted {
			t.Fatalf("accepted %q", body)
		}
		if !strings.Contains(strings.Join(p.Warnings, " "), "ollama.") {
			t.Fatalf("warning %q for %s", p.Warnings, body)
		}
	}
	// A managed ceiling of 0 disables retries even when the local file asks for more.
	localRetries := writePol(t, "local-retries.toml", "[ollama]\nstall_retries = 4\n")
	p, err = Load(Options{Path: localRetries, ManagedPath: writePol(t, "max-retries.toml", "[ollama]\nmax_stall_retries = 0\n")})
	if err != nil || p.EffectiveOllamaStallRetries() != 0 {
		t.Fatalf("ceiling 0 retries %d %v", p.EffectiveOllamaStallRetries(), err)
	}
}
