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

func assertOllamaTimes(t *testing.T, p Policy, first, stall, model, run time.Duration) {
	t.Helper()
	if p.EffectiveOllamaFirstOutputTimeout() != first ||
		p.EffectiveOllamaStallTimeout() != stall ||
		p.EffectiveOllamaModelTimeout() != model ||
		p.EffectiveOllamaRunTimeout() != run {
		t.Fatalf("first=%s stall=%s model=%s run=%s warnings=%v",
			p.EffectiveOllamaFirstOutputTimeout(), p.EffectiveOllamaStallTimeout(),
			p.EffectiveOllamaModelTimeout(), p.EffectiveOllamaRunTimeout(), p.Warnings)
	}
}

func TestExplicitModelTimeoutIsNotStricter(t *testing.T) {
	// Prod shape: an explicit model_timeout widens unset silence limits to
	// that value. They used to fall through to 5m / 2m and cut calls the
	// old cap allowed.
	prod := writePol(t, "prod.toml", "[ollama]\nmodel_timeout = \"10m\"\nrun_timeout = \"30m\"\n")
	p, err := Load(Options{Path: prod})
	if err != nil {
		t.Fatal(err)
	}
	assertOllamaTimes(t, p, 10*time.Minute, 10*time.Minute, 10*time.Minute, 30*time.Minute)

	onlyStall := writePol(t, "stall.toml", "[ollama]\nmodel_timeout = \"10m\"\nstall_timeout = \"45s\"\nrun_timeout = \"30m\"\n")
	p, err = Load(Options{Path: onlyStall})
	if err != nil {
		t.Fatal(err)
	}
	assertOllamaTimes(t, p, 10*time.Minute, 45*time.Second, 10*time.Minute, 30*time.Minute)

	onlyFirst := writePol(t, "first.toml", "[ollama]\nmodel_timeout = \"10m\"\nfirst_output_timeout = \"90s\"\n")
	p, err = Load(Options{Path: onlyFirst})
	if err != nil {
		t.Fatal(err)
	}
	assertOllamaTimes(t, p, 90*time.Second, 10*time.Minute, 10*time.Minute, 10*time.Minute)

	local := writePol(t, "local.toml", "[daemon]\nbind = \"127.0.0.1:8787\"\n")
	managed := writePol(t, "managed.toml", "[ollama]\nmodel_timeout = \"10m\"\nrun_timeout = \"30m\"\n")
	p, err = Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	assertOllamaTimes(t, p, 10*time.Minute, 10*time.Minute, 10*time.Minute, 30*time.Minute)

	capped := writePol(t, "cap.toml", "[ollama]\nmax_first_output_timeout = \"4m\"\n")
	p, err = Load(Options{Path: prod, ManagedPath: capped})
	if err != nil {
		t.Fatal(err)
	}
	assertOllamaTimes(t, p, 4*time.Minute, 10*time.Minute, 10*time.Minute, 30*time.Minute)
	if strings.Contains(strings.Join(p.Warnings, "\n"), "lowered") {
		t.Fatalf("inherited silence default was warned: %v", p.Warnings)
	}

	unset := writePol(t, "unset.toml", "[ollama]\nrun_timeout = \"12m\"\n")
	p, err = Load(Options{Path: unset})
	if err != nil {
		t.Fatal(err)
	}
	assertOllamaTimes(t, p, 5*time.Minute, 2*time.Minute, 12*time.Minute, 12*time.Minute)
}

func TestTimeoutErrorsNameTheirKey(t *testing.T) {
	cases := []struct{ body, want string }{
		{"[ollama]\nstall_timeout = \"soon\"\n", "ollama.stall_timeout must be seconds or a Go duration"},
		{"[ollama]\nrun_timeout = \"25h\"\n", "ollama.run_timeout exceeds 24h"},
		{"[ollama]\nfirst_output_timeout = \"0s\"\n", "ollama.first_output_timeout must be positive"},
		{"[ollama]\nmodel_timeout = 0\n", "ollama.model_timeout must be positive"},
		{"[ollama]\nstall_timeout = \"0\"\n", "ollama.stall_timeout must be positive"},
		{"[ollama]\nmodel_timeout = \"0s\"\n", "ollama.model_timeout must be positive"},
		{"[cli]\nturn_timeout = \"0s\"\n", "cli.turn_timeout must be positive"},
		{"[cli.permission]\nprompt_timeout = \"soon\"\n", "cli.permission.prompt_timeout must be seconds or a Go duration"},
		{"[cli]\nmax_turn_timeout = \"25h\"\n", "cli.max_turn_timeout exceeds 24h"},
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
		if strings.Contains(got, ": turn_timeout") {
			t.Fatalf("leaked turn_timeout name: %s", got)
		}
	}
}

func TestLocalValueAboveCeilingWarns(t *testing.T) {
	local := writePol(t, "local.toml", `
[ollama]
run_timeout = "45m"
model_timeout = "10m"
first_output_timeout = "8m"
stall_timeout = "5m"
stall_retries = 4
[cli]
turn_timeout = "6h"
[cli.permission]
prompt_timeout = "30m"
`)
	managed := writePol(t, "managed.toml", `
[ollama]
max_run_timeout = "20m"
max_model_timeout = "2m"
max_first_output_timeout = "3m"
max_stall_timeout = "1m"
max_stall_retries = 1
[cli]
max_turn_timeout = "3h"
[cli.permission]
max_prompt_timeout = "5m"
`)
	p, err := Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveOllamaRunTimeout() != 20*time.Minute ||
		p.EffectiveOllamaModelTimeout() != 2*time.Minute ||
		p.EffectiveOllamaFirstOutputTimeout() != 3*time.Minute ||
		p.EffectiveOllamaStallTimeout() != time.Minute ||
		p.EffectiveOllamaStallRetries() != 1 ||
		p.EffectiveTurnTimeout() != 3*time.Hour ||
		p.EffectivePromptTimeout() != 5*time.Minute {
		t.Fatalf("capped run=%s model=%s first=%s stall=%s retries=%d turn=%s prompt=%s",
			p.EffectiveOllamaRunTimeout(), p.EffectiveOllamaModelTimeout(), p.EffectiveOllamaFirstOutputTimeout(),
			p.EffectiveOllamaStallTimeout(), p.EffectiveOllamaStallRetries(), p.EffectiveTurnTimeout(), p.EffectivePromptTimeout())
	}
	warns := strings.Join(p.Warnings, "\n")
	want := []string{
		"ollama.run_timeout 45m lowered to managed max_run_timeout 20m",
		"ollama.model_timeout 10m lowered to managed max_model_timeout 2m",
		"ollama.first_output_timeout 8m lowered to managed max_first_output_timeout 3m",
		"ollama.stall_timeout 5m lowered to managed max_stall_timeout 1m",
		"ollama.stall_retries 4 lowered to managed max_stall_retries 1",
		"cli.turn_timeout 6h lowered to managed max_turn_timeout 3h",
		"cli.permission.prompt_timeout 30m lowered to managed max_prompt_timeout 5m",
	}
	for _, w := range want {
		if !strings.Contains(warns, w) {
			t.Fatalf("missing %q in %v", w, p.Warnings)
		}
	}
	if strings.Count(warns, "lowered to managed") != len(want) {
		t.Fatalf("warnings %v", p.Warnings)
	}

	// Inside or equal to the ceiling: no warning. A clamped default is not warned.
	within := writePol(t, "within.toml", "[ollama]\nstall_timeout = \"30s\"\nstall_retries = 1\n")
	p, err = Load(Options{Path: within, ManagedPath: writePol(t, "max.toml", "[ollama]\nmax_stall_timeout = \"2m\"\nmax_stall_retries = 3\n")})
	if err != nil || p.EffectiveOllamaStallTimeout() != 30*time.Second || p.EffectiveOllamaStallRetries() != 1 {
		t.Fatalf("within stall=%s retries=%d %v", p.EffectiveOllamaStallTimeout(), p.EffectiveOllamaStallRetries(), err)
	}
	if strings.Contains(strings.Join(p.Warnings, "\n"), "lowered") {
		t.Fatalf("warned within ceiling: %v", p.Warnings)
	}
	equal := writePol(t, "equal.toml", "[ollama]\nstall_timeout = \"1m\"\n")
	p, err = Load(Options{Path: equal, ManagedPath: writePol(t, "maxeq.toml", "[ollama]\nmax_stall_timeout = \"1m\"\n")})
	if err != nil || p.EffectiveOllamaStallTimeout() != time.Minute {
		t.Fatalf("equal %s %v", p.EffectiveOllamaStallTimeout(), err)
	}
	if strings.Contains(strings.Join(p.Warnings, "\n"), "lowered") {
		t.Fatalf("warned equal ceiling: %v", p.Warnings)
	}
	p, err = Load(Options{ManagedPath: writePol(t, "defcap.toml", "[ollama]\nmax_run_timeout = \"1m\"\n")})
	if err != nil || p.EffectiveOllamaRunTimeout() != time.Minute {
		t.Fatalf("default capped %s %v", p.EffectiveOllamaRunTimeout(), err)
	}
	if strings.Contains(strings.Join(p.Warnings, "\n"), "lowered") {
		t.Fatalf("warned a clamped default: %v", p.Warnings)
	}
}
