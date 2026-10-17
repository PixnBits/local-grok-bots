package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestTrustSystemConfigIsManagedOnly(t *testing.T) {
	if Defaults().CLITrustSystemConfig {
		t.Fatal("default trusts host config")
	}
	dir := t.TempDir()
	local := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(local, []byte("[cli.isolation]\ntrust_system_config = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: local})
	if err != nil {
		t.Fatal(err)
	}
	if p.CLITrustSystemConfig || !strings.Contains(strings.Join(p.Warnings, "\n"), "trust_system_config") {
		t.Fatalf("local trust applied: %v %v", p.CLITrustSystemConfig, p.Warnings)
	}
	managed := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(managed, []byte(`{"cli":{"isolation":{"trust_system_config":true}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err = Load(Options{Path: local, ManagedPath: managed})
	if err != nil || !p.CLITrustSystemConfig {
		t.Fatalf("managed trust: %v %v", p.CLITrustSystemConfig, err)
	}
}

func TestManagedEnvCannotSetGrokConfig(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "policy.toml")
	managed := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(local, []byte("[backend]\nbackend = \"grok\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"GROK_CONFIG", "GROK_CONFIG_PATH", "GROK_DEFAULT_SELECTED_PERMISSION", "GROK_PERMISSION_MODE", "grok_home"} {
		body := `{"cli":{"isolation":{"env":{"` + key + `":"x","ANTHROPIC_BASE_URL":"https://gw.example"}}}}`
		if err := os.WriteFile(managed, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		p, err := Load(Options{Path: local, ManagedPath: managed})
		if err != nil {
			t.Fatal(err)
		}
		if p.CLIPermitted || p.CLIEnv != nil || !strings.Contains(strings.Join(p.Warnings, " "), key) && !strings.Contains(strings.Join(p.Warnings, " "), strings.ToUpper(key)) {
			t.Fatalf("%s permitted %v env %v warnings %v", key, p.CLIPermitted, p.CLIEnv, p.Warnings)
		}
	}
	if err := os.WriteFile(managed, []byte(`{"cli":{"isolation":{"env":{"GROK_DISABLE_AUTOUPDATER":"1","ANTHROPIC_BASE_URL":"https://gw.example"}}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: local, ManagedPath: managed})
	if err != nil || !p.CLIPermitted || p.CLIEnv["ANTHROPIC_BASE_URL"] != "https://gw.example" || p.CLIEnv["GROK_DISABLE_AUTOUPDATER"] != "1" {
		t.Fatalf("allowed env: permitted %v env %v err %v warnings %v", p.CLIPermitted, p.CLIEnv, err, p.Warnings)
	}
	if err := os.WriteFile(local, []byte("[cli.isolation]\nenv = { GROK_CONFIG = \"x\" }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err = Load(Options{Path: local})
	if err != nil || !p.CLIPermitted || p.CLIEnv != nil {
		t.Fatalf("local env fail-closed: permitted %v env %v err %v", p.CLIPermitted, p.CLIEnv, err)
	}
}

func TestBlockedCLIEnv(t *testing.T) {
	for _, key := range []string{"GROK_CONFIG", "GROK_CONFIG_PATH", "GROK_DEFAULT_SELECTED_PERMISSION", "GROK_SANDBOX", "GROK_HOME"} {
		if !BlockedCLIEnv(key) {
			t.Fatalf("allowed %s", key)
		}
	}
	for _, key := range []string{"GROK_DISABLE_AUTOUPDATER", "ANTHROPIC_BASE_URL", "PATH"} {
		if BlockedCLIEnv(key) {
			t.Fatalf("blocked %s", key)
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

func TestEgressPortPolicyNarrows(t *testing.T) {
	if ports := Defaults().EgressPorts(); strings.Join(portText(ports), ",") != "443,80" {
		t.Fatalf("default %v", ports)
	}
	dir := t.TempDir()
	local := filepath.Join(dir, "policy.toml")
	write := func(body string) Policy {
		t.Helper()
		if err := os.WriteFile(local, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		p, err := Load(Options{Path: local})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := write("[cli.isolation]\nnet_ports = [80, 443, 8443]\n")
	if strings.Join(portText(p.EgressPorts()), ",") != "443,80" {
		t.Fatalf("local widen %v", p.EgressPorts())
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "8443") || !strings.Contains(strings.Join(p.Warnings, "\n"), "can only narrow") {
		t.Fatalf("warnings %v", p.Warnings)
	}
	p = write("[cli.isolation]\nnet_ports = [443]\n")
	if strings.Join(portText(p.EgressPorts()), ",") != "443" {
		t.Fatalf("narrow %v", p.EgressPorts())
	}
	p = write("[cli.isolation]\nnet_ports = []\n")
	if len(p.EgressPorts()) != 0 {
		t.Fatalf("empty %v", p.EgressPorts())
	}
	p = write("[backend]\nbackend = \"ollama\"\n")
	if strings.Join(portText(p.EgressPorts()), ",") != "443,80" {
		t.Fatalf("unset %v", p.EgressPorts())
	}
	managed := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(managed, []byte(`{"cli":{"isolation":{"net_ports":[443,8443]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(local, []byte("[cli.isolation]\nnet_ports = [8443]\n"), 0o644)
	p, err := Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(portText(p.EgressPorts()), ",") != "8443" || len(p.Warnings) != 0 {
		t.Fatalf("managed widen kept by local: %v %v", p.EgressPorts(), p.Warnings)
	}
	_ = os.WriteFile(local, []byte("[cli.isolation]\nnet_ports = [80, 443]\n"), 0o644)
	p, err = Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(portText(p.EgressPorts()), ",") != "443" || !strings.Contains(strings.Join(p.Warnings, "\n"), "80") {
		t.Fatalf("local could not add 80 back: %v %v", p.EgressPorts(), p.Warnings)
	}
	_ = os.WriteFile(local, []byte("[backend]\nbackend = \"ollama\"\n"), 0o644)
	if err := os.WriteFile(managed, []byte(`{"cli":{"isolation":{"net_ports":[22,443]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err = Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(portText(p.EgressPorts()), ",") != "22,443" {
		t.Fatalf("managed list %v", p.EgressPorts())
	}
	for _, body := range []string{
		"[cli.isolation]\nnet_ports = [0]\n",
		"[cli.isolation]\nnet_ports = [70000]\n",
	} {
		_ = os.WriteFile(local, []byte(body), 0o644)
		p, err = Load(Options{Path: local})
		if err == nil && !strings.Contains(strings.Join(p.Warnings, "\n"), "unparseable") {
			t.Fatalf("accepted %q %v", body, p.Warnings)
		}
	}
}

func portText(ports []int) []string {
	out := make([]string, len(ports))
	for i, n := range ports {
		out[i] = itoa(n)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestLGBTimerPolicy(t *testing.T) {
	if min, per := Defaults().BotTimerLimits(); min != 0 || per != 0 {
		t.Fatalf("ollama defaults %s %d", min, per)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	write := func(body string) Policy {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		p, err := Load(Options{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := write("[backend]\nbackend = \"claude\"\n")
	if min, per := p.BotTimerLimits(); min != DefaultCLIMinTimer || per != DefaultCLIScheduledPerHour {
		t.Fatalf("cli defaults %s %d", min, per)
	}
	p = write("[backend]\nbackend = \"ollama\"\n[cli.lgb]\nmin_timer_interval = \"1d\"\nmax_scheduled_per_hour = 3\n")
	if !p.LGBMinTimerSet || p.LGBMinTimer != 24*time.Hour || !p.LGBMaxSchedSet || p.LGBMaxSchedPerHour != 3 {
		t.Fatalf("parsed %+v", p)
	}
	if min, per := p.BotTimerLimits(); min != 24*time.Hour || per != 3 {
		t.Fatalf("ollama policy limits %s %d", min, per)
	}
	p = write("[backend]\nbackend = \"grok\"\n[cli.lgb]\nmin_timer_interval = \"0\"\nmax_scheduled_per_hour = 0\n")
	if min, per := p.BotTimerLimits(); min != 0 || per != 0 || !p.UsesCLI() {
		t.Fatalf("opt-out %s %d cli %v", min, per, p.UsesCLI())
	}
	p = write("[cli.lgb]\nmin_timer_interval = \"500ms\"\n")
	if p.CLIPermitted || !strings.Contains(strings.Join(p.Warnings, " "), "min_timer_interval") {
		t.Fatalf("short floor accepted: permitted %v warnings %v", p.CLIPermitted, p.Warnings)
	}
	p = write("[cli.lgb]\nmax_scheduled_per_hour = -1\n")
	if p.CLIPermitted || !strings.Contains(strings.Join(p.Warnings, " "), "max_scheduled_per_hour") {
		t.Fatalf("negative cap accepted: permitted %v warnings %v", p.CLIPermitted, p.Warnings)
	}
}
