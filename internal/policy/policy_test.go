package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultAllowsCurrentCLI(t *testing.T) {
	p := Default()
	if p.CLINetwork != NetOpen || !p.AllowsBackend("grok") || !p.AllowsBackend("claude") {
		t.Fatalf("%+v", p)
	}
	if p.AllowsBackend("openai") || p.ForceLocalOnly {
		t.Fatalf("%+v", p)
	}
	if err := p.Validate("http://127.0.0.1:11434", true); err != nil {
		t.Fatal(err)
	}
}

func TestExplicitEmptyBackendsDenyCLI(t *testing.T) {
	t.Setenv("POLICY_CLI_BACKENDS", "")
	p, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if p.AllowsBackend("grok") || p.AllowsBackend("claude") {
		t.Fatalf("%+v", p)
	}
}

func TestFileBeatsEnv(t *testing.T) {
	dir := t.TempDir()
	body := "" +
		"cli_network: none\n" +
		"allow_cli_backends: [claude]\n" +
		"cli_net_allow: []\n" +
		"default_net_allow: [Example.COM.]\n" +
		"env_allowlist: [REVIEW_NOTE]\n" +
		"force_local_only: false\n" +
		"build_binds: [/opt/tool]\n"
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLICY_CLI_NETWORK", "open")
	t.Setenv("POLICY_CLI_BACKENDS", "grok")
	t.Setenv("SANDBOX_BUILD_BINDS", "/opt/env")
	p, err := Load(dir, "http://127.0.0.1:11434", []string{"/opt/preset"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if p.CLINetwork != NetNone || strings.Join(p.AllowCLIBackends, ",") != "claude" {
		t.Fatalf("%+v", p)
	}
	if strings.Join(p.DefaultNetAllow, ",") != "example.com" || strings.Join(p.BuildBinds, ",") != "/opt/tool" {
		t.Fatalf("%+v", p)
	}
	if p.AllowsBackend("grok") || !p.AllowsBackend("claude") {
		t.Fatal(p.AllowCLIBackends)
	}
}

func TestMissingNamedFileFails(t *testing.T) {
	t.Setenv("POLICY_FILE", filepath.Join(t.TempDir(), "missing.yaml"))
	if _, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true); err == nil {
		t.Fatal("missing file was accepted")
	}
}

func TestUnknownKeyAndBadNetworkFail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("cli_network: wide\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, "http://127.0.0.1:11434", nil, true); err == nil {
		t.Fatal("bad network was accepted")
	}
	if err := os.WriteFile(path, []byte("mode: open\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, "http://127.0.0.1:11434", nil, true); err == nil {
		t.Fatal("unknown key was accepted")
	}
}

func TestProxyRequiresImplementation(t *testing.T) {
	t.Setenv("POLICY_CLI_NETWORK", "proxy")
	if _, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, false); err == nil {
		t.Fatal("proxy without an implementation was accepted")
	}
	p, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if p.CLINetwork != NetProxy {
		t.Fatal(p.CLINetwork)
	}
}

func TestForceLocalOnlyRejectsRemoteModel(t *testing.T) {
	t.Setenv("POLICY_FORCE_LOCAL_ONLY", "true")
	if _, err := Load(t.TempDir(), "http://10.1.2.3:11434", nil, true); err == nil {
		t.Fatal("remote model was accepted")
	}
	p, err := Load(t.TempDir(), "http://localhost:11434", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if !p.ForceLocalOnly || p.AllowsBackend("grok") {
		t.Fatalf("%+v", p)
	}
}

func TestBlockedEnvAndExtraEnv(t *testing.T) {
	p := Default()
	p.EnvAllowlist = []string{"XAI_API_KEY"}
	if err := p.Validate("http://127.0.0.1:11434", true); err == nil {
		t.Fatal("secret allowlist was accepted")
	}
	p.EnvAllowlist = []string{"REVIEW_NOTE"}
	if err := p.Validate("http://127.0.0.1:11434", true); err != nil {
		t.Fatal(err)
	}
	got, err := p.ExtraEnv(func(k string) (string, bool) {
		if k == "REVIEW_NOTE" {
			return "visible-note", true
		}
		return "", false
	})
	if err != nil || len(got) != 1 || got[0] != "REVIEW_NOTE=visible-note" {
		t.Fatalf("%v %v", got, err)
	}
	p.EnvAllowlist = []string{"SSH_AUTH_SOCK"}
	if _, err := p.ExtraEnv(func(string) (string, bool) { return "/tmp/a.sock", true }); err == nil {
		t.Fatal("ssh socket was passed")
	}
}

func TestCorporateProxyLoadAndRedaction(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://user:s3cret@ambient.example:8080")
	t.Setenv("POLICY_CLI_NETWORK", "open")
	openPol, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if openPol.UsesUpstream() || strings.Contains(openPol.Line(), "s3cret") {
		t.Fatalf("open policy applied or leaked the proxy: %s", openPol.Line())
	}
	if !strings.Contains(openPol.Line(), "user:xxxxx@ambient.example:8080") {
		t.Fatal(openPol.Line())
	}
	t.Setenv("HTTP_PROXY", "socks5://user:s3cret@127.0.0.1:1080")
	if _, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true); err != nil {
		t.Fatal(err)
	}

	t.Setenv("POLICY_CLI_NETWORK", "explicit-proxy")
	t.Setenv("HTTP_PROXY", "socks5://user:s3cret@127.0.0.1:1080")
	if _, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true); err == nil {
		t.Fatal("socks5 proxy was accepted")
	}

	t.Setenv("POLICY_HTTP_PROXY", "http://user:s3cret@policy.example:8080")
	t.Setenv("HTTP_PROXY", "http://other.example:1")
	t.Setenv("POLICY_NO_PROXY", "localhost, .example.com")
	pol, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if !pol.UsesUpstream() || pol.HTTPProxy != "http://user:s3cret@policy.example:8080" {
		t.Fatalf("%+v", pol)
	}
	if strings.Contains(pol.Line(), "s3cret") || !strings.Contains(pol.Line(), "policy.example:8080") {
		t.Fatal(pol.Line())
	}

	dir := t.TempDir()
	body := "cli_network: explicit-proxy\nhttp_proxy: \"http://file.example:8080\"\nhttps_proxy: \"http://file.example:8443\"\nno_proxy: localhost\n"
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	filePol, err := Load(dir, "http://127.0.0.1:11434", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if filePol.HTTPProxy != "http://file.example:8080" || filePol.HTTPSProxy != "http://file.example:8443" {
		t.Fatalf("%+v", filePol)
	}

	t.Setenv("POLICY_CLI_NETWORK", "proxy")
	t.Setenv("POLICY_HTTP_PROXY", "")
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("http_proxy", "")
	empty, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if empty.UsesUpstream() || empty.HTTPProxy != "" {
		t.Fatalf("%+v", empty)
	}
	empty.EnvAllowlist = []string{"HTTP_PROXY"}
	if err := empty.Validate("http://127.0.0.1:11434", true); err == nil {
		t.Fatal("HTTP_PROXY allowlist was accepted")
	}
}

func TestCLIPinsParseAndRejectMistakes(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	t.Setenv("POLICY_CLI_PINS", "grok sha256="+hash+";claude version=2.1.0")
	p, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	g, ok := p.CLIPinFor("grok")
	if !ok || g.SHA256 != hash {
		t.Fatalf("%+v", p.CLIPins)
	}
	if _, ok := p.CLIPinFor("missing"); ok {
		t.Fatal("missing backend was pinned")
	}
	dir := t.TempDir()
	body := "cli_pins: [\"claude path=/usr/bin/claude sha256=" + hash + "\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	filePol, err := Load(dir, "http://127.0.0.1:11434", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(filePol.CLIPins) != 1 || filePol.CLIPins[0].Backend != "claude" || filePol.CLIPins[0].Path != "/usr/bin/claude" {
		t.Fatalf("%+v", filePol.CLIPins)
	}
	for _, raw := range []string{
		"grok sha256=abc",
		"grok path=relative",
		"openai sha256=" + hash,
		"grok sha256=" + hash + ";grok version=1",
	} {
		t.Setenv("POLICY_CLI_PINS", raw)
		if _, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	t.Setenv("POLICY_CLI_PINS", "")
	empty, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true)
	if err != nil || len(empty.CLIPins) != 0 {
		t.Fatal(err)
	}
}

func TestDLPRejectsBadRules(t *testing.T) {
	if Default().DLPEnabled() || Default().DLPScanTools {
		t.Fatal("default dlp is on")
	}
	t.Setenv("POLICY_DLP_PATTERNS", "[")
	if _, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true); err == nil {
		t.Fatal("bad regex was accepted")
	}
	t.Setenv("POLICY_DLP_PATTERNS", "")
	t.Setenv("POLICY_DLP_FILE", "block.txt")
	if _, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true); err == nil {
		t.Fatal("relative dlp file was accepted")
	}
	t.Setenv("POLICY_DLP_FILE", "")
	t.Setenv("POLICY_DLP_COMMAND", filepath.Join(t.TempDir(), "missing-scan"))
	if _, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true); err == nil {
		t.Fatal("missing dlp command was accepted")
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "scan.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	block := filepath.Join(dir, "block.txt")
	if err := os.WriteFile(block, []byte("# note\nproject-secret\nre:(?i)\\btoken-[0-9]+\\b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := "dlp_patterns: [\"(?i)\\bssn\\b\"]\ndlp_file: " + block + "\ndlp_command: " + script + "\ndlp_scan_tools: true\n"
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLICY_DLP_COMMAND", filepath.Join(dir, "from-env"))
	p, err := Load(dir, "http://127.0.0.1:11434", nil, true)
	if err != nil || p.DLPCommand != script || p.DLPFile != block || !p.DLPScanTools || !p.DLPEnabled() {
		t.Fatalf("%v %+v", err, p)
	}
	if len(p.DLPPatterns) != 1 || p.DLPPatterns[0] != `(?i)\bssn\b` {
		t.Fatalf("%+v", p.DLPPatterns)
	}
}

func TestAuditLogPath(t *testing.T) {
	t.Setenv("POLICY_AUDIT_LOG", "audit.log")
	if _, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true); err == nil {
		t.Fatal("relative audit path was accepted")
	}
	t.Setenv("POLICY_AUDIT_LOG", "stderr")
	p, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true)
	if err != nil || p.AuditLog != "stderr" {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("audit_log: /var/log/lgb-audit.log\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	filePol, err := Load(dir, "http://127.0.0.1:11434", nil, true)
	if err != nil || filePol.AuditLog != "/var/log/lgb-audit.log" {
		t.Fatalf("%v %+v", err, filePol)
	}
}

func TestNetAllowUsesDefaultWhenBotHasNone(t *testing.T) {
	p := Default()
	p.DefaultNetAllow = []string{"example.com"}
	if got := strings.Join(p.NetAllow([]string{"net"}, nil), ","); got != "example.com" {
		t.Fatal(got)
	}
	if got := strings.Join(p.NetAllow([]string{"net"}, []string{"other.test"}), ","); got != "other.test" {
		t.Fatal(got)
	}
	if got := p.NetAllow(nil, nil); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestCLIROBindsValidation(t *testing.T) {
	if len(Default().CLIROBinds) != 0 {
		t.Fatal("default cli ro binds are set")
	}
	data := t.TempDir()
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "cli_ro_binds: [\"" + shared + "\"]\n"
	if err := os.WriteFile(filepath.Join(data, "policy.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLICY_CLI_RO_BINDS", filepath.Join(t.TempDir(), "from-env"))
	p, err := Load(data, "http://127.0.0.1:11434", nil, true)
	if err != nil || len(p.CLIROBinds) != 1 || p.CLIROBinds[0] != shared {
		t.Fatalf("%v %+v", err, p.CLIROBinds)
	}
	raw, err := p.MarshalJSON()
	if err != nil || !strings.Contains(string(raw), shared) || !strings.Contains(string(raw), `"cli_ro_binds"`) {
		t.Fatalf("%s %v", raw, err)
	}

	t.Setenv("POLICY_CLI_RO_BINDS", "")
	empty, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true)
	if err != nil || len(empty.CLIROBinds) != 0 {
		t.Fatal(err)
	}

	t.Setenv("POLICY_CLI_RO_BINDS", "relative/path")
	if _, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatal(err)
	}

	refused := filepath.Join(t.TempDir(), ".ssh")
	if err := os.Mkdir(refused, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLICY_CLI_RO_BINDS", refused)
	if _, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatal(err)
	}

	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("POLICY_CLI_RO_BINDS", missing)
	if _, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatal(err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLICY_CLI_RO_BINDS", filepath.Join(home, ".grok"))
	if _, err := Load(t.TempDir(), "http://127.0.0.1:11434", nil, true); err == nil || !strings.Contains(err.Error(), "login") {
		t.Fatal(err)
	}

	overlap := t.TempDir()
	ws := filepath.Join(overlap, "workspace")
	if err := os.Mkdir(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLICY_CLI_RO_BINDS", ws)
	if _, err := Load(overlap, "http://127.0.0.1:11434", nil, true); err == nil || !strings.Contains(err.Error(), "workspace") {
		t.Fatal(err)
	}
}
