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
