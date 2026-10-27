package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHotReloadFields(t *testing.T) {
	start := Policy{Backend: "ollama", CLIPermitted: true, Bind: "127.0.0.1:1", ClaudeTransport: TransportMCP}
	fresh := Policy{
		Backend: "claude", CLIPermitted: true, Bind: "127.0.0.1:9",
		VoiceEnabled: true, WhisperBin: "/voice/bin", WhisperModel: "/voice/model", HasWhisper: true,
		ClaudeTransport: TransportStreamControl, AllowedHosts: []string{"voice.example"},
	}
	got := start.WithHot(fresh)
	if got.Backend != "ollama" || got.Bind != "127.0.0.1:1" || len(got.AllowedHosts) != 0 {
		t.Fatalf("fixed fields changed: %#v", got)
	}
	if !got.VoiceEnabled || got.WhisperBin != "/voice/bin" || got.ClaudeTransport != TransportStreamControl || !got.HasWhisper {
		t.Fatalf("hot fields: %#v", got)
	}
	if !HotEqual(got, fresh) {
		t.Fatal("hot subset differs")
	}
	if HotEqual(start, fresh) {
		t.Fatal("different hot subset compared equal")
	}
	off := got.VoiceOff()
	if off.VoiceEnabled || off.HasWhisper || off.WhisperBin != "" || off.ClaudeTransport != TransportStreamControl {
		t.Fatalf("voice off: %#v", off)
	}
	keys := RestartKeys(start, fresh)
	joined := strings.Join(keys, ",")
	if !strings.Contains(joined, "backend") || !strings.Contains(joined, "bind") || !strings.Contains(joined, "allowed_hosts") {
		t.Fatalf("keys %v", keys)
	}
	if strings.Contains(joined, "claude") || strings.Contains(joined, "/voice") {
		t.Fatalf("values in keys %v", keys)
	}
	if len(RestartKeys(start, start)) != 0 {
		t.Fatal("identical policies reported keys")
	}
	plain := start
	opt := start
	opt.AllowInsecureLAN = true
	if strings.Join(RestartKeys(plain, opt), ",") != "allow_insecure_lan" {
		t.Fatalf("keys %v", RestartKeys(plain, opt))
	}
	kept := plain.WithHot(opt)
	if kept.AllowInsecureLAN {
		t.Fatal("allow_insecure_lan changed on a hot copy")
	}
}

func TestAllowInsecureLANBool(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("[daemon]\nallow_insecure_lan = true\n")
	p, err := Load(Options{Path: path})
	if err != nil || !p.Loaded || !p.AllowInsecureLAN {
		t.Fatalf("loaded %v flag %v err %v warnings %v", p.Loaded, p.AllowInsecureLAN, err, p.Warnings)
	}
	write("[daemon]\nallow_insecure_lan = false\n")
	p, err = Load(Options{Path: path})
	if err != nil || !p.Loaded || p.AllowInsecureLAN {
		t.Fatalf("false loaded %v flag %v err %v", p.Loaded, p.AllowInsecureLAN, err)
	}
	write("[daemon]\nallow_insecure_lan = \"yes\"\n")
	p, err = Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if p.Loaded || p.CLIPermitted || p.AllowInsecureLAN || p.UsesCLI() {
		t.Fatalf("bad bool loaded %v permitted %v flag %v cli %v", p.Loaded, p.CLIPermitted, p.AllowInsecureLAN, p.UsesCLI())
	}
}

func TestAllowedHostsFailClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("[daemon]\nallowed_hosts = [\"voice.example\", \"::1\"]\n")
	p, err := Load(Options{Path: path})
	if err != nil || !p.Loaded || !p.CLIPermitted {
		t.Fatalf("valid hosts loaded %v permitted %v err %v warnings %v", p.Loaded, p.CLIPermitted, err, p.Warnings)
	}
	if strings.Join(p.AllowedHosts, ",") != "voice.example,::1" {
		t.Fatalf("hosts %#v", p.AllowedHosts)
	}
	for _, bad := range []string{"http://voice.example", "voice.example:443", "*.example.com", "[::1]", "voice example", ""} {
		write("[backend]\nbackend = \"claude\"\n[daemon]\nallowed_hosts = [\"" + bad + "\"]\n")
		p, err = Load(Options{Path: path})
		if err != nil {
			t.Fatalf("%q returned %v", bad, err)
		}
		if p.Loaded || p.CLIPermitted || p.UsesCLI() || p.EffectiveBackend() != "ollama" {
			t.Fatalf("%q loaded %v permitted %v cli %v backend %s", bad, p.Loaded, p.CLIPermitted, p.UsesCLI(), p.EffectiveBackend())
		}
	}
	if _, err := NormalizeHosts(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeHosts([]string{"localhost"}); err != nil {
		t.Fatal(err)
	}
}

func TestAllowedHostsRejectsBadEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []string{"*", "bad_name!", "host:8080"} {
		write("[daemon]\nallowed_hosts = [\"" + bad + "\"]\n")
		p, err := Load(Options{Path: path})
		if err != nil {
			t.Fatalf("%q returned %v", bad, err)
		}
		if p.Loaded || p.CLIPermitted {
			t.Fatalf("%q loaded %v permitted %v", bad, p.Loaded, p.CLIPermitted)
		}
		if err := ValidHostName(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	write("[daemon]\nallowed_hosts = [\"100.64.0.10\", \"2001:db8::10\", \"myhost.tailnet-example.ts.net\"]\n")
	p, err := Load(Options{Path: path})
	if err != nil || !p.Loaded || !p.CLIPermitted {
		t.Fatalf("placeholders loaded %v permitted %v err %v", p.Loaded, p.CLIPermitted, err)
	}
	if strings.Join(p.AllowedHosts, ",") != "100.64.0.10,2001:db8::10,myhost.tailnet-example.ts.net" {
		t.Fatalf("hosts %#v", p.AllowedHosts)
	}
}

func TestAllowedHostsRejectsBroadAddresses(t *testing.T) {
	for _, bad := range []string{
		"0.0.0.0", "::", "255.255.255.255", "224.0.0.1",
		"::ffff:192.0.2.10", "1.2.3", "999.1.1.1",
	} {
		if err := ValidHostName(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
		p, err := Load(Options{Path: writeHostPolicy(t, bad)})
		if err != nil {
			t.Fatalf("%q returned %v", bad, err)
		}
		if p.Loaded || p.CLIPermitted {
			t.Fatalf("%q loaded %v permitted %v", bad, p.Loaded, p.CLIPermitted)
		}
	}
	for _, good := range []string{"127.0.0.1", "::1", "192.0.2.10", "100.64.0.10", "2001:db8::10", "myhost.tailnet-example.ts.net"} {
		if err := ValidHostName(good); err != nil {
			t.Fatalf("%q rejected: %v", good, err)
		}
	}
}

func writeHostPolicy(t *testing.T, host string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	body := "[daemon]\nallowed_hosts = [\"" + host + "\"]\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
