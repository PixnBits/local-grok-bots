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
