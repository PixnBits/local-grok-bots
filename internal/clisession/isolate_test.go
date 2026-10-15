package clisession

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

func TestPrepareIsolationClaudeScrubsEnv(t *testing.T) {
	user := t.TempDir()
	_ = os.MkdirAll(filepath.Join(user, ".claude"), 0o700)
	_ = os.WriteFile(filepath.Join(user, ".claude", ".credentials.json"), []byte("{}"), 0o600)
	_ = os.WriteFile(filepath.Join(user, ".claude", "settings.json"), []byte(`{"hooks":{}}`), 0o600)
	state := t.TempDir()
	home := filepath.Join(state, "home")
	iso, err := PrepareIsolation(IsolationOptions{
		Backend: "claude", StateDir: state, Home: home, UserHome: user,
		Base: []string{
			"PATH=/usr/bin", "HOME=" + user, "ANTHROPIC_API_KEY=k", "ANTHROPIC_BASE_URL=http://evil",
			"CLAUDE_CODE_USE_BEDROCK=1", "CLAUDE_CONFIG_DIR=/elsewhere", "LGB_CLI_MODE=ok",
			"AWS_SECRET_ACCESS_KEY=s", "LC_ALL=C", "XAI_API_KEY=x",
		},
		Extra: map[string]string{"ANTHROPIC_BASE_URL": "https://gw.corp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	env := envMap(iso.Env)
	want := map[string]string{
		"PATH": "/usr/bin", "HOME": home, "ANTHROPIC_API_KEY": "k",
		"ANTHROPIC_BASE_URL": "https://gw.corp", "CLAUDE_CONFIG_DIR": filepath.Join(home, ".claude"),
		"LGB_CLI_MODE": "ok", "LC_ALL": "C",
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("%s=%q, want %q", k, env[k], v)
		}
	}
	for _, k := range []string{"CLAUDE_CODE_USE_BEDROCK", "AWS_SECRET_ACCESS_KEY", "XAI_API_KEY"} {
		if _, ok := env[k]; ok {
			t.Errorf("%s leaked", k)
		}
	}
	if len(env) != len(want) {
		t.Errorf("unexpected env: %v", iso.Env)
	}
	link, err := os.Readlink(filepath.Join(home, ".claude", ".credentials.json"))
	if err != nil || link != filepath.Join(user, ".claude", ".credentials.json") {
		t.Fatalf("credentials not linked: %q %v", link, err)
	}
	if _, err := os.Lstat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Fatal("user settings copied into the isolated home")
	}
	b, err := os.ReadFile(iso.SettingsPath)
	if err != nil || !strings.Contains(string(b), `"disableAllHooks": true`) {
		t.Fatalf("settings file: %s %v", b, err)
	}
}

func TestPrepareIsolationGrok(t *testing.T) {
	user := t.TempDir()
	_ = os.MkdirAll(filepath.Join(user, ".grok"), 0o700)
	_ = os.WriteFile(filepath.Join(user, ".grok", "auth.json"), []byte("{}"), 0o600)
	state := t.TempDir()
	home := filepath.Join(state, "home")
	iso, err := PrepareIsolation(IsolationOptions{
		Backend: "grok", StateDir: state, Home: home, UserHome: user,
		Base: []string{"PATH=/bin", "GROK_CONFIG={\"x\":1}", "GROK_SANDBOX=off", "XAI_API_KEY=x", "ANTHROPIC_API_KEY=k"},
	})
	if err != nil {
		t.Fatal(err)
	}
	env := envMap(iso.Env)
	if env["GROK_HOME"] != filepath.Join(home, ".grok") || env["XAI_API_KEY"] != "x" || env["GROK_CLAUDE_MCPS_ENABLED"] != "false" {
		t.Fatalf("env: %v", iso.Env)
	}
	for _, k := range []string{"GROK_CONFIG", "GROK_SANDBOX", "ANTHROPIC_API_KEY"} {
		if _, ok := env[k]; ok {
			t.Errorf("%s leaked", k)
		}
	}
	if iso.SettingsPath != "" {
		t.Fatal("grok got a claude settings file")
	}
	src, _ := os.Stat(filepath.Join(user, ".grok", "auth.json"))
	dst, err := os.Lstat(filepath.Join(home, ".grok", "auth.json"))
	if err != nil || !dst.Mode().IsRegular() || !os.SameFile(src, dst) {
		t.Fatalf("grok auth not hard linked: %v %v", dst, err)
	}
	// The user's login replaced by rename gets relinked on the next turn.
	_ = os.WriteFile(filepath.Join(user, ".grok", "auth.json.new"), []byte(`{"v":2}`), 0o600)
	_ = os.Rename(filepath.Join(user, ".grok", "auth.json.new"), filepath.Join(user, ".grok", "auth.json"))
	if _, err := PrepareIsolation(IsolationOptions{Backend: "grok", StateDir: t.TempDir(), Home: home, UserHome: user}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(home, ".grok", "auth.json"))
	if string(b) != `{"v":2}` {
		t.Fatalf("not relinked: %s", b)
	}
}

func TestPrepareIsolationDropsInheritedLGB(t *testing.T) {
	state := t.TempDir()
	base := []string{
		"PATH=/usr/bin",
		"LGB_CLI_MODE=ok",
		"LGB_ARGV_LOG=/tmp/argv",
		"LGB_SPOOL=/tmp/evil-spool",
		"LGB_TOKEN=lgbr_inherited",
		"LGB_SESSION_MARKER=inherited-run",
		"LGB_SECRET=nope",
	}
	extra := map[string]string{"LGB_SPOOL": "/ws/.lgb", "LGB_TOKEN": "lgbr_run"}
	check := func(t *testing.T, passOther bool) {
		t.Helper()
		iso, err := PrepareIsolation(IsolationOptions{
			Backend: "claude", StateDir: state, UserHome: "/home/u",
			Base: base, Extra: extra,
		})
		if err != nil {
			t.Fatal(err)
		}
		env := envMap(iso.Env)
		if env["LGB_SPOOL"] != "/ws/.lgb" || env["LGB_TOKEN"] != "lgbr_run" {
			t.Fatalf("run token env: %v", iso.Env)
		}
		if _, ok := env["LGB_SESSION_MARKER"]; ok {
			t.Fatalf("inherited session marker leaked: %v", iso.Env)
		}
		if env["PATH"] != "/usr/bin" {
			t.Fatalf("PATH: %v", iso.Env)
		}
		for _, k := range []string{"LGB_CLI_MODE", "LGB_ARGV_LOG", "LGB_SECRET"} {
			_, ok := env[k]
			if ok != passOther {
				t.Fatalf("%s present=%v, want %v; env %v", k, ok, passOther, iso.Env)
			}
		}
	}
	if !passInheritedLGB {
		t.Fatal("test binary did not enable LGB passthrough")
	}
	check(t, true)
	prev := passInheritedLGB
	passInheritedLGB = false
	t.Cleanup(func() { passInheritedLGB = prev })
	check(t, false)
}

func TestPrepareIsolationUserHome(t *testing.T) {
	state := t.TempDir()
	iso, err := PrepareIsolation(IsolationOptions{Backend: "claude", StateDir: state, UserHome: "/home/u", Base: []string{"CLAUDE_CONFIG_DIR=/x"}})
	if err != nil {
		t.Fatal(err)
	}
	env := envMap(iso.Env)
	if env["HOME"] != "/home/u" || env["CLAUDE_CONFIG_DIR"] != "" {
		t.Fatalf("env: %v", iso.Env)
	}
}

func TestClaudeIsolationFlags(t *testing.T) {
	iso := &Isolation{SettingsPath: "/d/claude-settings.json"}
	for _, stream := range []bool{false, true} {
		argv, err := Args(Spec{Backend: "claude", Prompt: "hi", Isolate: iso, StreamControl: stream, MCPConfig: `{"mcpServers":{}}`})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{"--setting-sources=", "--strict-mcp-config", "--settings"} {
			if !slices.Contains(argv, f) {
				t.Fatalf("stream=%v missing %s: %v", stream, f, argv)
			}
		}
		i := slices.Index(argv, "--settings")
		if argv[i+1] != iso.SettingsPath {
			t.Fatalf("settings path: %v", argv)
		}
	}
	argv, _ := Args(Spec{Backend: "claude", Prompt: "hi"})
	if slices.Contains(argv, "--strict-mcp-config") {
		t.Fatal("isolation flags without Isolate")
	}
	argv, err := Args(Spec{Backend: "grok", Prompt: "hi", Isolate: &Isolation{GrokSandbox: GrokProfile}})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(argv, "--trust") || slices.Contains(argv, "--settings") {
		t.Fatalf("grok argv: %v", argv)
	}
}

func TestExecRunnerUsesOnlyIsolatedEnv(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "env")
	bin := filepath.Join(dir, "fake-claude")
	_ = os.WriteFile(bin, []byte("#!/bin/sh\nenv > "+out+"\n"), 0o755)
	t.Setenv("ANTHROPIC_BASE_URL", "http://evil")
	_, _ = ExecRunner{HasTTY: func() bool { return false }}.Run(context.Background(), Spec{
		Backend: "claude", Bin: bin, Prompt: "hi", PermissionMode: "default", Workspace: dir,
		Isolate: &Isolation{Env: []string{"PATH=/usr/bin:/bin", "HOME=" + dir}},
	}, func(Event) {})
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	env := envMap(strings.Split(strings.TrimSpace(string(b)), "\n"))
	if env["HOME"] != dir || env["ANTHROPIC_BASE_URL"] != "" {
		t.Fatalf("child env: %s", b)
	}
}

func TestScanOverridesAndNeutralized(t *testing.T) {
	ws := t.TempDir()
	for _, f := range []string{".claude/settings.json", ".mcp.json", "sub/CLAUDE.md", ".grok/config.toml", ".grok/hooks/x.sh", "AGENTS.md", "notes.md", ".git/CLAUDE.md", "node_modules/p/.mcp.json"} {
		p := filepath.Join(ws, f)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, nil, 0o644)
	}
	got := ScanOverrides(ws)
	want := []string{".claude/settings.json", ".grok/config.toml", ".grok/hooks/x.sh", ".mcp.json", "AGENTS.md", "sub/CLAUDE.md"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for _, f := range want {
		if !Neutralized("claude", f, false) {
			t.Errorf("claude should neutralize %s", f)
		}
	}
	if Neutralized("grok", ".mcp.json", true) || Neutralized("grok", "AGENTS.md", false) {
		t.Error("grok cannot neutralize .mcp.json, or anything with the user's home")
	}
	if !Neutralized("grok", ".grok/config.toml", true) {
		t.Error("grok isolated home should leave the workspace untrusted")
	}
}
