package clisession

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func nlink(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("stat has no nlink")
	}
	return uint64(st.Nlink)
}

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
	real := filepath.Join(user, ".grok", "auth.json")
	const marker = "unit-real-marker-value"
	if err := os.WriteFile(real, []byte(`{"key":"`+marker+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before := nlink(t, real)
	state := t.TempDir()
	home := filepath.Join(state, "home")
	// A planted hard link becomes a regular placeholder. A symlink is refused.
	plant := filepath.Join(home, ".grok")
	if err := os.MkdirAll(plant, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(real, filepath.Join(plant, "auth.json")); err != nil {
		t.Fatal(err)
	}
	iso, err := PrepareIsolation(IsolationOptions{
		Backend: "grok", StateDir: state, Home: home, UserHome: user,
		Base:  []string{"PATH=/bin", "GROK_CONFIG={\"x\":1}", "GROK_SANDBOX=off", "XAI_API_KEY=" + marker, "ANTHROPIC_API_KEY=k"},
		Extra: map[string]string{"XAI_API_KEY": marker, "XAI_API_BASE_URL": "https://api.x.ai/v1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	env := envMap(iso.Env)
	if env["GROK_HOME"] != filepath.Join(home, ".grok") || env["XAI_API_KEY"] != GrokPlaceholderToken || env["GROK_CLAUDE_MCPS_ENABLED"] != "false" {
		t.Fatalf("env: %v", iso.Env)
	}
	if env["XAI_API_BASE_URL"] != "" && !strings.Contains(env["XAI_API_BASE_URL"], "api.x.ai") {
		t.Fatalf("base url %q", env["XAI_API_BASE_URL"])
	}
	if strings.Contains(strings.Join(iso.Env, "\n"), marker) {
		t.Fatal("real marker reached the cli env")
	}
	for _, k := range []string{"GROK_CONFIG", "GROK_SANDBOX", "ANTHROPIC_API_KEY"} {
		if _, ok := env[k]; ok {
			t.Errorf("%s leaked", k)
		}
	}
	if iso.SettingsPath != "" {
		t.Fatal("grok got a claude settings file")
	}
	if nlink(t, real) != before || before != 1 {
		t.Fatalf("link count %d, was %d", nlink(t, real), before)
	}
	dstPath := filepath.Join(home, ".grok", "auth.json")
	dst, err := os.Lstat(dstPath)
	if err != nil || dst.Mode()&os.ModeSymlink != 0 || !dst.Mode().IsRegular() {
		t.Fatalf("bot auth is not a regular file: %v %v", dst, err)
	}
	src, _ := os.Stat(real)
	if os.SameFile(src, dst) {
		t.Fatal("bot auth shares the user inode")
	}
	b, err := os.ReadFile(dstPath)
	if err != nil || strings.Contains(string(b), marker) || string(b) != GrokPlaceholderAuth {
		t.Fatalf("bot auth = %q %v", b, err)
	}
	// Replacing the user file does not relink it into the bot home.
	_ = os.WriteFile(real+".new", []byte(`{"v":2,"key":"second-marker-value"}`), 0o600)
	_ = os.Rename(real+".new", real)
	const gate = "unit-gate-token-aaaa"
	if _, err := PrepareIsolation(IsolationOptions{
		Backend: "grok", StateDir: state, Home: home, UserHome: user,
		ProxyBase: "http://127.0.0.1:9",
	}); err == nil {
		t.Fatal("proxy without a per-run key")
	}
	if _, err := PrepareIsolation(IsolationOptions{
		Backend: "grok", StateDir: state, Home: home, UserHome: user,
		ProxyBase: "http://127.0.0.1:9", ProxyGate: gate,
	}); err != nil {
		t.Fatal(err)
	}
	if nlink(t, real) != 1 {
		t.Fatalf("link count after replace %d", nlink(t, real))
	}
	b, _ = os.ReadFile(dstPath)
	if strings.Contains(string(b), "second-marker-value") || strings.Contains(string(b), GrokPlaceholderToken) || !strings.Contains(string(b), gate) {
		t.Fatalf("bot auth followed the user file: %s", b)
	}
	iso2, err := PrepareIsolation(IsolationOptions{
		Backend: "grok", StateDir: state, Home: home, UserHome: user,
		ProxyBase: "http://127.0.0.1:9", ProxyGate: gate,
	})
	if err != nil {
		t.Fatal(err)
	}
	env = envMap(iso2.Env)
	if env["XAI_API_KEY"] != gate {
		t.Fatalf("key %q", env["XAI_API_KEY"])
	}
	for _, k := range []string{"GROK_CLI_CHAT_PROXY_BASE_URL", "GROK_XAI_API_BASE_URL", "XAI_API_BASE_URL"} {
		if env[k] != "http://127.0.0.1:9/v1" {
			t.Fatalf("%s=%q", k, env[k])
		}
	}
}

func TestPrepareIsolationGrokDropsDaemonMarkers(t *testing.T) {
	// Production builds do not copy LGB_* from the daemon. This test checks
	// that path. Test binaries still pass other LGB_* names so fakes can log.
	prev := passInheritedLGB
	passInheritedLGB = false
	t.Cleanup(func() { passInheritedLGB = prev })
	user := t.TempDir()
	state := t.TempDir()
	home := filepath.Join(state, "home")
	const (
		token     = "fake-admin-token-value"
		secret    = "fake-secret-canary"
		adminPath = "/tmp/lgb-admin-token-canary"
		canary    = "canary-var-value"
		gate      = "unit-gate-token-bbbb"
	)
	iso, err := PrepareIsolation(IsolationOptions{
		Backend: "grok", StateDir: state, Home: home, UserHome: user,
		ProxyBase: "http://127.0.0.1:9", ProxyGate: gate,
		Secrets: []string{token},
		Base: []string{
			"PATH=/usr/bin:/bin",
			"TERM=xterm-256color",
			"LANG=C.UTF-8",
			"HOME=/home/daemon",
			"USER=daemon",
			"LOGNAME=daemon",
			"SHELL=/bin/bash",
			"TZ=UTC",
			"TMPDIR=/tmp",
			"HTTP_PROXY=http://proxy.example",
			"HTTPS_PROXY=http://proxy.example",
			"LC_ALL=C",
			"SSL_CERT_FILE=/etc/ssl/cert.pem",
			"NODE_EXTRA_CA_CERTS=/etc/ssl/cert.pem",
			"AUTH_TOKEN=" + token,
			"LGB_FAKE_SECRET=" + secret,
			"LGB_ADMIN_TOKEN_PATH=" + adminPath,
			"LGB_CANARY_VAR=" + canary,
			"DAEMON_CANARY=" + canary,
			"GROK_CONFIG={\"x\":1}",
			"GROK_SANDBOX=off",
			"ANTHROPIC_API_KEY=k",
		},
		Extra: map[string]string{
			"LGB_TOKEN": "lgbr_run",
			"LGB_SPOOL": filepath.Join(home, ".lgb"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	env := envMap(iso.Env)
	want := map[string]string{
		"PATH":                         "/usr/bin:/bin",
		"TERM":                         "xterm-256color",
		"LANG":                         "C.UTF-8",
		"HOME":                         home,
		"XAI_API_KEY":                  gate,
		"GROK_CLI_CHAT_PROXY_BASE_URL": "http://127.0.0.1:9/v1",
		"GROK_XAI_API_BASE_URL":        "http://127.0.0.1:9/v1",
		"XAI_API_BASE_URL":             "http://127.0.0.1:9/v1",
		"LGB_TOKEN":                    "lgbr_run",
		"LGB_SPOOL":                    filepath.Join(home, ".lgb"),
		"GROK_HOME":                    filepath.Join(home, ".grok"),
		"GROK_DISABLE_AUTOUPDATER":     "1",
		"GROK_CLAUDE_MCPS_ENABLED":     "false",
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("%s=%q", k, env[k])
		}
	}
	allowed := map[string]bool{
		"PATH": true, "TERM": true, "LANG": true, "HOME": true,
		"XAI_API_KEY": true, "XAI_API_BASE_URL": true,
		"GROK_CLI_CHAT_PROXY_BASE_URL": true, "GROK_XAI_API_BASE_URL": true,
		"LGB_TOKEN": true, "LGB_SPOOL": true,
	}
	for k := range env {
		if allowed[k] || strings.HasPrefix(k, "GROK_") {
			continue
		}
		t.Errorf("unexpected %s", k)
	}
	for _, k := range []string{
		"USER", "LOGNAME", "SHELL", "TZ", "TMPDIR", "HTTP_PROXY", "HTTPS_PROXY",
		"LC_ALL", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "AUTH_TOKEN",
		"LGB_FAKE_SECRET", "LGB_ADMIN_TOKEN_PATH", "LGB_CANARY_VAR", "DAEMON_CANARY",
		"GROK_CONFIG", "GROK_SANDBOX", "ANTHROPIC_API_KEY",
	} {
		if _, ok := env[k]; ok {
			t.Errorf("%s reached the cli", k)
		}
	}
	flat := strings.Join(iso.Env, "\n")
	for _, v := range []string{token, secret, adminPath, canary, "/home/daemon"} {
		if strings.Contains(flat, v) {
			t.Fatal("daemon value reached the cli")
		}
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
