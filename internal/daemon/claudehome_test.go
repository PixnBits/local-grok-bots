package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func withGOOS(t *testing.T, goos string) {
	t.Helper()
	old := cliGOOS
	cliGOOS = goos
	t.Cleanup(func() { cliGOOS = old })
}

func loginLog(t *testing.T, app *App, botID string) map[string]any {
	t.Helper()
	evs, err := app.st.ListLog(botID, "cli_login", "", 10)
	if err != nil || len(evs) != 1 {
		t.Fatalf("cli_login events %d %v", len(evs), err)
	}
	var m map[string]any
	if err := json.Unmarshal(evs[0].Detail, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestClaudeHomeDarwinKeepsUserHome(t *testing.T) {
	withGOOS(t, "darwin")
	userHome := t.TempDir()
	t.Setenv("HOME", userHome)
	app, dir, bot, envLog := isolationApp(t, "claude", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	os.Unsetenv("ANTHROPIC_API_KEY")
	got := postAndWait(t, app, bot.ID)
	if got.LastRunStatus != "done" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	env := readArgv(t, envLog)
	if !strings.Contains(env, "HOME="+userHome+"\n") {
		t.Fatalf("HOME not the user's:\n%s", env)
	}
	for _, bad := range []string{"CLAUDE_CONFIG_DIR", "ANTHROPIC_BASE_URL", "/elsewhere"} {
		if strings.Contains(env, bad) {
			t.Fatalf("%s present on darwin:\n%s", bad, env)
		}
	}
	argv := readArgv(t, filepath.Join(dir, "argv.log"))
	for _, f := range []string{"--setting-sources=\n", "--strict-mcp-config\n", "--settings\n"} {
		if !strings.Contains(argv, f) {
			t.Fatalf("missing %q:\n%s", f, argv)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(app.ws), "cli", bot.ID, "home")); !os.IsNotExist(err) {
		t.Fatal("per-bot home created on darwin auto")
	}
	m := loginLog(t, app, bot.ID)
	if m["source"] != "keychain_or_user_home" || m["os"] != "darwin" || m["own_home"] != false ||
		m["auth_method"] != "claude.ai" || m["config_directory"] != filepath.Join(userHome, ".claude") {
		t.Fatalf("login log %v", m)
	}
	// Once per bot per daemon run.
	postAndWait(t, app, bot.ID)
	loginLog(t, app, bot.ID)
}

func TestClaudeHomeLinuxIsolatesWithCredentialLink(t *testing.T) {
	withGOOS(t, "linux")
	userHome := t.TempDir()
	t.Setenv("HOME", userHome)
	_ = os.MkdirAll(filepath.Join(userHome, ".claude"), 0o700)
	_ = os.WriteFile(filepath.Join(userHome, ".claude", ".credentials.json"), []byte(`{"secret":"x"}`), 0o600)
	app, _, bot, envLog := isolationApp(t, "claude", "")
	os.Unsetenv("ANTHROPIC_API_KEY")
	postAndWait(t, app, bot.ID)
	env := readArgv(t, envLog)
	home := filepath.Join(filepath.Dir(app.ws), "cli", bot.ID, "home")
	if !strings.Contains(env, "HOME="+home+"\n") || !strings.Contains(env, "CLAUDE_CONFIG_DIR="+filepath.Join(home, ".claude")+"\n") {
		t.Fatalf("linux env:\n%s", env)
	}
	m := loginLog(t, app, bot.ID)
	if m["source"] != "credentials_symlink" || m["own_home"] != true || m["config_directory"] != filepath.Join(home, ".claude") {
		t.Fatalf("login log %v", m)
	}
}

func TestClaudeHomeExplicitSettingsAndEnvToken(t *testing.T) {
	withGOOS(t, "darwin")
	t.Setenv("HOME", t.TempDir())
	app, _, bot, envLog := isolationApp(t, "claude", "")
	os.Unsetenv("ANTHROPIC_API_KEY")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "oat-SECRET-123")
	app.rtMu.Lock()
	app.editPol(func(p *policy.Policy) { p.CLIClaudeHome = policy.HomeIsolated })
	app.rtMu.Unlock()
	postAndWait(t, app, bot.ID)
	if env := readArgv(t, envLog); !strings.Contains(env, "CLAUDE_CONFIG_DIR=") {
		t.Fatalf("claude_home=isolated on darwin should isolate:\n%s", env)
	}
	m := loginLog(t, app, bot.ID)
	if m["source"] != "env_oauth_token" {
		t.Fatalf("login log %v", m)
	}
	evs, _ := app.st.ListLog(bot.ID, "", "", 200)
	for _, e := range evs {
		if strings.Contains(string(e.Detail), "SECRET") || strings.Contains(string(e.Detail), "sk-test") {
			t.Fatalf("secret in log: %s %s", e.Kind, e.Detail)
		}
	}
}

func TestGrokHomeUnchangedOnDarwin(t *testing.T) {
	withGOOS(t, "darwin")
	app, _, bot, _ := isolationApp(t, "grok", "")
	envLog := filepath.Join(app.ws, "bots", bot.ID, "env.log")
	if err := os.MkdirAll(filepath.Dir(envLog), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LGB_ENV_LOG", envLog)
	postAndWait(t, app, bot.ID)
	env := readArgv(t, envLog)
	home := filepath.Join(filepath.Dir(app.ws), "cli", bot.ID, "home")
	if !strings.Contains(env, "GROK_HOME="+filepath.Join(home, ".grok")+"\n") {
		t.Fatalf("grok env:\n%s", env)
	}
	if evs, _ := app.st.ListLog(bot.ID, "cli_login", "", 10); len(evs) != 0 {
		t.Fatal("login check ran for grok")
	}
}
