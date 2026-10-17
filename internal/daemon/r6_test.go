package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestHostConfigRefusesUntilTrusted(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	app := newApp(t, dir, nil)
	path := filepath.Join(dir, "host.toml")
	if err := os.WriteFile(path, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := clisession.HostConfigPaths
	clisession.HostConfigPaths = []string{path}
	t.Cleanup(func() { clisession.HostConfigPaths = old })
	app.rtMu.Lock()
	app.policy.Backend = "grok"
	app.policy.CLIPermitted = true
	app.rtMu.Unlock()
	auditPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err = app.cliIsolation(store.Bot{ID: "b1"}, "grok", ws, "run-1")
	var ue *clisession.UntrustedConfigError
	if !errors.As(err, &ue) || len(ue.Names) != 1 || ue.Names[0] != path {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), "host.toml") {
		t.Fatalf("error names the file: %v", err)
	}
	app.rtMu.Lock()
	app.policy.CLITrustSystemConfig = true
	app.policy.CLIClaudeSandbox = policy.SandboxOff
	app.rtMu.Unlock()
	if _, err := app.cliIsolation(store.Bot{ID: "b1"}, "claude", ws, "run-2"); err != nil {
		t.Fatal(err)
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "cli_untrusted_config") || !strings.Contains(string(raw), path) || !strings.Contains(string(raw), `"source":"host"`) {
		t.Fatalf("audit %s", raw)
	}
}

func TestPlantedGrokHomeRefusesTurn(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	app := newApp(t, dir, nil)
	app.rtMu.Lock()
	app.policy.Backend = "grok"
	app.policy.CLIPermitted = true
	app.rtMu.Unlock()
	auditPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	iso, err := app.cliIsolation(store.Bot{ID: "b1"}, "grok", ws, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	var gh string
	for _, e := range iso.Env {
		if strings.HasPrefix(e, "GROK_HOME=") {
			gh = strings.TrimPrefix(e, "GROK_HOME=")
		}
	}
	planted := []byte("planted\n")
	req := filepath.Join(gh, "requirements.toml")
	if err := os.WriteFile(req, planted, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = app.cliIsolation(store.Bot{ID: "b1"}, "grok", ws, "run-2")
	var ue *clisession.UntrustedConfigError
	if !errors.As(err, &ue) || len(ue.Names) != 1 || ue.Names[0] != "requirements.toml" {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), "planted") {
		t.Fatal(err)
	}
	got, err := os.ReadFile(req)
	if err != nil || string(got) != string(planted) {
		t.Fatalf("overwrote %q %v", got, err)
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "cli_untrusted_config") || !strings.Contains(text, "requirements.toml") || !strings.Contains(text, `"action":"refuse"`) {
		t.Fatalf("audit %s", text)
	}
}

func TestACPModeRefusesBeforePrompt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cases := []struct {
		mode, needle string
	}{
		{mode: "bad-mode", needle: "permission mode"},
		{mode: "mode-update", needle: "permission mode"},
		{mode: "config-update", needle: "permission mode"},
		{mode: "notice", needle: "permission mode"},
		{mode: "changed", needle: "permission mode"},
		{mode: "changed-alias", needle: "permission mode"},
		{mode: "other-session", needle: "does not match"},
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			f := prepareACP(t, c.mode, policy.Policy{UIPrompts: false})
			f.start(false)
			assertHostClosed(t, f, c.needle)
		})
	}
	t.Run("broad-name", func(t *testing.T) {
		f := prepareACP(t, "broad-name", policy.Policy{
			UIPrompts: false, PermissionMode: "always-allow", ManagedBypass: true,
		})
		f.start(false)
		assertHostClosed(t, f, "allow_once")
	})
}

func TestACPSlashPromptRefused(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := prepareACP(t, "ok", policy.Policy{UIPrompts: false})
	f.startContent("  /status", false)
	got := f.waitDone()
	if got.LastRunStatus != "error" || !strings.Contains(got.LastRunError, "slash commands") || strings.Contains(got.LastRunError, "status") {
		t.Fatalf("%s %s", got.LastRunStatus, got.LastRunError)
	}
	raw := f.auditText()
	if !strings.Contains(raw, `"source":"host"`) || !strings.Contains(raw, "slash commands") || strings.Contains(raw, "/status") {
		t.Fatalf("audit %s", raw)
	}
}

func TestACPPlainPromptWithSlashInsideRuns(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := prepareACP(t, "ok", policy.Policy{UIPrompts: false})
	f.startContent("please /status", false)
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("%s %s", got.LastRunStatus, got.LastRunError)
	}
}

func TestACPToolAllowlist(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := prepareACP(t, "ok", policy.Policy{UIPrompts: false})
	f.start(false)
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("%s %s", got.LastRunStatus, got.LastRunError)
	}
	assertToolList(t, f.argvText(), "run_terminal_command,read_file,search_replace,grep,write")
}

func TestACPNetGrantAddsWebToolsOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := prepareACP(t, "ok", policy.Policy{UIPrompts: false})
	res, b := do(t, "PATCH", f.url+"/api/bots/"+f.bot.ID, map[string]any{"grants": []string{"net"}}, "")
	if res.StatusCode != 200 {
		t.Fatalf("patch %d %s", res.StatusCode, b)
	}
	f.start(false)
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("%s %s", got.LastRunStatus, got.LastRunError)
	}
	assertToolList(t, f.argvText(), "run_terminal_command,read_file,search_replace,grep,write,web_fetch,web_search")
}

func TestACPUnknownToolNote(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := prepareACP(t, "quiet-unknown", policy.Policy{UIPrompts: false})
	f.start(false)
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("%s %s", got.LastRunStatus, got.LastRunError)
	}
	raw := f.auditText()
	if !strings.Contains(raw, `"tool":"unknown"`) || !strings.Contains(raw, `"classification":"unknown"`) || !strings.Contains(raw, `"source":"host"`) {
		t.Fatalf("audit %s", raw)
	}
	if strings.Contains(raw, "custom_widget") {
		t.Fatalf("raw name kept %s", raw)
	}
	recs := f.permRecs()
	if len(recs) != 1 || recs[0].Name != "unknown" {
		t.Fatalf("records %+v", recs)
	}
}

func TestACPCLIDenyIsAudited(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := prepareACP(t, "cli-deny", policy.Policy{UIPrompts: false})
	f.start(false)
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("%s %s", got.LastRunStatus, got.LastRunError)
	}
	raw := f.auditText()
	if !strings.Contains(raw, `"source":"cli_deny"`) || !strings.Contains(raw, `"tool":"Bash"`) || !strings.Contains(raw, `"decision":"deny"`) {
		t.Fatalf("audit %s", raw)
	}
	recs := f.permRecs()
	if len(recs) != 1 || recs[0].Name != "Bash" || !strings.Contains(recs[0].Result, `"source":"cli_deny"`) {
		t.Fatalf("records %+v", recs)
	}
}

func assertToolList(t *testing.T, argv, want string) {
	t.Helper()
	lines := strings.Split(argv, "\n")
	toolsAt, agentAt := -1, -1
	for i, line := range lines {
		if line == "--tools" && i+1 < len(lines) {
			toolsAt = i
			if lines[i+1] != want {
				t.Fatalf("tools %q\n%s", lines[i+1], argv)
			}
		}
		if line == "agent" && agentAt < 0 {
			agentAt = i
		}
	}
	if toolsAt < 0 || agentAt < 0 || toolsAt > agentAt {
		t.Fatalf("argv\n%s", argv)
	}
	for _, bad := range []string{"list_dir", "todo_write", "x_keyword_search", "x_semantic_search", "--disallowed-tools"} {
		if strings.Contains(argv, bad) {
			t.Fatalf("argv has %s\n%s", bad, argv)
		}
	}
}
