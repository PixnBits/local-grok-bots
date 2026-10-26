package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestGeneratedSettingsDenyDaemonSecrets(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeCLIPolicy(t, dir)
	app := newCLIApp(t, dir, policyPath)
	secrets := app.daemonSecrets()
	admin := filepath.Join(dir, adminTokenFile)
	cliDir := filepath.Join(dir, "cli")
	proxyDir := filepath.Join(dir, "cli-proxy")
	egressDir := filepath.Join(dir, "cli-egress")
	for _, want := range []string{admin, policyPath, cliDir, proxyDir, egressDir} {
		if !strings.Contains("\n"+strings.Join(secrets, "\n")+"\n", "\n"+want+"\n") {
			t.Fatalf("secrets %v lack %s", secrets, want)
		}
	}
	if strings.Contains("\n"+strings.Join(secrets, "\n")+"\n", "\n"+filepath.Join(dir, "workspace")+"\n") {
		t.Fatalf("workspace is denied: %v", secrets)
	}
	for _, d := range []string{cliDir, proxyDir, egressDir} {
		st, err := os.Stat(d)
		if err != nil || !st.IsDir() || st.Mode().Perm()&0o077 != 0 {
			t.Fatalf("secret dir %s %v %v", d, st, err)
		}
	}
	home := t.TempDir()
	iso, err := clisession.PrepareIsolation(clisession.IsolationOptions{
		Backend: "claude", StateDir: filepath.Join(cliDir, "bot"),
		UserHome: home, ClaudeSandbox: true, Protect: secrets,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(iso.SettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	perms := doc["permissions"].(map[string]any)
	var deny []string
	for _, r := range perms["deny"].([]any) {
		deny = append(deny, r.(string))
	}
	files := doc["sandbox"].(map[string]any)["credentials"].(map[string]any)["files"].([]any)
	modes := map[string]string{}
	for _, f := range files {
		m := f.(map[string]any)
		modes[m["path"].(string)] = m["mode"].(string)
	}
	for _, p := range []string{admin, policyPath, cliDir, proxyDir, egressDir} {
		if !strings.Contains("\n"+strings.Join(deny, "\n")+"\n", "\nRead(/"+p+")\n") {
			t.Fatalf("deny lacks %s: %v", p, deny)
		}
		if modes[p] != "deny" {
			t.Fatalf("credentials %s mode %q", p, modes[p])
		}
	}
	if _, err := clisession.PrepareIsolation(clisession.IsolationOptions{
		Backend: "grok", StateDir: filepath.Join(cliDir, "gbot"),
		UserHome: home, Protect: secrets,
	}); err != nil {
		t.Fatal(err)
	}
	// GROK_HOME is StateDir/grok-home when Home is empty.
	toml, err := os.ReadFile(filepath.Join(cliDir, "gbot", "grok-home", "sandbox.toml"))
	if err != nil {
		t.Fatal(err)
	}
	// DATA_DIR/cli is denied around this bot's GROK_HOME: another bot's
	// state is denied, the path down to grok-home is not.
	for _, p := range []string{admin, policyPath, filepath.Join(cliDir, "bot"), proxyDir, egressDir} {
		if !strings.Contains(string(toml), strconv.Quote(p)) {
			t.Fatalf("grok deny lacks %s:\n%s", p, toml)
		}
	}
	for _, p := range []string{cliDir, filepath.Join(cliDir, "gbot"), filepath.Join(cliDir, "gbot", "grok-home")} {
		if strings.Contains(string(toml), strconv.Quote(p)) {
			t.Fatalf("grok deny covers its own home via %s:\n%s", p, toml)
		}
	}
}

func TestDaemonSecretsCoverCredentialHomes(t *testing.T) {
	dir := t.TempDir()
	homeA := filepath.Join(dir, "homes", "grok")
	homeB := filepath.Join(dir, "homes", "other")
	if err := os.MkdirAll(homeA, 0o700); err != nil || os.MkdirAll(homeB, 0o700) != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.toml")
	body := fmt.Sprintf(`
[backend]
backend = "claude"
[timers]
enabled = false
[[tools.cli]]
name = "grok"
path = "/usr/bin/grok"
credential_home = %q
timeout = "1s"
max_output = 1
max_calls_per_hour = 1
[[tools.cli]]
name = "other"
path = "/usr/bin/other"
credential_home = %q
timeout = "1s"
max_output = 1
max_calls_per_hour = 1
`, homeA, homeB)
	if err := os.WriteFile(policyPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	app := newCLIApp(t, dir, policyPath)
	secrets := app.daemonSecrets()
	coiDir := filepath.Join(dir, "coi")
	for _, want := range []string{homeA, homeB, coiDir} {
		if !strings.Contains("\n"+strings.Join(secrets, "\n")+"\n", "\n"+want+"\n") {
			t.Fatalf("secrets %v lack %s", secrets, want)
		}
	}
	if st, err := os.Stat(coiDir); err != nil || !st.IsDir() || st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("coi dir %v %v", st, err)
	}
	userHome := t.TempDir()
	cliDir := filepath.Join(dir, "cli")
	iso, err := clisession.PrepareIsolation(clisession.IsolationOptions{
		Backend: "claude", StateDir: filepath.Join(cliDir, "bot"),
		UserHome: userHome, ClaudeSandbox: true, Protect: secrets,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(iso.SettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	perms := doc["permissions"].(map[string]any)
	var deny []string
	for _, r := range perms["deny"].([]any) {
		deny = append(deny, r.(string))
	}
	files := doc["sandbox"].(map[string]any)["credentials"].(map[string]any)["files"].([]any)
	modes := map[string]string{}
	for _, f := range files {
		m := f.(map[string]any)
		modes[m["path"].(string)] = m["mode"].(string)
	}
	for _, p := range []string{homeA, homeB, coiDir} {
		if !strings.Contains("\n"+strings.Join(deny, "\n")+"\n", "\nRead(/"+p+")\n") {
			t.Fatalf("claude deny lacks %s: %v", p, deny)
		}
		if modes[p] != "deny" {
			t.Fatalf("credentials %s mode %q", p, modes[p])
		}
	}
	if _, err := clisession.PrepareIsolation(clisession.IsolationOptions{
		Backend: "grok", StateDir: filepath.Join(cliDir, "gbot"),
		UserHome: userHome, Protect: secrets,
	}); err != nil {
		t.Fatal(err)
	}
	toml, err := os.ReadFile(filepath.Join(cliDir, "gbot", "grok-home", "sandbox.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{homeA, homeB, coiDir} {
		if !strings.Contains(string(toml), strconv.Quote(p)) {
			t.Fatalf("grok deny lacks %s:\n%s", p, toml)
		}
	}
}

func TestTurnDeniesCredentialHomeAddedAfterStartup(t *testing.T) {
	old := claudeSandboxMissing
	claudeSandboxMissing = func() []string { return nil }
	t.Cleanup(func() { claudeSandboxMissing = old })
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	homeA := filepath.Join(dir, "homes", "grok")
	homeB := filepath.Join(dir, "homes", "later")
	if err := os.MkdirAll(homeA, 0o700); err != nil || os.MkdirAll(homeB, 0o700) != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.toml")
	write := func(homes ...string) {
		t.Helper()
		var b strings.Builder
		b.WriteString("[backend]\nbackend = \"claude\"\n[timers]\nenabled = false\n")
		for i, home := range homes {
			fmt.Fprintf(&b, "[[tools.cli]]\nname = %q\npath = \"/usr/bin/tool%d\"\ncredential_home = %q\ntimeout = \"1s\"\nmax_output = 1\nmax_calls_per_hour = 1\n",
				[]string{"grok", "later"}[i], i, home)
		}
		if err := os.WriteFile(policyPath, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(homeA)
	app := newCLIApp(t, dir, policyPath)
	before := app.daemonSecrets()
	if !strings.Contains("\n"+strings.Join(before, "\n")+"\n", "\n"+homeA+"\n") || strings.Contains("\n"+strings.Join(before, "\n")+"\n", "\n"+homeB+"\n") {
		t.Fatalf("startup secrets = %v", before)
	}
	write(homeA, homeB)
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	bot := store.Bot{ID: "b1"}
	iso, err := app.cliIsolation(bot, "claude", ws, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(iso.SettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "Read(/"+homeB+")") {
		t.Fatalf("claude settings omit the new home: %s", raw)
	}
	if !coiListed(iso.Protect, homeB) {
		t.Fatalf("turn protect %v lacks %s", iso.Protect, homeB)
	}
	giso, err := app.cliIsolation(bot, "grok", ws, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	toml, err := os.ReadFile(filepath.Join(dir, "cli", "b1", "home", ".grok", "sandbox.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(toml), strconv.Quote(homeB)) {
		t.Fatalf("grok deny omits the new home:\n%s", toml)
	}
	if !coiListed(giso.Protect, homeB) {
		t.Fatalf("grok turn protect %v lacks %s", giso.Protect, homeB)
	}
	run, _, err := app.startLGB(context.Background(), bot, "run1", ws)
	if err != nil || run == nil {
		t.Fatal(err)
	}
	t.Cleanup(run.stop)
	if !run.protectSet || !coiListed(run.protect, homeB) {
		t.Fatalf("run deny list %v set=%v", run.protect, run.protectSet)
	}
}

func TestAuthTokensFileSymlinkIsDenied(t *testing.T) {
	old := claudeSandboxMissing
	claudeSandboxMissing = func() []string { return nil }
	t.Cleanup(func() { claudeSandboxMissing = old })
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	outside := t.TempDir()
	target := filepath.Join(outside, "tokens")
	if err := os.WriteFile(target, []byte("alice:"+strings.Repeat("a", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(outside, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	app.cfg.AuthTokensFile = link
	linkAbs, err := filepath.Abs(link)
	if err != nil {
		t.Fatal(err)
	}
	linkAbs = filepath.Clean(linkAbs)
	resolved, err := filepath.EvalSymlinks(linkAbs)
	if err != nil {
		t.Fatal(err)
	}
	resolved = filepath.Clean(resolved)
	if linkAbs == resolved {
		t.Fatalf("symlink %s resolved to itself", linkAbs)
	}
	st, err := os.Stat(target)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("target mode %v %v", st, err)
	}
	secrets := app.daemonSecrets()
	for _, p := range []string{linkAbs, resolved} {
		if !coiListed(secrets, p) {
			t.Fatalf("secrets %v lack %s", secrets, p)
		}
	}
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	bot := store.Bot{ID: "b1"}
	iso, err := app.cliIsolation(bot, "claude", ws, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(iso.SettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{linkAbs, resolved} {
		for _, rule := range []string{"Read(/" + p + ")", "Edit(/" + p + ")"} {
			if !strings.Contains(string(raw), rule) {
				t.Fatalf("claude settings lack %s:\n%s", rule, raw)
			}
		}
	}
	noted, ok := app.botProtect(bot.ID)
	if !ok || !coiListed(noted, linkAbs) || !coiListed(noted, resolved) {
		t.Fatalf("botProtect %v ok=%v", noted, ok)
	}
	run, _, err := app.startLGB(context.Background(), bot, "run1", ws)
	if err != nil || run == nil || !run.protectSet {
		t.Fatalf("lgb %v set=%v err=%v", run, run != nil && run.protectSet, err)
	}
	t.Cleanup(run.stop)
	roots := run.argRoots(app.policy)
	if !coiListed(roots, linkAbs) || !coiListed(roots, resolved) {
		t.Fatalf("argRoots %v lack %s and %s", roots, linkAbs, resolved)
	}
}

func coiListed(paths []string, home string) bool {
	for _, p := range paths {
		if p == home {
			return true
		}
	}
	return false
}

func TestClaudeSandboxUnavailableFailsClosed(t *testing.T) {
	old := claudeSandboxMissing
	claudeSandboxMissing = func() []string { return []string{"socat"} }
	t.Cleanup(func() { claudeSandboxMissing = old })
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	ws := filepath.Join(dir, "ws")
	_ = os.MkdirAll(ws, 0o755)
	_, err := app.cliIsolation(store.Bot{ID: "b1"}, "claude", ws, "run-1")
	if err == nil || !strings.Contains(err.Error(), "missing socat") || !strings.Contains(err.Error(), "claude_sandbox") {
		t.Fatalf("want fail-closed sandbox error, got %v", err)
	}
	srv := serve(t, app)
	_, b := do(t, "GET", srv.URL+"/api/log?kind=cli_sandbox_unavailable&limit=10", nil, app.cfg.AuthToken)
	var events []store.LogEvent
	decodeJSON(t, b, &events)
	if len(events) != 1 {
		t.Fatalf("log events %s", b)
	}
	// Grok is unaffected.
	if _, err := app.cliIsolation(store.Bot{ID: "b1"}, "grok", ws, "run-1"); err != nil {
		t.Fatal(err)
	}
}

func TestClaudeSandboxManagedOffSkipsCheckAndBlock(t *testing.T) {
	old := claudeSandboxMissing
	claudeSandboxMissing = func() []string { return []string{"bwrap", "socat"} }
	t.Cleanup(func() { claudeSandboxMissing = old })
	dir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	managed := filepath.Join(dir, "managed.json")
	_ = os.WriteFile(managed, []byte(`{"cli":{"isolation":{"claude_sandbox":"off"}}}`), 0o644)
	t.Setenv("MANAGED_POLICY", managed)
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	ws := filepath.Join(dir, "ws")
	_ = os.MkdirAll(ws, 0o755)
	iso, err := app.cliIsolation(store.Bot{ID: "b1", Grants: []string{"net"}, NetAllow: []string{"pypi.org"}}, "claude", ws, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(iso.SettingsPath)
	var doc map[string]any
	_ = json.Unmarshal(b, &doc)
	if _, ok := doc["sandbox"]; ok || iso.ClaudeSandbox {
		t.Fatalf("sandbox block with managed off: %s", b)
	}
	if strings.Contains(string(b), `"WebFetch"`) {
		t.Fatalf("net grant still denies WebFetch: %s", b)
	}
	if !strings.Contains(string(b), filepath.Join(dir, adminTokenFile)) {
		t.Fatalf("admin token not denied to Claude tools: %s", b)
	}
}

func TestUserSandboxSurvivesManagedOff(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	_ = os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	body := `{
		"hooks": {"PreToolUse": []},
		"permissions": {"allow": ["Bash(danger)"], "deny": ["Bash(curl *)"]},
		"sandbox": {
			"enabled": true,
			"credentials": {"files": [{"path": "/only-user", "mode": "deny"}]}
		}
	}`
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(dir, "managed.json")
	_ = os.WriteFile(managed, []byte(`{"cli":{"isolation":{"claude_sandbox":"off"}}}`), 0o644)
	t.Setenv("MANAGED_POLICY", managed)
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	ws := filepath.Join(dir, "ws")
	_ = os.MkdirAll(ws, 0o755)
	iso, err := app.cliIsolation(store.Bot{ID: "b1"}, "claude", ws, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if iso.ClaudeSandbox {
		t.Fatal("managed off still marked the daemon sandbox on")
	}
	b, err := os.ReadFile(iso.SettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(b)
	for _, want := range []string{`"enabled": true`, "Bash(curl *)", "/only-user", "Skill"} {
		if !strings.Contains(raw, want) {
			t.Fatalf("missing %s in %s", want, raw)
		}
	}
	for _, banned := range []string{"Bash(danger)", "PreToolUse", `"enabled": false`} {
		if strings.Contains(raw, banned) {
			t.Fatalf("copied or loosened %s in %s", banned, raw)
		}
	}
}

func TestUnparseableUserSettingsRefusesAndAudits(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	_ = os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	logPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	ws := filepath.Join(dir, "ws")
	_ = os.MkdirAll(ws, 0o755)
	_, err = app.cliIsolation(store.Bot{ID: "b1"}, "claude", ws, "run-1")
	if err == nil || !strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "claude_sandbox") {
		t.Fatalf("err %v", err)
	}
	evs, lerr := app.st.ListLog("b1", "cli_sandbox_unavailable", "", 10)
	if lerr != nil || len(evs) != 1 || !strings.Contains(string(evs[0].Detail), `"backend":"claude"`) {
		t.Fatalf("log %v %v", evs, lerr)
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(raw), `"event":"cli_sandbox_unavailable"`) || !strings.Contains(string(raw), `"backend":"claude"`) {
		t.Fatalf("audit %s %v", raw, err)
	}
}

func TestGrokUserHomeUsesFailClosedProfile(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	_ = os.MkdirAll(filepath.Join(home, ".grok"), 0o700)
	_ = os.WriteFile(filepath.Join(home, ".grok", "auth.json"), []byte("{}"), 0o600)
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	app.rtMu.Lock()
	app.policy.CLIHome = policy.HomeUser
	app.rtMu.Unlock()
	ws := filepath.Join(dir, "ws")
	_ = os.MkdirAll(ws, 0o755)
	iso, err := app.cliIsolation(store.Bot{ID: "b1"}, "grok", ws, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if iso.GrokSandbox != clisession.GrokProfile {
		t.Fatalf("profile %q", iso.GrokSandbox)
	}
	grokHome := filepath.Join(filepath.Dir(app.ws), "cli", "b1", "grok-home")
	env := strings.Join(iso.Env, "\n")
	if !strings.Contains(env, "HOME="+home+"\n") || !strings.Contains(env, "GROK_HOME="+grokHome+"\n") {
		t.Fatalf("env:\n%s", env)
	}
	if _, err := os.Stat(filepath.Join(home, ".grok", "sandbox.toml")); err == nil {
		t.Fatal("wrote the user's sandbox.toml")
	}
	b, err := os.ReadFile(filepath.Join(grokHome, "sandbox.toml"))
	if err != nil || !strings.Contains(string(b), "[profiles.lgb]") {
		t.Fatalf("profile file: %s %v", b, err)
	}
	argv, err := clisession.Args(clisession.Spec{Backend: "grok", Prompt: "hi", Workspace: ws, Isolate: iso})
	if err != nil || !strings.Contains(strings.Join(argv, " "), "--sandbox lgb") {
		t.Fatalf("argv %v %v", argv, err)
	}
}

type sandboxFailRunner struct{}

func (sandboxFailRunner) Run(context.Context, clisession.Spec, func(clisession.Event)) (clisession.Result, error) {
	return clisession.Result{}, fmt.Errorf("sandbox profile lgb could not be applied")
}

type bridgeFailRunner struct{}

func (bridgeFailRunner) Run(context.Context, clisession.Spec, func(clisession.Event)) (clisession.Result, error) {
	return clisession.Result{}, &clisession.BridgeError{}
}

type okRunner struct{}

func (okRunner) Run(context.Context, clisession.Spec, func(clisession.Event)) (clisession.Result, error) {
	return clisession.Result{Text: "ok", SessionID: "sess-ok"}, nil
}

func TestGrokDarwinNetworkIsWarned(t *testing.T) {
	old := cliGOOS
	cliGOOS = "darwin"
	t.Cleanup(func() { cliGOOS = old })
	dir := t.TempDir()
	app := newApp(t, dir, nil)
	logPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	app.runner = okRunner{}
	app.rtMu.Lock()
	app.policy = policy.Policy{Backend: "grok", CLIPermitted: true, TimersEnabled: true, Idle: time.Hour, Imminent: time.Minute}
	app.rtMu.Unlock()
	srv := serve(t, app)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldErr := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = oldErr })

	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Geo", "description": "g"}, "")
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	postGrok(t, srv.URL, bot.ID)
	waitIdle(t, srv.URL, bot.ID, "")
	postGrok(t, srv.URL, bot.ID)
	waitIdle(t, srv.URL, bot.ID, "")
	_ = w.Close()
	os.Stderr = oldErr
	stderr, _ := io.ReadAll(r)
	if strings.Count(string(stderr), "cli_network_unrestricted") != 2 {
		t.Fatalf("stderr warnings:\n%s", stderr)
	}
	evs, err := app.st.ListLog(bot.ID, "cli_network_unrestricted", "", 10)
	if err != nil || len(evs) != 2 {
		t.Fatalf("log %v %v", evs, err)
	}
	for _, ev := range evs {
		d := string(ev.Detail)
		for _, want := range []string{`"backend":"grok"`, `"os":"darwin"`, `"run_id":`, `"reason":"restrict_network is not enforced on macOS"`} {
			if !strings.Contains(d, want) {
				t.Fatalf("detail lacks %s: %s", want, d)
			}
		}
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil || strings.Count(string(raw), `"event":"cli_network_unrestricted"`) != 2 || !strings.Contains(string(raw), `"os":"darwin"`) {
		t.Fatalf("audit %s %v", raw, err)
	}
}

func TestGrokNetworkWarnSkipsLinuxAndNetGrant(t *testing.T) {
	dir := t.TempDir()
	app := newApp(t, dir, nil)
	app.runner = okRunner{}
	app.rtMu.Lock()
	app.policy = policy.Policy{Backend: "grok", CLIPermitted: true, TimersEnabled: true, Idle: time.Hour, Imminent: time.Minute}
	app.rtMu.Unlock()
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Geo", "description": "g"}, "")
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	postGrok(t, srv.URL, bot.ID)
	waitIdle(t, srv.URL, bot.ID, "")
	if n := networkWarnings(t, app, bot.ID); n != 0 {
		t.Fatalf("linux warned %d times", n)
	}
	old := cliGOOS
	cliGOOS = "darwin"
	t.Cleanup(func() { cliGOOS = old })
	if _, err := app.st.UpdateBot(bot.ID, store.BotPatch{GrantsSet: true, Grants: []string{"net"}}); err != nil {
		t.Fatal(err)
	}
	postGrok(t, srv.URL, bot.ID)
	waitIdle(t, srv.URL, bot.ID, "")
	if n := networkWarnings(t, app, bot.ID); n != 0 {
		t.Fatalf("net grant warned %d times", n)
	}
}

func postGrok(t *testing.T, base, botID string) {
	t.Helper()
	res, b := do(t, "POST", base+"/api/bots/"+botID+"/thread/messages", map[string]any{"content": "go"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
}

func networkWarnings(t *testing.T, app *App, botID string) int {
	t.Helper()
	evs, err := app.st.ListLog(botID, "cli_network_unrestricted", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	return len(evs)
}

func TestGrokSandboxFailureIsAudited(t *testing.T) {
	dir := t.TempDir()
	app := newApp(t, dir, nil)
	logPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	app.runner = sandboxFailRunner{}
	app.rtMu.Lock()
	app.policy = policy.Policy{Backend: "grok", CLIPermitted: true, TimersEnabled: true, Idle: time.Hour, Imminent: time.Minute}
	app.rtMu.Unlock()
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Geo", "description": "g"}, "")
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{"content": "go"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, "")
	got, err := app.st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastRunStatus != "error" || !strings.Contains(got.LastRunError, "Grok's sandbox is required") {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	evs, err := app.st.ListLog(bot.ID, "cli_sandbox_unavailable", "", 10)
	if err != nil || len(evs) != 1 || !strings.Contains(string(evs[0].Detail), `"backend":"grok"`) {
		t.Fatalf("log %v %v", evs, err)
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(raw), `"event":"cli_sandbox_unavailable"`) || !strings.Contains(string(raw), `"backend":"grok"`) {
		t.Fatalf("audit %s %v", raw, err)
	}
}

func TestGrokBridgeRefusalIsAudited(t *testing.T) {
	dir := t.TempDir()
	app := newApp(t, dir, nil)
	logPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	app.runner = bridgeFailRunner{}
	app.rtMu.Lock()
	app.policy = policy.Policy{Backend: "grok", CLIPermitted: true, TimersEnabled: true, Idle: time.Hour, Imminent: time.Minute}
	app.rtMu.Unlock()
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Geo", "description": "g"}, "")
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{"content": "go"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, "")
	evs, err := app.st.ListLog(bot.ID, "cli_bridge_unavailable", "", 10)
	if err != nil || len(evs) != 1 || !strings.Contains(string(evs[0].Detail), `"backend":"grok"`) {
		t.Fatalf("log %v %v", evs, err)
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(raw), `"event":"cli_bridge_unavailable"`) || !strings.Contains(string(raw), `"backend":"grok"`) {
		t.Fatalf("audit %s %v", raw, err)
	}
}

func TestCLIPreambleStatesTheRealBoundary(t *testing.T) {
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	got := app.cliBoundary()
	for _, want := range []string{"Claude Code's sandbox", "not inside the daemon's jail", "run_shell"} {
		if !strings.Contains(got, want) {
			t.Fatalf("claude boundary lacks %q: %s", want, got)
		}
	}
	if strings.Contains(got, "your own sandbox is the boundary") {
		t.Fatalf("old wording: %s", got)
	}
	app.policy.Backend = "grok"
	if g := app.cliBoundary(); !strings.Contains(g, "Grok's sandbox") {
		t.Fatalf("grok boundary: %s", g)
	}
}
