package clisession

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func claudeDoc(t *testing.T, o IsolationOptions) map[string]any {
	t.Helper()
	o.Backend = "claude"
	o.StateDir = t.TempDir()
	iso, err := PrepareIsolation(o)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(iso.SettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if iso.ClaudeSandbox != o.ClaudeSandbox {
		t.Fatalf("iso sandbox %v", iso.ClaudeSandbox)
	}
	return doc
}

func denyList(doc map[string]any) string {
	perms, _ := doc["permissions"].(map[string]any)
	var out []string
	for _, r := range perms["deny"].([]any) {
		out = append(out, r.(string))
	}
	return "\n" + strings.Join(out, "\n") + "\n"
}

func TestClaudeSettingsDefault(t *testing.T) {
	home := "/home/u"
	doc := claudeDoc(t, IsolationOptions{UserHome: home, ClaudeSandbox: true, Protect: []string{"/data/admin-token"}})
	deny := denyList(doc)
	for _, want := range []string{"Skill", "SlashCommand", "WebFetch", "WebSearch", "Bash(git push *)", "Bash(ssh *)", "Bash(scp *)",
		"Read(//home/u/.ssh/**)", "Edit(//home/u/.aws/**)", "Read(//data/admin-token)"} {
		if !strings.Contains(deny, "\n"+want+"\n") {
			t.Fatalf("deny lacks %s:%s", want, deny)
		}
	}
	perms := doc["permissions"].(map[string]any)
	if perms["blockReadsOutsideWorkingDirectories"] != true {
		t.Fatalf("reads outside workspace not blocked")
	}
	sb := doc["sandbox"].(map[string]any)
	if sb["enabled"] != true || sb["failIfUnavailable"] != true || sb["allowUnsandboxedCommands"] != false || sb["autoAllowBashIfSandboxed"] != false {
		t.Fatalf("sandbox %v", sb)
	}
	net := sb["network"].(map[string]any)
	if net["strictAllowlist"] != true || len(net["allowedDomains"].([]any)) != 0 {
		t.Fatalf("network %v", net)
	}
	files := sb["credentials"].(map[string]any)["files"].([]any)
	if !strings.Contains(mustJSON(files), `"/home/u/.ssh"`) || !strings.Contains(mustJSON(files), `"mode":"deny"`) {
		t.Fatalf("credentials %v", files)
	}
}

func TestClaudeSettingsNetGrant(t *testing.T) {
	doc := claudeDoc(t, IsolationOptions{UserHome: "/home/u", ClaudeSandbox: true,
		Grants: Grants{Net: true, NetAllow: []string{"pypi.org", "github.com"}, Git: true, SSH: true}})
	deny := denyList(doc)
	for _, gone := range []string{"\nWebFetch\n", "\nWebSearch\n", "git push", "Bash(ssh", "/home/u/.ssh"} {
		if strings.Contains(deny, gone) {
			t.Fatalf("granted rule still denied %q:%s", gone, deny)
		}
	}
	net := doc["sandbox"].(map[string]any)["network"].(map[string]any)
	if mustJSON(net["allowedDomains"]) != `["github.com","pypi.org"]` || net["strictAllowlist"] != true {
		t.Fatalf("allowlist %v", net)
	}
}

// With claude_sandbox off and no user sandbox settings, the daemon writes no
// sandbox block, so it can't override a managed sandbox. It never writes
// enabled:false on its own.
func TestClaudeSettingsSandboxOffLeavesManagedSandbox(t *testing.T) {
	doc := claudeDoc(t, IsolationOptions{UserHome: "/home/u"})
	if _, ok := doc["sandbox"]; ok {
		t.Fatalf("sandbox block written while off: %v", doc["sandbox"])
	}
	if !strings.Contains(denyList(doc), "\nWebFetch\n") {
		t.Fatalf("deny rules dropped with sandbox off")
	}
	for _, sb := range []bool{true, false} {
		d := claudeDoc(t, IsolationOptions{UserHome: "/home/u", ClaudeSandbox: sb})
		if strings.Contains(mustJSON(d), `"enabled":false`) {
			t.Fatalf("settings disable the sandbox")
		}
	}
}

func writeUserSettings(t *testing.T, home, body string) {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestUserSandboxEnabledSurvivesSandboxOff(t *testing.T) {
	home := t.TempDir()
	writeUserSettings(t, home, `{
		"env": {"ANTHROPIC_API_KEY": "sk-user-secret"},
		"hooks": {"PreToolUse": [{"matcher": "Bash"}]},
		"permissions": {"allow": ["Bash(danger)"], "deny": ["Bash(curl *)"]},
		"sandbox": {
			"enabled": true,
			"failIfUnavailable": true,
			"allowUnsandboxedCommands": false,
			"excludedCommands": ["docker"],
			"network": {"allowedDomains": ["corp.example"], "strictAllowlist": false},
			"filesystem": {"allowWrite": ["/tmp/user-scratch"], "denyRead": ["/srv/hidden"]},
			"credentials": {"files": [{"path": "/only-user", "mode": "deny"}]}
		}
	}`)
	doc := claudeDoc(t, IsolationOptions{UserHome: home})
	sb := doc["sandbox"].(map[string]any)
	if sb["enabled"] != true || sb["failIfUnavailable"] != true || sb["allowUnsandboxedCommands"] != false {
		t.Fatalf("user sandbox not kept: %v", sb)
	}
	raw := mustJSON(doc)
	for _, want := range []string{"Bash(curl *)", "/srv/hidden", "/only-user", "WebFetch"} {
		if !strings.Contains(raw, want) {
			t.Fatalf("missing %s in %s", want, raw)
		}
	}
	for _, banned := range []string{"Bash(danger)", "PreToolUse", "sk-user-secret", `"enabled":false`, "corp.example", `"docker"`, "excludedCommands", "/tmp/user-scratch", `"strictAllowlist":false`} {
		if strings.Contains(raw, banned) {
			t.Fatalf("copied or loosened %s in %s", banned, raw)
		}
	}
	net := sb["network"].(map[string]any)
	if _, ok := net["strictAllowlist"]; ok || mustJSON(net["allowedDomains"]) != `[]` {
		t.Fatalf("network %v", net)
	}
}

func TestUserDenyAndCredentialsAreUnioned(t *testing.T) {
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	writeUserSettings(t, home, `{
		"permissions": {"deny": ["Bash(curl *)", "WebFetch"]},
		"sandbox": {
			"enabled": true,
			"allowUnsandboxedCommands": true,
			"network": {"allowedDomains": ["corp.example"], "strictAllowlist": false},
			"credentials": {"files": [
				{"path": "/only-user", "mode": "deny"},
				{"path": "`+ssh+`", "mode": "allow"}
			]}
		}
	}`)
	doc := claudeDoc(t, IsolationOptions{
		UserHome: home, ClaudeSandbox: true,
		Grants:  Grants{Net: true, NetAllow: []string{"pypi.org"}},
		Protect: []string{"/data/admin-token"},
	})
	deny := denyList(doc)
	if !strings.Contains(deny, "\nBash(curl *)\n") || !strings.Contains(deny, "\nWebFetch\n") || !strings.Contains(deny, "\nSkill\n") {
		t.Fatalf("deny union:%s", deny)
	}
	if strings.Count(deny, "\nWebFetch\n") != 1 {
		t.Fatalf("duplicate deny:%s", deny)
	}
	sb := doc["sandbox"].(map[string]any)
	if sb["enabled"] != true || sb["allowUnsandboxedCommands"] != false {
		t.Fatalf("bool merge loosened the daemon sandbox: %v", sb)
	}
	net := sb["network"].(map[string]any)
	if net["strictAllowlist"] != true || mustJSON(net["allowedDomains"]) != `[]` {
		t.Fatalf("allowlist not narrowed to policy: %v", net)
	}
	if strings.Contains(mustJSON(net), "pypi.org") || strings.Contains(mustJSON(net), "corp.example") {
		t.Fatalf("daemon host added to the user allowlist: %v", net)
	}
	files := sb["credentials"].(map[string]any)["files"].([]any)
	raw := mustJSON(files)
	if !strings.Contains(raw, "/only-user") || !strings.Contains(raw, "/data/admin-token") || !strings.Contains(raw, ssh) {
		t.Fatalf("credentials union: %s", raw)
	}
	for _, f := range files {
		m := f.(map[string]any)
		if m["path"] == ssh && m["mode"] != "deny" {
			t.Fatalf("credential mode loosened: %v", m)
		}
	}
}

func TestDaemonDomainsUsedWhenUserSetsNone(t *testing.T) {
	home := t.TempDir()
	writeUserSettings(t, home, `{"sandbox":{"enabled":true}}`)
	doc := claudeDoc(t, IsolationOptions{
		UserHome: home, ClaudeSandbox: true,
		Grants: Grants{Net: true, NetAllow: []string{"pypi.org"}},
	})
	net := doc["sandbox"].(map[string]any)["network"].(map[string]any)
	if mustJSON(net["allowedDomains"]) != `["pypi.org"]` || net["strictAllowlist"] != true {
		t.Fatalf("network %v", net)
	}
	if doc["sandbox"].(map[string]any)["enabled"] != true {
		t.Fatal("enabled dropped")
	}
}

func TestUnparseableUserSettingsRefuses(t *testing.T) {
	for _, body := range []string{"{", "", "null", "[]", `{"sandbox":[]}`, `{"permissions":{"deny":"Bash"}}`} {
		home := t.TempDir()
		writeUserSettings(t, home, body)
		_, err := PrepareIsolation(IsolationOptions{Backend: "claude", StateDir: t.TempDir(), UserHome: home, ClaudeSandbox: true})
		var se *SandboxError
		if err == nil || !errors.As(err, &se) || se.Backend != "claude" || !strings.Contains(err.Error(), "refused") {
			t.Fatalf("body %q: %v", body, err)
		}
		if strings.Contains(err.Error(), `claude_sandbox = "off"`) {
			t.Fatalf("unparseable settings offered a bypass: %v", err)
		}
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude", "settings.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := PrepareIsolation(IsolationOptions{Backend: "claude", StateDir: t.TempDir(), UserHome: home})
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("directory settings: %v", err)
	}
}

func TestGrokProfileAndFlags(t *testing.T) {
	user := t.TempDir()
	_ = os.MkdirAll(filepath.Join(user, ".ssh"), 0o700)
	_ = os.MkdirAll(filepath.Join(user, ".grok"), 0o700)
	_ = os.WriteFile(filepath.Join(user, ".grok", "auth.json"), []byte("{}"), 0o600)
	home := filepath.Join(t.TempDir(), "home")
	iso, err := PrepareIsolation(IsolationOptions{Backend: "grok", StateDir: t.TempDir(), Home: home, UserHome: user})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(home, ".grok", "sandbox.toml"))
	if err != nil {
		t.Fatal(err)
	}
	toml := string(b)
	for _, want := range []string{"[profiles.lgb]", `extends = "strict"`, "restrict_network = true", filepath.Join(user, ".ssh")} {
		if !strings.Contains(toml, want) {
			t.Fatalf("profile lacks %q:\n%s", want, toml)
		}
	}
	// Missing paths would make Grok refuse to start. The user login is denied.
	// The placeholder in the bot home is not.
	userAuth := filepath.Join(user, ".grok", "auth.json")
	if strings.Contains(toml, ".aws") || !strings.Contains(toml, strconv.Quote(userAuth)) {
		t.Fatalf("profile deny list:\n%s", toml)
	}
	if strings.Contains(toml, strconv.Quote(filepath.Join(home, ".grok", "auth.json"))) {
		t.Fatalf("profile denies the placeholder:\n%s", toml)
	}
	cfg, err := os.ReadFile(filepath.Join(home, ".grok", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`permission_mode = "default"`, `"Bash"`, `"Read"`, `"Grep"`, `"Glob"`, `"Edit"`, `"Write"`, `"WebFetch"`, `"WebSearch"`, `"MCPTool"`} {
		if !strings.Contains(string(cfg), want) {
			t.Fatalf("config lacks %q:\n%s", want, cfg)
		}
	}
	argv := grokArgv(t, &iso)
	if !strings.Contains(argv, "--sandbox lgb") || !strings.Contains(argv, "--disallowed-tools web_fetch,web_search") || !strings.Contains(argv, "todo_write") {
		t.Fatalf("argv %s", argv)
	}

	iso, err = PrepareIsolation(IsolationOptions{Backend: "grok", StateDir: t.TempDir(), Home: home, UserHome: user,
		Grants: Grants{Net: true, SSH: true}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(home, ".grok", "sandbox.toml"))
	if !strings.Contains(string(b), "restrict_network = false") || strings.Contains(string(b), ".ssh") {
		t.Fatalf("net/ssh grant profile:\n%s", b)
	}
	argv = grokArgv(t, &iso)
	if !strings.Contains(argv, "--disallowed-tools") || strings.Contains(argv, "web_fetch") || strings.Contains(argv, "web_search") || !strings.Contains(argv, "todo_write") {
		t.Fatalf("net grant disallowed list: %s", argv)
	}

	// home = "user" does not write ~/.grok/sandbox.toml. The custom profile
	// lives in a daemon GROK_HOME, because a built-in profile can run unenforced.
	state := t.TempDir()
	iso, err = PrepareIsolation(IsolationOptions{Backend: "grok", StateDir: state, UserHome: user})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(user, ".grok", "sandbox.toml")); err == nil {
		t.Fatalf("wrote the user's sandbox.toml")
	}
	if _, err := os.Stat(filepath.Join(user, ".grok", "config.toml")); err == nil {
		t.Fatalf("wrote the user's config.toml")
	}
	if iso.GrokSandbox != GrokProfile {
		t.Fatalf("user-home profile %q", iso.GrokSandbox)
	}
	env := envMap(iso.Env)
	grokHome := filepath.Join(state, "grok-home")
	if env["HOME"] != user || env["GROK_HOME"] != grokHome {
		t.Fatalf("user-home env: %v", iso.Env)
	}
	b, err = os.ReadFile(filepath.Join(grokHome, "sandbox.toml"))
	if err != nil || !strings.Contains(string(b), "[profiles.lgb]") || !strings.Contains(string(b), `extends = "strict"`) {
		t.Fatalf("daemon profile: %s %v", b, err)
	}
	cfg, err = os.ReadFile(filepath.Join(grokHome, "config.toml"))
	if err != nil || !strings.Contains(string(cfg), `permission_mode = "default"`) {
		t.Fatalf("daemon permission config: %s %v", cfg, err)
	}
	real := filepath.Join(user, ".grok", "auth.json")
	fi, err := os.Stat(real)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		t.Fatalf("user login nlink %v", st)
	}
	dst, err := os.Lstat(filepath.Join(grokHome, "auth.json"))
	if err != nil || dst.Mode()&os.ModeSymlink != 0 || !dst.Mode().IsRegular() || os.SameFile(fi, dst) {
		t.Fatalf("user-home auth was linked: %v %v", dst, err)
	}
	body, err := os.ReadFile(filepath.Join(grokHome, "auth.json"))
	if err != nil || string(body) != GrokPlaceholderAuth {
		t.Fatalf("placeholder %q %v", body, err)
	}
	userBody, err := os.ReadFile(real)
	if err != nil || string(userBody) != "{}" {
		t.Fatalf("user login changed: %q %v", userBody, err)
	}
	if _, err := PrepareIsolation(IsolationOptions{Backend: "grok", StateDir: "relative", UserHome: user}); err == nil {
		t.Fatal("relative state dir wrote a profile")
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func grokArgv(t *testing.T, iso *Isolation) string {
	t.Helper()
	a, err := Args(Spec{Backend: "grok", Prompt: "hi", Workspace: "/ws", Isolate: iso})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(a, " ")
}

// A user sandbox block must not widen policy: with no net grant, user
// domains, sockets, allowWrite "/" and excludedCommands are all dropped.
func TestUserSandboxCannotWidenPolicy(t *testing.T) {
	home := t.TempDir()
	writeUserSettings(t, home, `{"sandbox": {
		"enabled": true,
		"excludedCommands": ["curl"],
		"someFutureKey": true,
		"network": {"allowedDomains": ["evil.example"], "allowUnixSockets": ["/var/run/docker.sock"], "allowLocalBinding": true},
		"filesystem": {"allowWrite": ["/"], "allowRead": ["/"]}
	}}`)
	for _, on := range []bool{true, false} {
		doc := claudeDoc(t, IsolationOptions{UserHome: home, ClaudeSandbox: on})
		sb := doc["sandbox"].(map[string]any)
		raw := mustJSON(sb)
		if sb["enabled"] != true {
			t.Fatalf("sandbox=%v: user enabled lost: %s", on, raw)
		}
		for _, bad := range []string{"evil.example", "docker.sock", `"/"`, "excludedCommands", "curl", "someFutureKey", `"allowLocalBinding":true`} {
			if strings.Contains(raw, bad) {
				t.Fatalf("sandbox=%v: %s leaked into %s", on, bad, raw)
			}
		}
	}
	doc := claudeDoc(t, IsolationOptions{UserHome: home, ClaudeSandbox: true,
		Grants: Grants{Net: true, NetAllow: []string{"pypi.org", "evil.example"}}})
	net := doc["sandbox"].(map[string]any)["network"].(map[string]any)
	if mustJSON(net["allowedDomains"]) != `["evil.example"]` {
		t.Fatalf("intersection: %v", net)
	}
}

// Denying DATA_DIR/cli whole makes Grok's own home read-only and Grok exits
// (seen live with grok 1.0.52). The deny skips the path to the bot's home.
func TestGrokDenyKeepsOwnHomeWritable(t *testing.T) {
	cli := filepath.Join(t.TempDir(), "cli")
	state := filepath.Join(cli, "bot")
	for _, d := range []string{filepath.Join(state, "home"), filepath.Join(state, "perm", "r1"), filepath.Join(cli, "other")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	toml := grokSandboxTOML(IsolationOptions{StateDir: state, Home: filepath.Join(state, "home"), Protect: []string{cli}})
	for _, want := range []string{filepath.Join(cli, "other"), filepath.Join(state, "perm")} {
		if !strings.Contains(toml, strconv.Quote(want)) {
			t.Fatalf("missing deny %s:\n%s", want, toml)
		}
	}
	for _, bad := range []string{strconv.Quote(cli), strconv.Quote(state), strconv.Quote(filepath.Join(state, "home"))} {
		if strings.Contains(toml, bad) {
			t.Fatalf("own home denied (%s):\n%s", bad, toml)
		}
	}
}

func TestRuleFilesAreDeniedWhenPresent(t *testing.T) {
	cli := filepath.Join(t.TempDir(), "cli")
	state := filepath.Join(cli, "bot")
	home := filepath.Join(state, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, name := range []string{"user-permissions.json", "grok-permission-rules"} {
		p := filepath.Join(state, name)
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	opts := IsolationOptions{StateDir: state, Home: home, Protect: []string{cli}}
	toml := grokSandboxTOML(opts)
	for _, p := range files {
		if strings.Count(toml, strconv.Quote(p)) != 1 {
			t.Fatalf("deny count for %s:\n%s", p, toml)
		}
	}
	if strings.Contains(toml, strconv.Quote(home)) {
		t.Fatalf("home denied:\n%s", toml)
	}
	empty := filepath.Join(t.TempDir(), "cli", "bot")
	if err := os.MkdirAll(filepath.Join(empty, "home"), 0o700); err != nil {
		t.Fatal(err)
	}
	absent := grokSandboxTOML(IsolationOptions{StateDir: empty, Home: filepath.Join(empty, "home"), Protect: []string{filepath.Dir(empty)}})
	if strings.Contains(absent, "user-permissions.json") || strings.Contains(absent, "grok-permission-rules") {
		t.Fatalf("missing rule file was denied:\n%s", absent)
	}
	raw, err := claudeSettingsJSON(IsolationOptions{
		Backend: "claude", StateDir: state, UserHome: t.TempDir(), Protect: []string{cli},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, p := range files {
		for _, want := range []string{"Read(/" + p + ")", "Edit(/" + p + ")"} {
			if !strings.Contains(body, want) {
				t.Fatalf("claude settings missing %s:\n%s", want, body)
			}
		}
	}
}
