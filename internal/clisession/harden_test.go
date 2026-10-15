package clisession

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// With claude_sandbox off (managed: the org's own Claude settings run the
// sandbox) the daemon writes no sandbox block at all, so it can't override
// or weaken the user's; it never writes enabled:false in any mode.
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
	// Missing paths would make Grok refuse to start; its own login stays readable.
	if strings.Contains(toml, ".aws") || strings.Contains(toml, "auth.json") {
		t.Fatalf("profile denies a missing path or Grok's login:\n%s", toml)
	}
	argv := grokArgv(t, &iso)
	if !strings.Contains(argv, "--sandbox lgb") || !strings.Contains(argv, "--disallowed-tools web_fetch,web_search") {
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
	if strings.Contains(argv, "--disallowed-tools") {
		t.Fatalf("net grant still disallows web tools: %s", argv)
	}

	// The user's own GROK_HOME is never written; built-in strict is used.
	iso, err = PrepareIsolation(IsolationOptions{Backend: "grok", StateDir: t.TempDir(), UserHome: user})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(user, ".grok", "sandbox.toml")); err == nil {
		t.Fatalf("wrote the user's sandbox.toml")
	}
	if iso.GrokSandbox != "strict" {
		t.Fatalf("user-home profile %q", iso.GrokSandbox)
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
