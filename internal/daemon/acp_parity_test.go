package daemon

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func installFakeGrok(t *testing.T, dir string) {
	t.Helper()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(bin, "grok")
	if err := os.Link(exe, dst); err != nil {
		in, rerr := os.Open(exe)
		if rerr != nil {
			t.Fatalf("link %v; open %v", err, rerr)
		}
		defer in.Close()
		out, rerr := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if _, rerr = io.Copy(out, in); rerr != nil {
			out.Close()
			t.Fatal(rerr)
		}
		if rerr = out.Close(); rerr != nil {
			t.Fatal(rerr)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("LGB_ACP_FAKE", "1")
}

type acpFix struct {
	t         *testing.T
	app       *App
	url       string
	bot       store.Bot
	runID     string
	ws        string
	stdinPath string
	argvPath  string
	gate      string
	events    <-chan string
	lg        *audit.Logger
	auditPath string
	dataDir   string
	saved     []string
	token     string
}

func prepareACP(t *testing.T, mode string, pol policy.Policy) *acpFix {
	t.Helper()
	dir := t.TempDir()
	installFakeGrok(t, dir)
	f := &acpFix{
		t:         t,
		auditPath: filepath.Join(dir, "audit.log"),
		dataDir:   dir,
	}
	t.Setenv("LGB_ACP_MODE", mode)
	app := newApp(t, dir, nil)
	f.token = armAdmin(app)
	lg, err := audit.Open(f.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	app.cliTTY = func() bool { return false }
	pol.Backend = "grok"
	pol.CLIPermitted = true
	pol.TimersEnabled = true
	if pol.Idle == 0 {
		pol.Idle = time.Hour
	}
	if pol.Imminent == 0 {
		pol.Imminent = time.Minute
	}
	app.rtMu.Lock()
	app.setPol(pol)
	app.rtMu.Unlock()
	srv := serve(t, app)
	app.permBase = srv.URL
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Ada", "description": "g"}, f.token)
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	f.app = app
	f.url = srv.URL
	f.bot = bot
	f.lg = lg
	f.ws = filepath.Join(app.ws, "bots", bot.ID)
	if err := os.MkdirAll(f.ws, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.ws, "a.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.stdinPath = filepath.Join(f.ws, "stdin.log")
	f.argvPath = filepath.Join(f.ws, "argv.log")
	t.Setenv("LGB_STDIN_LOG", f.stdinPath)
	t.Setenv("LGB_ARGV_LOG", f.argvPath)
	return f
}

func (f *acpFix) rule(effect, pattern string) {
	f.t.Helper()
	res, b := do(f.t, "POST", f.url+"/api/bots/"+f.bot.ID+"/permission-rules", map[string]any{
		"effect": effect, "pattern": pattern,
	}, f.token)
	if res.StatusCode != 201 {
		f.t.Fatalf("rule %s %s: %d %s", effect, pattern, res.StatusCode, b)
	}
}

func (f *acpFix) gateFile() string {
	f.t.Helper()
	if f.gate == "" {
		f.gate = filepath.Join(f.ws, "gate")
		f.t.Setenv("LGB_ACP_GATE", f.gate)
	}
	return f.gate
}

func (f *acpFix) start(prompts bool) {
	f.startContent("go", prompts)
}

func (f *acpFix) startContent(content string, prompts bool) {
	f.t.Helper()
	res, b := do(f.t, "POST", f.url+"/api/bots/"+f.bot.ID+"/thread/messages", map[string]any{"content": content}, f.token)
	if res.StatusCode != 200 {
		f.t.Fatalf("post %d %s", res.StatusCode, b)
	}
	var posted struct {
		RunID string `json:"run_id"`
	}
	decodeJSON(f.t, b, &posted)
	f.runID = posted.RunID
	if prompts {
		f.events = startSSE(f.t, f.url, f.bot.ID, posted.RunID, f.token)
		waitSubscribed(f.t, f.app, posted.RunID)
	}
}

func (f *acpFix) openGate() {
	f.t.Helper()
	if err := os.WriteFile(f.gateFile(), []byte("go\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *acpFix) waitDone() store.Bot {
	f.t.Helper()
	waitIdle(f.t, f.url, f.bot.ID, f.token)
	got, err := f.app.st.GetBot(f.bot.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	return got
}

func (f *acpFix) auditText() string {
	f.t.Helper()
	if err := f.lg.Close(); err != nil {
		f.t.Fatal(err)
	}
	raw, err := os.ReadFile(f.auditPath)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(raw)
}

func (f *acpFix) stdinText() string {
	f.t.Helper()
	b, err := os.ReadFile(f.stdinPath)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(b)
}

func (f *acpFix) argvText() string {
	f.t.Helper()
	b, err := os.ReadFile(f.argvPath)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(b)
}

func (f *acpFix) permRecs() []store.ToolRecord {
	f.t.Helper()
	tools, err := f.app.st.RunTools([]string{f.runID})
	if err != nil {
		f.t.Fatal(err)
	}
	var out []store.ToolRecord
	for _, rec := range tools[f.runID] {
		if rec.Kind == "permission" {
			out = append(out, rec)
		}
	}
	return out
}

func (f *acpFix) askEnv(variant, name, command, path string) {
	f.t.Helper()
	f.t.Setenv("LGB_ACP_VARIANT", variant)
	f.t.Setenv("LGB_ACP_NAME", name)
	f.t.Setenv("LGB_ACP_COMMAND", command)
	f.t.Setenv("LGB_ACP_PATH", path)
}

func assertNoAlwaysAllow(t *testing.T, stdin string) {
	t.Helper()
	if strings.Contains(stdin, "always-allow") || strings.Contains(stdin, "allow_always") {
		t.Fatalf("host selected allow_always:\n%s", stdin)
	}
}

func assertWireOnce(t *testing.T, stdin, option string) {
	t.Helper()
	assertNoAlwaysAllow(t, stdin)
	if !strings.Contains(stdin, `"optionId":"`+option+`"`) {
		t.Fatalf("stdin missing %s:\n%s", option, stdin)
	}
	if strings.Contains(stdin, "yoloMode") || strings.Contains(stdin, "autoMode") {
		t.Fatalf("session start bypassed policy:\n%s", stdin)
	}
}

func argvFlag(argv, flag, value string) bool {
	lines := strings.Split(argv, "\n")
	for i := 0; i < len(lines)-1; i++ {
		if lines[i] == flag && lines[i+1] == value {
			return true
		}
	}
	return false
}

func assertGrokAskConfig(t *testing.T, dataDir string) {
	t.Helper()
	var found string
	err := filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if info.Name() == "config.toml" && strings.Contains(path, "grok") {
			found = path
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == "" {
		t.Fatal("grok config.toml was not written")
	}
	b, err := os.ReadFile(found)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, want := range []string{`permission_mode = "default"`, `"Bash"`, `"Read"`, `"Grep"`, `"Glob"`, `"Edit"`, `"Write"`, `"WebFetch"`, `"WebSearch"`, `"MCPTool"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("config %s lacks %s:\n%s", found, want, text)
		}
	}
}

func TestACPUserAllowMatchesClaudeAudit(t *testing.T) {
	f := prepareACP(t, "ask", policy.Policy{UIPrompts: false})
	f.rule("allow", "Bash(cat *)")
	f.rule("allow", "Read(./**)")
	f.askEnv("Bash", "run_terminal_command", "cat -- a.txt", "")
	f.start(false)
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	raw := f.auditText()
	recs := f.permRecs()
	if len(recs) != 1 || !recs[0].OK {
		t.Fatalf("records %+v", recs)
	}
	for _, body := range []string{raw, recs[0].Result} {
		for _, want := range []string{
			`"decision":"allow"`, `"source":"user"`, `"transport":"acp"`,
			`"rule_id"`, `"classification":"read_only"`, `"sensitivity":"project"`, `"risk":"low"`,
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("missing %s in %s", want, body)
			}
		}
	}
	if !strings.Contains(recs[0].Result, "Bash(cat *)") {
		t.Fatalf("rule %s", recs[0].Result)
	}
	assertWireOnce(t, f.stdinText(), "allow-once")
	argv := f.argvText()
	if argvFlag(argv, "--allow", "Bash(cat *)") || strings.Contains(argv, "--always-approve") || strings.Contains(argv, "--permission-mode") {
		t.Fatalf("argv\n%s", argv)
	}
	assertGrokAskConfig(t, f.dataDir)
}

func TestACPUserAllowRead(t *testing.T) {
	f := prepareACP(t, "ask", policy.Policy{UIPrompts: false})
	f.rule("allow", "Read(./**)")
	f.askEnv("ReadFile", "read_file", "", "a.txt")
	f.start(false)
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	recs := f.permRecs()
	if len(recs) != 1 || !recs[0].OK || recs[0].Name != "Read" {
		t.Fatalf("records %+v", recs)
	}
	raw := f.auditText()
	for _, body := range []string{raw, recs[0].Result} {
		for _, want := range []string{`"source":"user"`, `"decision":"allow"`, `"classification":"read_only"`, `"transport":"acp"`, "Read(./**)"} {
			if !strings.Contains(body, want) {
				t.Fatalf("missing %s in %s", want, body)
			}
		}
	}
	assertWireOnce(t, f.stdinText(), "allow-once")
}

func TestACPFloorDoesNotAutoAllow(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("no\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, variant, tool, command, path string
		link                               bool
	}{
		{name: "composed", variant: "Bash", tool: "run_terminal_command", command: "cat -- a.txt; rm -rf /tmp/nope"},
		{name: "git", variant: "Bash", tool: "run_terminal_command", command: "git status"},
		{name: "outside", variant: "ReadFile", tool: "read_file", path: outside},
		{name: "symlink", variant: "ReadFile", tool: "read_file", path: "out-link", link: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := prepareACP(t, "ask", policy.Policy{UIPrompts: false})
			f.rule("allow", "Bash(cat *)")
			f.rule("allow", "Read(./**)")
			if c.link {
				if err := os.Symlink(outside, filepath.Join(f.ws, "out-link")); err != nil {
					t.Fatal(err)
				}
			}
			f.askEnv(c.variant, c.tool, c.command, c.path)
			f.start(false)
			got := f.waitDone()
			if got.LastRunStatus != "done" || got.LastRunError != "" {
				t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
			}
			raw := f.auditText()
			if strings.Contains(raw, `"source":"user"`) || !strings.Contains(raw, `"source":"no_ui"`) || !strings.Contains(raw, `"decision":"deny"`) || !strings.Contains(raw, `"transport":"acp"`) {
				t.Fatalf("audit %s", raw)
			}
			assertWireOnce(t, f.stdinText(), "reject-once")
		})
	}
}

func TestACPManagedDenyBeatsUserAllow(t *testing.T) {
	f := prepareACP(t, "ask", policy.Policy{
		UIPrompts: false,
		ToolDeny:  []string{"Bash(cat *)"},
	})
	f.rule("allow", "Bash(cat *)")
	f.askEnv("Bash", "run_terminal_command", "cat -- a.txt", "")
	f.start(false)
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	raw := f.auditText()
	if !strings.Contains(raw, `"source":"policy"`) || !strings.Contains(raw, `"decision":"deny"`) || strings.Contains(raw, `"source":"user"`) {
		t.Fatalf("audit %s", raw)
	}
	argv := f.argvText()
	if !argvFlag(argv, "--deny", "Bash(cat *)") || argvFlag(argv, "--allow", "Bash(cat *)") {
		t.Fatalf("argv\n%s", argv)
	}
	assertWireOnce(t, f.stdinText(), "reject-once")
}

func TestACPUserDenyBeatsManagedAllowAndBypass(t *testing.T) {
	f := prepareACP(t, "ask", policy.Policy{
		UIPrompts:      false,
		PermissionMode: "bypassPermissions",
		ManagedBypass:  true,
		ToolAllow:      []string{"Bash(git status*)"},
	})
	f.rule("deny", "Bash(git status*)")
	f.askEnv("Bash", "run_terminal_command", "git status", "")
	f.start(false)
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	raw := f.auditText()
	if !strings.Contains(raw, `"source":"user"`) || !strings.Contains(raw, `"decision":"deny"`) || strings.Contains(raw, `"source":"policy"`) {
		t.Fatalf("audit %s", raw)
	}
	argv := f.argvText()
	if strings.Contains(argv, "--always-approve") || argvFlag(argv, "--allow", "Bash(git status*)") {
		t.Fatalf("argv\n%s", argv)
	}
	assertWireOnce(t, f.stdinText(), "reject-once")
}

func TestACPManagedAskBeatsBypassAndUserAllow(t *testing.T) {
	f := prepareACP(t, "ask", policy.Policy{
		UIPrompts:      false,
		PermissionMode: "bypassPermissions",
		ManagedBypass:  true,
		ToolAsk:        []string{"Bash(cat *)"},
	})
	f.rule("allow", "Bash(cat *)")
	f.askEnv("Bash", "run_terminal_command", "cat -- a.txt", "")
	f.start(false)
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	raw := f.auditText()
	if !strings.Contains(raw, `"source":"no_ui"`) || !strings.Contains(raw, `"decision":"deny"`) || strings.Contains(raw, `"source":"policy"`) || strings.Contains(raw, `"source":"user"`) {
		t.Fatalf("audit %s", raw)
	}
	if strings.Contains(f.argvText(), "--always-approve") {
		t.Fatalf("argv\n%s", f.argvText())
	}
	assertWireOnce(t, f.stdinText(), "reject-once")
}

func TestACPBypassAllowsWithoutApproveFlag(t *testing.T) {
	f := prepareACP(t, "ask", policy.Policy{
		UIPrompts:      false,
		PermissionMode: "always-allow",
		ManagedBypass:  true,
	})
	f.askEnv("Bash", "run_terminal_command", "git status", "")
	f.start(false)
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	raw := f.auditText()
	if !strings.Contains(raw, `"source":"policy"`) || !strings.Contains(raw, `"decision":"allow"`) || !strings.Contains(raw, "always-allow") {
		t.Fatalf("audit %s", raw)
	}
	argv := f.argvText()
	if strings.Contains(argv, "--always-approve") || strings.Contains(argv, "--permission-mode") {
		t.Fatalf("argv\n%s", argv)
	}
	assertWireOnce(t, f.stdinText(), "allow-once")
}

func TestACPManagedAllow(t *testing.T) {
	f := prepareACP(t, "ask", policy.Policy{
		UIPrompts: false,
		ToolAllow: []string{"Bash(git status*)"},
	})
	f.askEnv("Bash", "run_terminal_command", "git status", "")
	f.start(false)
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	raw := f.auditText()
	if !strings.Contains(raw, `"source":"policy"`) || !strings.Contains(raw, `"decision":"allow"`) || !strings.Contains(raw, "Bash(git status*)") {
		t.Fatalf("audit %s", raw)
	}
	assertWireOnce(t, f.stdinText(), "allow-once")
}

func TestACPUnknownToolReachesBroker(t *testing.T) {
	f := prepareACP(t, "ask", policy.Policy{UIPrompts: false})
	f.askEnv("", "custom_widget", "", "")
	f.start(false)
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	raw := f.auditText()
	if !strings.Contains(raw, `"tool":"unknown"`) || !strings.Contains(raw, `"classification":"unknown"`) || !strings.Contains(raw, `"source":"no_ui"`) || !strings.Contains(raw, `"transport":"acp"`) {
		t.Fatalf("audit %s", raw)
	}
	if strings.Contains(raw, "custom_widget") {
		t.Fatalf("raw name kept %s", raw)
	}
	recs := f.permRecs()
	if len(recs) != 1 || recs[0].Name != "unknown" || !strings.Contains(recs[0].Result, `"classification":"unknown"`) {
		t.Fatalf("records %+v", recs)
	}
	assertWireOnce(t, f.stdinText(), "reject-once")
}

func TestACPHostFailureFailsClosed(t *testing.T) {
	cases := []struct {
		mode, needle string
	}{
		{mode: "exit", needle: "stream ended"},
		{mode: "malformed", needle: "malformed"},
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			f := prepareACP(t, c.mode, policy.Policy{UIPrompts: true, PromptTimeout: 5 * time.Second})
			f.start(false)
			assertHostClosed(t, f, c.needle)
		})
	}
	t.Run("always-only", func(t *testing.T) {
		// The broker allows. The only allow option is allow_always, so the
		// host fails closed instead of selecting it.
		f := prepareACP(t, "always-only", policy.Policy{
			UIPrompts: false, PermissionMode: "always-allow", ManagedBypass: true,
		})
		f.askEnv("Bash", "run_terminal_command", "git status", "")
		f.start(false)
		assertHostClosed(t, f, "allow_once")
	})
}

func assertHostClosed(t *testing.T, f *acpFix, needle string) {
	t.Helper()
	got := f.waitDone()
	if got.LastRunStatus != "error" || !strings.Contains(got.LastRunError, "acp host") {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	raw := f.auditText()
	if !strings.Contains(raw, `"source":"host"`) || !strings.Contains(raw, `"transport":"acp"`) || !strings.Contains(raw, `"decision":"deny"`) || !strings.Contains(raw, needle) {
		t.Fatalf("audit %s", raw)
	}
	assertNoAlwaysAllow(t, f.stdinText())
}

func TestACPProtocolTimeoutFailsClosed(t *testing.T) {
	f := prepareACP(t, "hang", policy.Policy{TurnTimeout: 2 * time.Second})
	f.start(false)
	got := f.waitDone()
	if got.LastRunStatus != "error" || got.LastRunError != "turn_timeout" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	raw := f.auditText()
	if !strings.Contains(raw, `"source":"host"`) || !strings.Contains(raw, `"transport":"acp"`) || !strings.Contains(raw, "protocol timeout") {
		t.Fatalf("audit %s", raw)
	}
}

func TestACPCardAllowOnceDenyAndSession(t *testing.T) {
	t.Run("allow-once", func(t *testing.T) {
		f := cardTurn(t, false, 1)
		id, body := f.waitCard()
		if !strings.Contains(body, `"transport":"acp"`) || !strings.Contains(body, `"tool":"Bash"`) || !strings.Contains(body, `"session_allowed":false`) {
			t.Fatalf("card %s", body)
		}
		f.decide(id, "allow_once")
		got := f.waitDone()
		if got.LastRunStatus != "done" || got.LastRunError != "" {
			t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
		}
		raw := f.auditText()
		if !strings.Contains(raw, `"decision":"allow_once"`) || !strings.Contains(raw, `"source":"ui"`) || !strings.Contains(raw, `"transport":"acp"`) {
			t.Fatalf("audit %s", raw)
		}
		assertWireOnce(t, f.stdinText(), "allow-once")
		if strings.Count(f.eventText(), "permission_request\n") != 1 {
			t.Fatalf("events %s", f.eventText())
		}
	})
	t.Run("deny", func(t *testing.T) {
		f := cardTurn(t, false, 1)
		id, _ := f.waitCard()
		f.decide(id, "deny")
		got := f.waitDone()
		if got.LastRunStatus != "done" || got.LastRunError != "" {
			t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
		}
		raw := f.auditText()
		if !strings.Contains(raw, `"decision":"deny"`) || !strings.Contains(raw, `"source":"ui"`) || !strings.Contains(raw, `"transport":"acp"`) {
			t.Fatalf("audit %s", raw)
		}
		assertWireOnce(t, f.stdinText(), "reject-once")
		tools, err := f.app.st.RunTools([]string{f.runID})
		if err != nil {
			t.Fatal(err)
		}
		denied := false
		for _, rec := range tools[f.runID] {
			if rec.Kind == "permission" {
				continue
			}
			if rec.Name == "Bash" && !rec.OK && rec.Result == "denied" {
				denied = true
			}
		}
		if !denied {
			t.Fatalf("tool records %+v", tools[f.runID])
		}
		msgs, err := f.app.st.ListMessages(f.bot.ID, "user", "", 20)
		if err != nil {
			t.Fatal(err)
		}
		sawText := false
		sawNotice := false
		for _, m := range msgs {
			if m.Content == "Notice: Stopped after denial." {
				sawNotice = true
			}
			if m.Role == "bot" && strings.Contains(m.Content, "continued after deny") {
				sawText = true
			}
		}
		if sawNotice || !sawText {
			t.Fatalf("thread %+v", msgs)
		}
	})
	t.Run("allow-session", func(t *testing.T) {
		f := cardTurn(t, true, 2)
		id, body := f.waitCard()
		if !strings.Contains(body, `"session_allowed":true`) || !strings.Contains(body, `"transport":"acp"`) {
			t.Fatalf("card %s", body)
		}
		f.decide(id, "allow_session")
		got := f.waitDone()
		if got.LastRunStatus != "done" || got.LastRunError != "" {
			t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
		}
		raw := f.auditText()
		if !strings.Contains(raw, `"decision":"allow_session"`) || !strings.Contains(raw, `"source":"ui"`) {
			t.Fatalf("audit %s", raw)
		}
		if !strings.Contains(raw, `"decision":"allow"`) || !strings.Contains(raw, `"rule":"session"`) {
			t.Fatalf("grant %s", raw)
		}
		stdin := f.stdinText()
		assertWireOnce(t, stdin, "allow-once")
		if strings.Count(stdin, `"optionId":"allow-once"`) != 2 {
			t.Fatalf("session grant was not answered allow-once twice:\n%s", stdin)
		}
		if n := strings.Count(f.eventText(), "permission_request\n"); n != 1 {
			t.Fatalf("cards %d\n%s", n, f.eventText())
		}
	})
}

func TestACPSessionGrantSurvivesNextTurn(t *testing.T) {
	f := cardTurn(t, true, 1)
	id, _ := f.waitCard()
	f.decide(id, "allow_session")
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	if got.SessionID != "acp-session" {
		t.Fatalf("session %q", got.SessionID)
	}
	// The gate file is already present, so the next ask is immediate.
	// A grant stored under the daemon id would open another card.
	f.start(false)
	got = f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" {
		t.Fatalf("next run %s %s", got.LastRunStatus, got.LastRunError)
	}
	raw := f.auditText()
	exactAllow := strings.Count(raw, `"decision":"allow"`) - strings.Count(raw, `"decision":"allow_"`)
	if !strings.Contains(raw, `"decision":"allow_session"`) || strings.Count(raw, `"rule":"session"`) < 1 || exactAllow < 1 {
		t.Fatalf("audit %s", raw)
	}
	stdin := f.stdinText()
	assertWireOnce(t, stdin, "allow-once")
	if strings.Count(stdin, `"optionId":"allow-once"`) != 2 {
		t.Fatalf("wire\n%s", stdin)
	}
}

func cardTurn(t *testing.T, session bool, count int) *acpFix {
	t.Helper()
	f := prepareACP(t, "ask", policy.Policy{
		UIPrompts: true, PromptTimeout: 20 * time.Second, AllowSessionGrants: session,
	})
	f.askEnv("Bash", "run_terminal_command", "git status", "")
	if count > 1 {
		t.Setenv("LGB_ACP_COUNT", "2")
	}
	f.gateFile()
	f.start(true)
	return f
}

func (f *acpFix) waitCard() (string, string) {
	f.t.Helper()
	f.openGate()
	var saw []string
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if f.events != nil {
			select {
			case ev := <-f.events:
				saw = append(saw, ev)
			default:
			}
		}
		res, b := do(f.t, "GET", f.url+"/api/bots/"+f.bot.ID+"/permissions", nil, f.token)
		if res.StatusCode != 200 {
			f.t.Fatalf("pending %d %s", res.StatusCode, b)
		}
		if strings.Contains(string(b), `"id"`) && strings.Contains(string(b), `"tool"`) {
			var list pendingList
			decodeJSON(f.t, b, &list)
			if len(list.Pending) > 0 {
				f.saved = append(f.saved, saw...)
				return list.Pending[0].ID, string(b)
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	f.t.Fatalf("no card; events %#v", saw)
	return "", ""
}

func (f *acpFix) decide(id, decision string) {
	f.t.Helper()
	res, b := do(f.t, "POST", f.url+"/api/bots/"+f.bot.ID+"/runs/"+f.runID+"/permissions/"+id, map[string]any{"decision": decision}, f.token)
	if res.StatusCode != 200 {
		f.t.Fatalf("decide %s %d %s", decision, res.StatusCode, b)
	}
}

func (f *acpFix) eventText() string {
	f.t.Helper()
	if f.events != nil {
		f.saved = append(f.saved, drainEvents(f.events, 300*time.Millisecond)...)
	}
	return strings.Join(f.saved, "\n")
}

func TestUserRulesDoNotWidenGrokArgv(t *testing.T) {
	dir := t.TempDir()
	app := newApp(t, dir, nil)
	tok := armAdmin(app)
	cap := &captureRunner{}
	app.runner = cap
	app.rtMu.Lock()
	app.setPol(policy.Policy{
		Backend: "grok", CLIPermitted: true, DaemonJail: false,
		TimersEnabled: true, Idle: time.Hour, Imminent: time.Minute,
		ToolAllow: []string{"Read"},
		ToolDeny:  []string{"Bash(rm *)"},
	})
	app.rtMu.Unlock()
	bot, err := app.st.CreateBot("rules", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	srv := serve(t, app)
	base := srv.URL + "/api/bots/" + bot.ID
	res, body := do(t, "POST", base+"/permission-rules", map[string]any{
		"effect": "allow", "pattern": "Bash(cat *)",
	}, tok)
	if res.StatusCode != 201 {
		t.Fatalf("allow %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", base+"/permission-rules", map[string]any{
		"effect": "deny", "pattern": "Bash(*push*)",
	}, tok)
	if res.StatusCode != 201 {
		t.Fatalf("deny %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", base+"/thread/messages", map[string]any{"content": "go"}, tok)
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, body)
	}
	waitIdle(t, srv.URL, bot.ID, tok)
	got, err := app.st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastRunStatus != "done" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	argv, err := clisession.Args(cap.spec)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, "\n")
	if strings.Contains(joined, "cat") || strings.Contains(joined, "push") || strings.Contains(joined, "--always-approve") || strings.Contains(joined, "--permission-mode") {
		t.Fatalf("argv %v", argv)
	}
	if argvFlag(joined, "--allow", "Read") || !argvFlag(joined, "--deny", "Bash(rm *)") {
		t.Fatalf("policy flags %v", argv)
	}
	if !strings.Contains(joined, "agent\n--no-leader\nstdio") {
		t.Fatalf("argv %v", argv)
	}
	native, err := os.ReadFile(filepath.Join(dir, "cli", bot.ID, "grok-permission-rules"))
	if err != nil || !strings.Contains(string(native), "Bash(cat *)") || !strings.Contains(string(native), "Bash(*push*)") {
		t.Fatalf("native %v %s", err, native)
	}
}
