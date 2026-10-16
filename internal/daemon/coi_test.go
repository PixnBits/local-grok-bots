package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/coi"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

const coiFakeScript = `#!/bin/sh
case "$1" in
  --prompt)
    echo "do you want to allow this command?"
    sleep 30
    exit 0
    ;;
  --fail)
    exit 3
    ;;
  --sleep)
    sleep 2
    echo slept
    exit 0
    ;;
esac
touch "$PWD/ran"
env > "$PWD/child.env"
printf 'HOME=%s\n' "$HOME"
cat "$HOME/auth.json"
`

const coiSecret = "hunter2-hunter2"

func setupCOI(t *testing.T, calls int, bots []string) *coiFix {
	t.Helper()
	t.Setenv("MANAGED_POLICY", "")
	t.Setenv("BIND_ADDR", "")
	t.Setenv("OLLAMA_URL", "")
	t.Setenv("OLLAMA_MODEL", "")
	t.Setenv("LGB_TOKEN", "lgbr_"+strings.Repeat("ab", 32))
	t.Setenv("XAI_API_KEY", "xai-"+strings.Repeat("k", 24))
	t.Setenv("LC_ALL", "C.UTF-8")
	t.Setenv("FOO", "bar")

	dir := t.TempDir()
	ws := filepath.Join(dir, "ws")
	cred := filepath.Join(dir, "cred")
	bin := filepath.Join(dir, "bin", "fake")
	for _, d := range []string{ws, cred, filepath.Dir(bin)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(bin, []byte(coiFakeScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cred, "auth.json"), []byte(`{"token":"`+coiSecret+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &coiFix{
		dir:    dir,
		ws:     ws,
		cred:   cred,
		bin:    bin,
		policy: filepath.Join(dir, "policy.toml"),
		audit:  filepath.Join(dir, "audit.log"),
		calls:  calls,
	}
	f.writeTools(t, "")
	f.app = newCLIApp(t, dir, f.policy)
	var err error
	f.bot, err = f.app.st.CreateBot("Ada", "d", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	if bots == nil {
		bots = []string{f.bot.Name}
	}
	f.bots = bots
	f.writeTools(t, f.entry("fake", bin, cred, bots, calls))
	f.run, _, err = f.app.startLGB(context.Background(), f.bot, "run1", ws)
	if err != nil || f.run == nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.run.stop() })
	return f
}

type coiFix struct {
	app    *App
	bot    store.Bot
	run    *lgbRun
	dir    string
	ws     string
	cred   string
	bin    string
	policy string
	audit  string
	bots   []string
	calls  int
	n      int
}

func (f *coiFix) entry(name, path, home string, bots []string, calls int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[[tools.cli]]\nname = %s\npath = %s\ncredential_home = %s\n",
		strconv.Quote(name), strconv.Quote(path), strconv.Quote(home))
	b.WriteString("bots = [")
	for i, bot := range bots {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(strconv.Quote(bot))
	}
	b.WriteString("]\nallowed_args = [\"--version\", \"--fail\", \"--prompt\", \"--model\", \"--sleep\", \"edit\", \"config\", \"--print-config\", \"--debug\"]\n")
	b.WriteString("value_flags = [\"--model\", \"--prompt\"]\ncredential_files = [\"auth.json\"]\n")
	fmt.Fprintf(&b, "timeout = \"30s\"\nmax_output = 65536\nmax_calls_per_hour = %d\n", calls)
	return b.String()
}

func (f *coiFix) writeTools(t *testing.T, tools string) {
	t.Helper()
	body := "[backend]\nbackend = \"claude\"\n[timers]\nenabled = false\n[security]\naudit_log = " +
		strconv.Quote(f.audit) + "\n" + tools
	if err := os.WriteFile(f.policy, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *coiFix) manual() {
	f.run.cancel()
	<-f.run.done
}

func (f *coiFix) drop(t *testing.T, token string, args ...string) string {
	t.Helper()
	f.n++
	name := fmt.Sprintf("%032x", f.n)
	var b strings.Builder
	b.WriteString(token)
	b.WriteByte(0)
	for _, a := range args {
		b.WriteString(a)
		b.WriteByte(0)
	}
	if err := os.WriteFile(filepath.Join(f.ws, ".lgb", "req", name), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

func (f *coiFix) waitResp(t *testing.T, name string, d time.Duration) (int, string) {
	t.Helper()
	path := filepath.Join(f.ws, ".lgb", "resp", name)
	deadline := time.Now().Add(d)
	for {
		raw, err := os.ReadFile(path)
		if err == nil {
			line, rest, ok := strings.Cut(string(raw), "\n")
			if !ok {
				t.Fatalf("response %q", raw)
			}
			code, err := strconv.Atoi(line)
			if err != nil {
				t.Fatal(err)
			}
			return code, strings.TrimRight(rest, "\n")
		}
		if time.Now().After(deadline) {
			t.Fatalf("no response for %s: %v", name, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (f *coiFix) post(t *testing.T, token string, args ...string) (int, string) {
	t.Helper()
	name := f.drop(t, token, args...)
	f.run.drain(context.Background())
	f.run.waitCOI()
	return f.waitResp(t, name, time.Second)
}

func (f *coiFix) coi(t *testing.T, args ...string) (int, string) {
	t.Helper()
	return f.post(t, f.run.token, append([]string{"coi"}, args...)...)
}

func (f *coiFix) ran() bool {
	_, err := os.Stat(filepath.Join(f.ws, "ran"))
	return err == nil
}

func (f *coiFix) clearRan(t *testing.T) {
	t.Helper()
	_ = os.Remove(filepath.Join(f.ws, "ran"))
}

func (f *coiFix) logs(t *testing.T) []map[string]any {
	t.Helper()
	ev, err := f.app.st.ListLog(f.bot.ID, "coi_call", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]map[string]any, 0, len(ev))
	for _, e := range ev {
		if e.BotID == nil || *e.BotID != f.bot.ID {
			t.Fatalf("log bot %v", e.BotID)
		}
		var m map[string]any
		if err := json.Unmarshal(e.Detail, &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func assertClean(t *testing.T, text string, cred string) {
	t.Helper()
	for _, bad := range []string{cred, coiSecret, "lgbr_", "xai-", "XAI_API_KEY"} {
		if strings.Contains(text, bad) {
			t.Fatalf("text contains %q:\n%s", bad, text)
		}
	}
}

func TestCOIShimRunsFakeCLI(t *testing.T) {
	f := setupCOI(t, 5, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	runShim := func(bin string, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, filepath.Join(f.ws, ".lgb", "bin", bin), args...)
		cmd.Env = []string{
			"PATH=/usr/bin:/bin",
			"LGB_SPOOL=" + filepath.Join(f.ws, lgbDirName),
			"LGB_TOKEN=" + f.run.token,
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", bin, args, err, out)
		}
		return string(out)
	}
	out := runShim("coi", "fake", "--version")
	if !strings.Contains(out, coi.PlaceholderToken) || strings.Contains(out, coiSecret) {
		t.Fatalf("shim output:\n%s", out)
	}
	assertClean(t, out, f.cred)
	envb, err := os.ReadFile(filepath.Join(f.ws, "child.env"))
	if err != nil {
		t.Fatal(err)
	}
	envText := string(envb)
	for _, want := range []string{
		"LC_ALL=C.UTF-8\n",
		"PWD=" + f.ws + "\n",
	} {
		if !strings.Contains(envText, want) {
			t.Fatalf("child env lacks %q:\n%s", want, envText)
		}
	}
	if !strings.Contains(envText, "HOME=") || strings.Contains(envText, "HOME="+f.cred) {
		t.Fatalf("child home still the credential home:\n%s", envText)
	}
	for _, bad := range []string{"LGB_TOKEN=", "XAI_API_KEY=", "FOO=", "lgbr_", coiSecret, "HOME=" + f.ws, f.cred} {
		if strings.Contains(envText, bad) {
			t.Fatalf("child env contains %q:\n%s", bad, envText)
		}
	}
	if strings.Contains(envText, "HOME=/home/") {
		t.Fatalf("child kept a host home:\n%s", envText)
	}
	f.clearRan(t)
	again := runShim("lgb", "coi", "fake", "--model", coiSecret)
	assertClean(t, again, f.cred)
	if !strings.Contains(again, coi.PlaceholderToken) {
		t.Fatalf("lgb coi output:\n%s", again)
	}

	logs := f.logs(t)
	if len(logs) < 2 {
		t.Fatalf("coi logs: %+v", logs)
	}
	redactedArg := false
	for _, m := range logs[:2] {
		if m["run_id"] != f.run.runID || m["cli"] != "fake" || m["status"] != coi.StatusOK {
			t.Fatalf("log %+v", m)
		}
		if m["exit_code"] != float64(0) {
			t.Fatalf("exit %+v", m["exit_code"])
		}
		if args, ok := m["args"].([]any); ok {
			for _, a := range args {
				if a == "[redacted]" {
					redactedArg = true
				}
			}
		}
	}
	if !redactedArg {
		t.Fatalf("secret arg was not redacted: %+v", logs[:2])
	}
	raw := string(mustRead(t, f.audit))
	if !strings.Contains(raw, `"event":"coi_call"`) || !strings.Contains(raw, f.bot.ID) || !strings.Contains(raw, f.run.runID) {
		t.Fatalf("audit log:\n%s", raw)
	}
	assertClean(t, raw, f.cred)
	lgb, err := f.app.st.ListLog(f.bot.ID, "lgb_call", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(lgb) != 0 {
		t.Fatalf("coi was also logged as lgb: %+v", lgb)
	}
}

func TestCOIDeniesAndCaps(t *testing.T) {
	f := setupCOI(t, 1, nil)
	f.manual()

	code, out := f.coi(t, "nope", "--version")
	if code != 1 || out != "coi: unknown cli" || f.ran() {
		t.Fatalf("unknown %d %q ran=%v", code, out, f.ran())
	}
	code, out = f.coi(t)
	if code != 1 || out != "coi: unknown cli" {
		t.Fatalf("empty %d %q", code, out)
	}

	f.writeTools(t, f.entry("fake", f.bin, f.cred, []string{"Other"}, 1))
	code, out = f.coi(t, "fake", "--version")
	if code != 1 || out != "coi: not granted" || f.ran() {
		t.Fatalf("grant %d %q ran=%v", code, out, f.ran())
	}
	f.writeTools(t, f.entry("fake", f.bin, f.cred, []string{f.bot.Name}, 1))

	code, out = f.coi(t, "fake", "--print-config")
	if code != 1 || !strings.Contains(out, "argument is blocked") || f.ran() {
		t.Fatalf("print-config %d %q ran=%v", code, out, f.ran())
	}
	assertClean(t, out, f.cred)
	code, out = f.coi(t, "fake", "config")
	if code != 1 || !strings.Contains(out, "argument is blocked") || f.ran() {
		t.Fatalf("config %d %q", code, out)
	}
	code, out = f.coi(t, "fake", "edit", "/etc/passwd")
	if code != 1 || !strings.Contains(out, "outside the workspace") || f.ran() {
		t.Fatalf("outside %d %q", code, out)
	}
	code, out = f.coi(t, "fake", f.cred+"/auth.json")
	if code != 1 || strings.Contains(out, f.cred) || f.ran() {
		t.Fatalf("cred arg %d %q ran=%v", code, out, f.ran())
	}

	code, out = f.coi(t, "fake", "--version")
	if code != 0 || !f.ran() || strings.Contains(out, coiSecret) || strings.Contains(out, f.cred) {
		t.Fatalf("first call %d %q ran=%v", code, out, f.ran())
	}
	f.clearRan(t)
	code, out = f.coi(t, "fake", "--version")
	if code != 1 || out != "coi: hourly cap reached" || f.ran() {
		t.Fatalf("cap %d %q ran=%v", code, out, f.ran())
	}

	f.writeTools(t, f.entry("fake", f.bin, f.cred, []string{f.bot.Name}, 1)+
		f.entry("zero", f.bin, f.cred, []string{f.bot.Name}, 0))
	code, out = f.coi(t, "zero", "--version")
	if code != 1 || out != "coi: hourly cap reached" || f.ran() {
		t.Fatalf("zero cap %d %q ran=%v", code, out, f.ran())
	}

	missing := filepath.Join(f.dir, "missing-bin")
	f.writeTools(t, f.entry("fake", missing, f.cred, []string{f.bot.Name}, 5))
	code, out = f.coi(t, "fake", "--version")
	if code != 1 || out != "coi: cli binary is not available" || f.ran() {
		t.Fatalf("missing bin %d %q", code, out)
	}
	homeFile := filepath.Join(f.dir, "not-a-dir")
	if err := os.WriteFile(homeFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.writeTools(t, f.entry("fake", f.bin, homeFile, []string{f.bot.Name}, 5))
	code, out = f.coi(t, "fake", "--version")
	if code != 1 || out != "coi: credential home is not available" || strings.Contains(out, homeFile) {
		t.Fatalf("file home %d %q", code, out)
	}
	inside := filepath.Join(f.ws, "secrets")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	f.writeTools(t, f.entry("fake", f.bin, inside, []string{f.bot.Name}, 5))
	code, out = f.coi(t, "fake", "--version")
	if code != 1 || out != "coi: credential home is not available" || strings.Contains(out, inside) || f.ran() {
		t.Fatalf("inside home %d %q ran=%v", code, out, f.ran())
	}

	if err := os.Remove(f.policy); err != nil {
		t.Fatal(err)
	}
	code, out = f.coi(t, "fake", "--version")
	if code != 1 || out != "coi: policy is not available" {
		t.Fatalf("missing policy %d %q", code, out)
	}
	if err := os.WriteFile(f.policy, []byte("[[["), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out = f.coi(t, "fake", "--version")
	if code != 1 || out != "coi: policy is not available" || f.ran() {
		t.Fatalf("bad policy %d %q ran=%v", code, out, f.ran())
	}

	f.run.calls = lgbMaxCalls
	code, out = f.coi(t, "fake", "--version")
	if code != 2 || out != "coi: call limit for this turn reached" {
		t.Fatalf("turn cap %d %q", code, out)
	}
}

func TestCOITokenBinding(t *testing.T) {
	f := setupCOI(t, 5, nil)
	f.manual()
	ws2 := filepath.Join(f.dir, "ws2")
	if err := os.MkdirAll(ws2, 0o755); err != nil {
		t.Fatal(err)
	}
	other, _, err := f.app.startLGB(context.Background(), f.bot, "run2", ws2)
	if err != nil || other == nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.stop() })
	other.cancel()
	<-other.done

	code, out := f.post(t, other.token, "coi", "fake", "--version")
	if code != 2 || out != "coi: not authorized" || f.ran() {
		t.Fatalf("other run %d %q ran=%v", code, out, f.ran())
	}
	code, out = f.post(t, "lgbr_"+strings.Repeat("cd", 32), "coi", "fake", "--version")
	if code != 2 || out != "coi: not authorized" || f.ran() {
		t.Fatalf("wrong token %d %q", code, out)
	}

	f.app.lgbMu.Lock()
	cred := f.app.lgbLive[f.run.token]
	cred.botID = "other-bot"
	f.app.lgbLive[f.run.token] = cred
	f.app.lgbMu.Unlock()
	code, out = f.coi(t, "fake", "--version")
	if code != 2 || out != "coi: not authorized" || f.ran() {
		t.Fatalf("wrong bot %d %q ran=%v", code, out, f.ran())
	}

	f.app.lgbMu.Lock()
	cred = f.app.lgbLive[f.run.token]
	cred.botID = f.bot.ID
	cred.runID = "other-run"
	f.app.lgbLive[f.run.token] = cred
	f.app.lgbMu.Unlock()
	code, out = f.coi(t, "fake", "--version")
	if code != 2 || out != "coi: not authorized" || f.ran() {
		t.Fatalf("wrong run %d %q ran=%v", code, out, f.ran())
	}

	f.app.forgetRunToken(f.run.token)
	code, out = f.coi(t, "fake", "--version")
	if code != 2 || out != "coi: not authorized" || f.ran() {
		t.Fatalf("expired %d %q ran=%v", code, out, f.ran())
	}
	logs := f.logs(t)
	if len(logs) < 5 {
		t.Fatalf("want a denial per attempt, got %d", len(logs))
	}
	for _, m := range logs {
		if m["status"] != coi.StatusDenied || m["error"] != "bad token" || m["run_id"] != f.run.runID {
			t.Fatalf("log %+v", m)
		}
	}
}

func TestCOIReloadsPolicy(t *testing.T) {
	f := setupCOI(t, 5, nil)
	f.manual()
	code, out := f.coi(t, "fake", "--fail")
	if code != 3 || out != "" {
		t.Fatalf("exit %d %q", code, out)
	}
	f.writeTools(t, "")
	code, out = f.coi(t, "fake", "--version")
	if code != 1 || out != "coi: unknown cli" || f.ran() {
		t.Fatalf("removed %d %q ran=%v", code, out, f.ran())
	}
	f.writeTools(t, f.entry("other", f.bin, f.cred, []string{f.bot.ID}, 5))
	code, out = f.coi(t, "other", "--version")
	if code != 0 || !f.ran() || strings.Contains(out, f.cred) || strings.Contains(out, coiSecret) {
		t.Fatalf("reloaded %d %q ran=%v", code, out, f.ran())
	}
	logs := f.logs(t)
	var sawFail, sawOther bool
	for _, m := range logs {
		if m["cli"] == "fake" && m["status"] == coi.StatusOK && m["exit_code"] == float64(3) {
			sawFail = true
		}
		if m["cli"] == "other" && m["status"] == coi.StatusOK && m["exit_code"] == float64(0) {
			sawOther = true
			args, _ := m["args"].([]any)
			if len(args) != 1 || args[0] != "--version" {
				t.Fatalf("args %+v", m["args"])
			}
		}
	}
	if !sawFail || !sawOther {
		t.Fatalf("logs %+v", logs)
	}
}

func TestCOIPermissionPromptDenied(t *testing.T) {
	f := setupCOI(t, 5, nil)
	f.manual()
	start := time.Now()
	code, out := f.coi(t, "fake", "--prompt", coiSecret)
	if time.Since(start) > 3*time.Second {
		t.Fatalf("prompt waited %s", time.Since(start))
	}
	if code != 1 || out != "coi: permission prompt denied" || strings.Contains(out, "allow this") {
		t.Fatalf("prompt %d %q", code, out)
	}
	f.assertPrompt(t, "no_ui", "")

	body := "[backend]\nbackend = \"claude\"\n[timers]\nenabled = false\n[cli.permission]\nui_prompts = true\nprompt_timeout = \"30s\"\n[security]\naudit_log = " +
		strconv.Quote(f.audit) + "\n" + f.entry("fake", f.bin, f.cred, []string{f.bot.Name}, 5)
	if err := os.WriteFile(f.policy, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	code, out = f.coi(t, "fake", "--prompt")
	if time.Since(start) > 3*time.Second {
		t.Fatalf("ui prompt waited %s", time.Since(start))
	}
	if code != 1 || out != "coi: permission prompt denied" {
		t.Fatalf("ui prompt %d %q", code, out)
	}
	f.assertPrompt(t, "coi", "stdin-closed")
	assertClean(t, string(mustRead(t, f.audit)), f.cred)
}

func (f *coiFix) assertPrompt(t *testing.T, source, rule string) {
	t.Helper()
	raw := string(mustRead(t, f.audit))
	if !strings.Contains(raw, `"event":"permission_decision"`) || !strings.Contains(raw, `"tool":"coi:fake"`) || !strings.Contains(raw, `"source":"`+source+`"`) {
		t.Fatalf("audit lacks permission %s:\n%s", source, raw)
	}
	if rule != "" && !strings.Contains(raw, `"rule":"`+rule+`"`) {
		t.Fatalf("audit lacks rule %s:\n%s", rule, raw)
	}
	logs := f.logs(t)
	if len(logs) == 0 || logs[0]["status"] != coi.StatusDenied || logs[0]["error"] != "permission prompt denied" {
		t.Fatalf("coi log %+v", logs)
	}
	tools, err := f.app.st.RunTools([]string{f.run.runID})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, rec := range tools[f.run.runID] {
		if rec.Kind == "permission" && rec.Name == "coi:fake" && strings.Contains(rec.Result, `"source":"`+source+`"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("run tools %+v", tools[f.run.runID])
	}
}

func TestCOIRefusesCredentialHomeOutsideTurn(t *testing.T) {
	f := setupCOI(t, 5, nil)
	f.run.protect = f.app.daemonSecrets()
	f.run.protectSet = true
	if !coi.Covers(f.run.protect, f.cred) {
		t.Fatalf("snapshot %v lacks %s", f.run.protect, f.cred)
	}
	later := filepath.Join(f.dir, "later-home")
	if err := os.MkdirAll(later, 0o700); err != nil {
		t.Fatal(err)
	}
	f.writeTools(t, f.entry("fake", f.bin, f.cred, f.bots, 5)+f.entry("later", f.bin, later, f.bots, 5))
	code, out := f.coi(t, "later", "--version")
	if code != 1 || out != "coi: credential home is not allowed" || f.ran() {
		t.Fatalf("later %d %q ran=%v", code, out, f.ran())
	}
	code, out = f.coi(t, "fake", "--version")
	if code != 0 || !f.ran() {
		t.Fatalf("original %d %q", code, out)
	}
}

func TestCOIDoesNotBlockLGB(t *testing.T) {
	f := setupCOI(t, 5, nil)
	start := time.Now()
	slow := f.drop(t, f.run.token, "coi", "fake", "--sleep")
	mem := f.drop(t, f.run.token, "memory", "set", "color", "blue")
	code, out := f.waitResp(t, mem, 2*time.Second)
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("lgb waited on coi: %s %d %q", time.Since(start), code, out)
	}
	if code != 0 {
		t.Fatalf("lgb %d %q", code, out)
	}
	got, err := f.app.st.ListMemory(f.bot.ID)
	if err != nil || len(got) != 1 || got[0].Key != "color" || got[0].Value != "blue" {
		t.Fatalf("memory %+v %v", got, err)
	}
	code, out = f.waitResp(t, slow, 8*time.Second)
	if code != 0 || !strings.Contains(out, "slept") {
		t.Fatalf("coi %d %q", code, out)
	}
}

func TestCOISandboxUnavailable(t *testing.T) {
	f := setupCOI(t, 5, nil)
	f.manual()
	var b strings.Builder
	fmt.Fprintf(&b, "[[tools.cli]]\nname = %s\npath = %s\ncredential_home = %s\n",
		strconv.Quote("fake"), strconv.Quote(f.bin), strconv.Quote(f.cred))
	fmt.Fprintf(&b, "bots = [%s]\nallowed_args = [\"--version\"]\nvalue_flags = []\ncredential_files = [\"auth.json\"]\n",
		strconv.Quote(f.bot.Name))
	fmt.Fprintf(&b, "sandbox_bin = %s\ntimeout = \"30s\"\nmax_output = 65536\nmax_calls_per_hour = 5\n",
		strconv.Quote(filepath.Join(f.dir, "missing-bwrap")))
	f.writeTools(t, b.String())
	code, out := f.coi(t, "fake", "--version")
	if code != 1 || !strings.Contains(out, "sandbox is not available") || f.ran() {
		t.Fatalf("sandbox %d %q ran=%v", code, out, f.ran())
	}
	raw := string(mustRead(t, f.audit))
	if !strings.Contains(raw, `"event":"coi_sandbox_unavailable"`) {
		t.Fatalf("audit:\n%s", raw)
	}
	ev, err := f.app.st.ListLog(f.bot.ID, "coi_sandbox_unavailable", "", 10)
	if err != nil || len(ev) == 0 {
		t.Fatalf("log %v %d", err, len(ev))
	}
}

func TestCOIAuditRedactsSecretArg(t *testing.T) {
	f := setupCOI(t, 5, nil)
	f.manual()
	code, out := f.coi(t, "fake", "--model", coiSecret)
	if code != 0 || strings.Contains(out, coiSecret) {
		t.Fatalf("call %d %q", code, out)
	}
	logs := f.logs(t)
	if len(logs) != 1 {
		t.Fatalf("logs %+v", logs)
	}
	blob, err := json.Marshal(logs[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), coiSecret) || strings.Contains(string(blob), f.cred) {
		t.Fatalf("log leaked secret: %s", blob)
	}
	args, _ := logs[0]["args"].([]any)
	if len(args) != 2 || args[0] != "--model" || args[1] != "[redacted]" {
		t.Fatalf("args %+v", logs[0]["args"])
	}
	raw := string(mustRead(t, f.audit))
	assertClean(t, raw, f.cred)
}

func TestCOIDeniesJailCredentialsWithoutOptIn(t *testing.T) {
	f := setupCOI(t, 1, nil)
	f.manual()
	f.writeTools(t, f.entry("fake", f.bin, f.cred, f.bots, 1)+"fixed_args = [\"--always-approve\"]\n")
	code, out := f.coi(t, "fake", "--version")
	if code != 1 || !strings.Contains(out, "jail credentials are not allowed") || f.ran() {
		t.Fatalf("opt-in %d %q ran=%v", code, out, f.ran())
	}
	logs := f.logs(t)
	if len(logs) == 0 || logs[0]["error"] != "jail credentials are not allowed" {
		t.Fatalf("log %+v", logs)
	}
	f.writeTools(t, f.entry("fake", f.bin, f.cred, f.bots, 1))
	f.clearRan(t)
	code, out = f.coi(t, "fake", "--version")
	if code != 0 || !strings.Contains(out, coi.PlaceholderToken) || strings.Contains(out, coiSecret) || !f.ran() {
		t.Fatalf("follow-up %d %q ran=%v", code, out, f.ran())
	}
}

func TestCOIProxyUnavailableDoesNotRun(t *testing.T) {
	f := setupCOI(t, 1, nil)
	f.manual()
	f.writeTools(t, f.entry("fake", f.bin, f.cred, f.bots, 1)+"proxy_hosts = [\"api.test\"]\n")
	code, out := f.coi(t, "fake", "--version")
	if code != 1 || !strings.Contains(out, "proxy is not available") || f.ran() {
		t.Fatalf("proxy %d %q ran=%v", code, out, f.ran())
	}
	raw := string(mustRead(t, f.audit))
	if !strings.Contains(raw, `"event":"coi_proxy_unavailable"`) {
		t.Fatal("audit missing coi_proxy_unavailable")
	}
	assertClean(t, raw, f.cred)
	assertClean(t, out, f.cred)
	ev, err := f.app.st.ListLog(f.bot.ID, "coi_proxy_unavailable", "", 10)
	if err != nil || len(ev) == 0 {
		t.Fatalf("log %v %d", err, len(ev))
	}
	f.writeTools(t, f.entry("fake", f.bin, f.cred, f.bots, 1))
	f.clearRan(t)
	code, out = f.coi(t, "fake", "--version")
	if code != 0 || !f.ran() {
		t.Fatalf("slot consumed %d %q ran=%v", code, out, f.ran())
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
