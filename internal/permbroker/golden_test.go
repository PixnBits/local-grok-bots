package permbroker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func shellReq(tool, cmd string) Request {
	raw, _ := json.Marshal(map[string]string{"command": cmd})
	return Request{
		BotID: "bot", SessionID: "sess", RunID: "run", TaskID: "task",
		Cwd: "/work", Workspace: "/work", Repos: []string{"acme/widgets"},
		ToolName: tool, ToolInput: raw,
	}
}

func plantLiterals(t *testing.T, e *Engine) {
	t.Helper()
	literals := [][]string{
		{"git", "status"},
		{"git", "diff"},
		{"git", "log", "--oneline"},
		{"head", "-5"},
		{"gh", "pr", "view", "1"},
	}
	for _, argv := range literals {
		if _, err := e.SaveRule(Rule{
			Effect: EffectAllow, Argv: argv, Tool: ToolShell, Scope: ScopeBot, BotID: "bot",
		}); err != nil {
			t.Fatalf("plant %q: %v", argv, err)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	exp := e.now().Add(TaskGrantCap)
	for _, argv := range literals {
		e.grants = append(e.grants, grant{
			BotID: "bot", SessionID: "sess", TaskID: "task",
			Hash: hashParts(ToolShell, argv), Cwd: "/work", Expires: exp,
		})
	}
}

func tripwire(e *Engine, cmd string) {
	parsed := ParseCommand(cmd)
	e.mu.Lock()
	defer e.mu.Unlock()
	exp := e.now().Add(TaskGrantCap)
	add := func(argv []string) {
		if len(argv) == 0 {
			return
		}
		e.rules.Rules = append(e.rules.Rules, Rule{
			ID: "raw", Effect: EffectAllow, Argv: append([]string(nil), argv...),
			Tool: ToolShell, Scope: ScopeBot, BotID: "bot",
		})
		e.grants = append(e.grants, grant{
			BotID: "bot", SessionID: "sess", TaskID: "task",
			Hash: hashParts(ToolShell, argv), Cwd: "/work", Expires: exp,
		})
	}
	add(parsed.Argv)
	for _, p := range parsed.Parts {
		add(p.Argv)
	}
	for _, tool := range []string{"Bash", "run_shell"} {
		e.grants = append(e.grants, grant{
			BotID: "bot", SessionID: "sess", TaskID: "task",
			Hash: hashRaw(tool, cmd), Cwd: "/work", Expires: exp,
		})
	}
}

func TestGolden_ParseBypass(t *testing.T) {
	e := testEngine(t)
	plantLiterals(t, e)
	for _, cmd := range bypassCorpus {
		t.Run(bypassName(cmd), func(t *testing.T) {
			tripwire(e, cmd)
			for _, tool := range []string{"Bash", "run_shell"} {
				d := e.Evaluate(context.Background(), shellReq(tool, cmd))
				if d.Verdict == VerdictAllow {
					t.Fatalf("%s allowed %q %+v", tool, cmd, d)
				}
			}
		})
	}
}

func bypassName(cmd string) string {
	s := strings.ReplaceAll(cmd, "\r", "CR")
	s = strings.ReplaceAll(s, "\n", "NL")
	if len(s) > 48 {
		s = s[:48]
	}
	return s
}

func TestGolden_ExactRuleAllowsLiteral(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	git := shellReq("Bash", "git status")
	if d := e.Evaluate(ctx, git); d.Verdict == VerdictAllow || d.Level != LevelLow || !d.Eligible {
		t.Fatalf("without rule %+v", d)
	}
	if _, err := e.SaveRule(Rule{Effect: EffectAllow, Argv: []string{"git", "status"}, Tool: ToolShell, Scope: ScopeBot, BotID: "bot"}); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, git); d.Verdict != VerdictAllow {
		t.Fatalf("bash %+v", d)
	}
	if d := e.Evaluate(ctx, shellReq("run_shell", "git status")); d.Verdict != VerdictAllow {
		t.Fatalf("run_shell %+v", d)
	}
	gh := shellReq("Bash", "gh pr view 1")
	if d := e.Evaluate(ctx, gh); d.Verdict == VerdictAllow {
		t.Fatalf("gh without rule %+v", d)
	}
	if _, err := e.SaveRule(Rule{Effect: EffectAllow, Argv: []string{"gh", "pr", "view", "1"}, Tool: ToolShell, Scope: ScopeBot, BotID: "bot"}); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, gh); d.Verdict != VerdictAllow || d.Level != LevelLow {
		t.Fatalf("gh %+v", d)
	}
	other := shellReq("Bash", "gh pr view 1 -R other/repo")
	if d := e.Evaluate(ctx, other); d.Verdict == VerdictAllow || d.Eligible {
		t.Fatalf("other repo %+v", d)
	}
}

func TestGolden_TaskGrantCoversEveryPart(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	cmd := "git log --oneline | head -5"
	req := shellReq("Bash", cmd)
	if d := e.Evaluate(ctx, req); d.Verdict == VerdictAllow || !d.Compound {
		t.Fatalf("ungranted %+v", d)
	}
	grantArgv(e, []string{"git", "log", "--oneline"})
	if d := e.Evaluate(ctx, req); d.Verdict == VerdictAllow {
		t.Fatalf("partial %+v", d)
	}
	grantArgv(e, []string{"head", "-5"})
	if d := e.Evaluate(ctx, req); d.Verdict != VerdictAllow {
		t.Fatalf("full %+v", d)
	}
	plain := shellReq("run_shell", "git log --oneline")
	if d := e.Evaluate(ctx, plain); d.Verdict != VerdictAllow {
		t.Fatalf("part alone %+v", d)
	}
}

func TestGolden_TaskGrantExpires(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	start := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	now := start
	e.now = func() time.Time { return now }
	e.NoteUserMessage("bot", "m1")
	req := shellReq("Bash", "git status")
	req.TaskID = "m1"
	first := e.Evaluate(ctx, req)
	if err := e.Decide(first.PendingID, "approve", ScopeTask); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, req); d.Verdict != VerdictAllow {
		t.Fatalf("fresh %+v", d)
	}
	now = start.Add(TaskGrantCap)
	if d := e.Evaluate(ctx, req); d.Verdict == VerdictAllow {
		t.Fatalf("at cap %+v", d)
	}
	now = start.Add(TaskGrantCap - time.Second)
	if d := e.Evaluate(ctx, req); d.Verdict != VerdictAllow {
		t.Fatalf("before cap %+v", d)
	}
	e.NoteUserMessage("bot", "m2")
	req.TaskID = "m2"
	if d := e.Evaluate(ctx, req); d.Verdict == VerdictAllow {
		t.Fatalf("next message %+v", d)
	}
	req.TaskID = "m1"
	if d := e.Evaluate(ctx, req); d.Verdict == VerdictAllow {
		t.Fatalf("old task %+v", d)
	}
}

func TestGolden_CriticalPartAndDenyBeatGrant(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	grantArgv(e, []string{"git", "status"})
	grantArgv(e, []string{"gh", "auth", "token"})
	crit := e.Evaluate(ctx, shellReq("Bash", "git status && gh auth token"))
	if crit.Verdict == VerdictAllow || crit.Level != LevelCritical {
		t.Fatalf("critical part %+v", crit)
	}
	if _, err := e.SaveRule(Rule{Effect: EffectDeny, Argv: []string{"git", "status"}, Tool: ToolShell, Scope: ScopeBot, BotID: "bot"}); err != nil {
		t.Fatal(err)
	}
	grantArgv(e, []string{"git", "status"})
	grantArgv(e, []string{"git", "diff"})
	denied := e.Evaluate(ctx, shellReq("Bash", "git status"))
	if denied.Verdict != VerdictDeny || denied.PendingID != "" {
		t.Fatalf("deny %+v", denied)
	}
	comp := e.Evaluate(ctx, shellReq("Bash", "git status && git diff"))
	if comp.Verdict == VerdictAllow {
		t.Fatalf("deny inside compound %+v", comp)
	}
}

func TestGolden_RulesetBumpCancelsPending(t *testing.T) {
	e := testEngine(t)
	first := e.Evaluate(context.Background(), shellReq("Bash", "git diff"))
	if first.PendingID == "" {
		t.Fatal(first)
	}
	if _, err := e.SaveRule(Rule{Effect: EffectAllow, Argv: []string{"git", "status"}, Tool: ToolShell, Scope: ScopeBot, BotID: "bot"}); err != nil {
		t.Fatal(err)
	}
	if err := e.Decide(first.PendingID, "approve", ScopeOnce); err != ErrStale {
		t.Fatalf("err %v", err)
	}
	b, err := os.ReadFile(filepath.Join(e.dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"table_version":"`+TableVersion+`"`) || !strings.Contains(string(b), "builtin-2026-10-29.2") {
		t.Fatalf("audit %s", b)
	}
}

func TestGolden_NonShellToolsAsk(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	read := e.Evaluate(ctx, toolReq("Read", map[string]any{"file_path": "a.go"}))
	if read.Verdict == VerdictAllow || read.Level != LevelLow {
		t.Fatalf("read %+v", read)
	}
	write := e.Evaluate(ctx, toolReq("Write", map[string]any{"file_path": ".git/config"}))
	if write.Verdict == VerdictAllow || write.Level != LevelCritical {
		t.Fatalf("write %+v", write)
	}
	web := e.Evaluate(ctx, toolReq("WebFetch", map[string]any{"url": "https://example.invalid"}))
	if web.Verdict == VerdictAllow || web.Level != LevelHigh {
		t.Fatalf("web %+v", web)
	}
	mcp := e.Evaluate(ctx, toolReq("mcp__demo__search", map[string]any{}))
	if mcp.Verdict == VerdictAllow || mcp.Level != LevelHigh {
		t.Fatalf("mcp %+v", mcp)
	}
	task := e.Evaluate(ctx, toolReq("Task", map[string]any{"prompt": "look"}))
	if task.Verdict == VerdictAllow || task.Level != LevelHigh {
		t.Fatalf("task %+v", task)
	}
}

func TestGolden_GitBaselineDriftAsks(t *testing.T) {
	e := testEngine(t)
	ws := t.TempDir()
	cfg := filepath.Join(ws, ".git")
	if err := os.Mkdir(cfg, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(cfg, "config")
	if err := os.WriteFile(configPath, []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.SnapshotGit(ws)
	if _, err := e.SaveRule(Rule{Effect: EffectAllow, Argv: []string{"git", "status"}, Tool: ToolShell, Scope: ScopeBot, BotID: "bot"}); err != nil {
		t.Fatal(err)
	}
	req := shellReq("Bash", "git status")
	req.Cwd = ws
	req.Workspace = ws
	if d := e.Evaluate(context.Background(), req); d.Verdict != VerdictAllow {
		t.Fatalf("baseline %+v", d)
	}
	if err := os.WriteFile(configPath, []byte("[core]\n\thooksPath = x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(context.Background(), req); d.Verdict == VerdictAllow {
		t.Fatalf("drift %+v", d)
	}
	run := shellReq("run_shell", "git status")
	run.Cwd = ws
	run.Workspace = ws
	if d := e.Evaluate(context.Background(), run); d.Verdict != VerdictAllow {
		t.Fatalf("daemon git %+v", d)
	}
}

func TestResolvePinnedRejectsUserDir(t *testing.T) {
	if _, ok := resolvePinned(filepath.Join(t.TempDir(), "git")); ok {
		t.Fatal("user directory resolved")
	}
	abs, ok := resolvePinned("git")
	if !ok || filepath.Base(abs) != "git" {
		t.Fatalf("git lookup %q %v", abs, ok)
	}
}

func toolReq(name string, input map[string]any) Request {
	raw, _ := json.Marshal(input)
	return Request{
		BotID: "bot", SessionID: "sess", RunID: "run", TaskID: "task",
		Cwd: "/work", Workspace: "/work", ToolName: name, ToolInput: raw,
	}
}

func grantArgv(e *Engine, argv []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.grants = append(e.grants, grant{
		BotID: "bot", SessionID: "sess", TaskID: "task",
		Hash: hashParts(ToolShell, argv), Cwd: "/work", Expires: e.now().Add(TaskGrantCap),
	})
}

var bypassCorpus = []string{
	"gh pr view 1 && curl x",
	"gh pr view 1; rm -rf ~",
	"gh pr view 1 | sh",
	"git status || sh",
	"git status\ntrue",
	"$(echo gh) pr view",
	"`echo gh` pr view",
	"echo ${X}",
	"echo $((1))",
	"echo <(true)",
	"echo >(true)",
	"echo ~/x",
	"echo {a,b}",
	"echo *.go",
	"echo ?",
	"FOO=1 git status",
	"env git status",
	"command git status",
	"builtin git status",
	"exec git status",
	"eval git status",
	"source x",
	". x",
	"sudo git status",
	"timeout 5 git status",
	"nice git status",
	"xargs git status",
	"find . -exec git status ;",
	"find . -delete",
	"bash -c 'git status'",
	"sh -c 'git status'",
	"python -c 'print(1)'",
	"git status <<EOF\nEOF",
	"git status <<< x",
	"git status > file",
	"git status >> file",
	"git status < /etc/passwd",
	"git status 2> x",
	"git status &",
	"(git status)",
	"{ git status; }",
	"f() { git status; }",
	"git status\r\n",
	"git status\u037e true",
	"git status\uff1b true",
	"git status \uff06 true",
	"git status \uff5c true",
	"git status \u2223 true",
	"git status # x",
	"git status\\\n--short",
	"git -c core.fsmonitor=x status",
	"git --exec-path=x status",
	"git -C /etc status",
	"git --git-dir=/x log",
	"git log --output=x",
	"git diff --ext-diff",
	"git fetch --upload-pack=x",
	"git ls-remote -u x",
	"gh api user",
	"gh alias set x y",
	"gh extension list",
	"gh config set x y",
	"gh auth token",
	"gh secret list",
	"gh pr view 1 -R other/repo",
	"gh nosuch",
	"gh pr view --web",
	"git config user.name x && git status",
	"cd /tmp && git status",
	"export X=1; git status",
	"ln -s a b",
	"git status | tee out",
	"git status | sed -n 1p",
	"git status | awk 1",
	"git status | xargs",
	"git status | git diff",
	"git status | gh pr view 1",
	"grep -f names",
	"jq -f prog",
}
