package permbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGolden_PerBotWorkspaceIsolation(t *testing.T) {
	e := testEngine(t)
	root := t.TempDir()
	dirA := filepath.Join(root, "bots", "A")
	dirB := filepath.Join(root, "bots", "B")
	if err := os.MkdirAll(dirA, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dirB, 0o755); err != nil {
		t.Fatal(err)
	}
	fileA := filepath.Join(dirA, "a.txt")
	fileB := filepath.Join(dirB, "b.txt")
	if err := os.WriteFile(fileA, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fileB, []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.SetBotContext("B", dirB, nil)
	e.SnapshotBot("B")

	outside := e.Evaluate(context.Background(), bashCmd("B", dirB, root, "git diff -- "+fileA))
	if outside.Eligible || outside.Verdict == VerdictAllow {
		t.Fatalf("bot A path is inside bot B: %+v", outside)
	}
	inside := e.Evaluate(context.Background(), bashCmd("B", dirB, root, "git diff -- "+fileB))
	if !inside.Eligible || inside.Level != LevelLow {
		t.Fatalf("bot B path is outside: %+v", inside)
	}
	readA := e.Evaluate(context.Background(), readReq("B", dirB, root, fileA))
	if Rank(readA.Level) < Rank(LevelHigh) {
		t.Fatalf("read of the other bot stayed low: %+v", readA)
	}
	readB := e.Evaluate(context.Background(), readReq("B", dirB, root, fileB))
	if readB.Level != LevelLow {
		t.Fatalf("read of this bot: %+v", readB)
	}
}

func TestGolden_RiskyGitConfigHardAsk(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		allow  bool
		apply  func(ws, home, userHome string) []string
	}{
		{name: "core.hooksPath", reason: "core.hooksPath", apply: func(ws, _, _ string) []string {
			writeGit(t, ws, "[core]\n\thooksPath = x\n")
			return nil
		}},
		{name: "core.fsmonitor", reason: "core.fsmonitor", apply: func(ws, _, _ string) []string {
			writeGit(t, ws, "[core]\n\tfsmonitor = x\n")
			return nil
		}},
		{name: "core.sshCommand", reason: "core.sshCommand", apply: func(ws, _, _ string) []string {
			writeGit(t, ws, "[core]\n\tsshCommand = x\n")
			return nil
		}},
		{name: "core.pager", reason: "core.pager", apply: func(ws, _, _ string) []string {
			writeGit(t, ws, "[core]\n\tpager = x\n")
			return nil
		}},
		{name: "core.editor", reason: "core.editor", apply: func(_, home, _ string) []string {
			mustWrite(t, filepath.Join(home, ".gitconfig"), "[core]\n\teditor = x\n")
			return nil
		}},
		{name: "diff.external", reason: "diff.external", apply: func(ws, _, _ string) []string {
			writeGit(t, ws, "[diff]\n\texternal = x\n")
			return nil
		}},
		{name: "credential.helper", reason: "credential.helper", apply: func(_, _, userHome string) []string {
			mustWrite(t, filepath.Join(userHome, ".config", "git", "config"), "[credential]\n\thelper = store\n")
			return nil
		}},
		{name: "filter", reason: "filter", apply: func(ws, _, _ string) []string {
			writeGit(t, ws, "[filter \"lfs\"]\n\tsmudge = x\n")
			return nil
		}},
		{name: "attributes-filter", reason: "filter", apply: func(ws, _, _ string) []string {
			mustWrite(t, filepath.Join(ws, ".gitattributes"), "* filter=x\n")
			return nil
		}},
		{name: "include", reason: "include", apply: func(ws, _, _ string) []string {
			writeGit(t, ws, "[include]\n\tpath = missing.gitconfig\n")
			return nil
		}},
		{name: "include-file", reason: "core.hooksPath", apply: func(ws, _, _ string) []string {
			mustWrite(t, filepath.Join(ws, ".git", "nested.gitconfig"), "[core]\n\thooksPath = x\n")
			writeGit(t, ws, "[include]\n\tpath = nested.gitconfig\n")
			return nil
		}},
		{name: "includeIf", reason: "core.fsmonitor", apply: func(ws, _, _ string) []string {
			mustWrite(t, filepath.Join(ws, ".git", "when.gitconfig"), "[core]\n\tfsmonitor = x\n")
			writeGit(t, ws, "[includeIf \"gitdir:.\"]\n\tpath = when.gitconfig\n")
			return nil
		}},
		{name: "env", reason: "core.hooksPath", apply: func(_, _, _ string) []string {
			return []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=core.hooksPath", "GIT_CONFIG_VALUE_0=x"}
		}},
		{name: "author-env", allow: true, apply: func(_, _, _ string) []string {
			return []string{"GIT_AUTHOR_NAME=hooksPath"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := testEngine(t)
			ws, home, userHome := riskyRepo(t, e)
			req := shellReq("Bash", "git status")
			req.Cwd = ws
			req.Workspace = ws
			if d := e.Evaluate(context.Background(), req); d.Verdict != VerdictAllow {
				t.Fatalf("clean %+v", d)
			}
			env := tc.apply(ws, home, userHome)
			e.SetBotRuntime("bot", home, userHome, env)
			d := e.Evaluate(context.Background(), req)
			if tc.allow {
				if d.Verdict != VerdictAllow {
					t.Fatalf("benign env %+v", d)
				}
				return
			}
			if d.Verdict == VerdictAllow || d.Level == LevelCritical || d.PendingID == "" {
				t.Fatalf("ask %+v", d)
			}
			for _, scope := range []string{ScopeTask, ScopeBot, ScopeGlobal} {
				if err := e.Decide(d.PendingID, "approve", scope); err != ErrScope {
					t.Fatalf("scope %s %v", scope, err)
				}
			}
			if err := e.Decide(d.PendingID, "approve", ScopeOnce); err != nil {
				t.Fatal(err)
			}
			again := e.Evaluate(context.Background(), req)
			if again.Verdict == VerdictAllow {
				t.Fatalf("once token allowed %+v", again)
			}
			body, err := os.ReadFile(filepath.Join(e.dir, "audit.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), "git config "+tc.reason) {
				t.Fatalf("audit missing %s\n%s", tc.reason, body)
			}
			run := shellReq("run_shell", "git status")
			run.Cwd = ws
			run.Workspace = ws
			if got := e.Evaluate(context.Background(), run); got.Verdict == VerdictAllow || got.PendingID == "" {
				t.Fatalf("run_shell %+v", got)
			}
		})
	}
}

func TestGolden_RunShellRiskyGit(t *testing.T) {
	e := testEngine(t)
	ws, home, userHome := riskyRepo(t, e)
	req := shellReq("run_shell", "git status")
	req.Cwd = ws
	req.Workspace = ws
	if d := e.Evaluate(context.Background(), req); d.Verdict != VerdictAllow {
		t.Fatalf("clean %+v", d)
	}
	writeGit(t, ws, "[core]\n\thooksPath = x\n")
	e.SetBotRuntime("bot", home, userHome, nil)
	d := e.Evaluate(context.Background(), req)
	if d.Verdict == VerdictAllow || d.Level == LevelCritical || d.PendingID == "" {
		t.Fatalf("ask %+v", d)
	}
	if err := e.Decide(d.PendingID, "approve", ScopeOnce); err != nil {
		t.Fatal(err)
	}
	again := e.Evaluate(context.Background(), req)
	if again.Verdict == VerdictAllow {
		t.Fatalf("once token allowed %+v", again)
	}
	body, err := os.ReadFile(filepath.Join(e.dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "git config core.hooksPath") {
		t.Fatalf("audit\n%s", body)
	}
	e.SetBotRuntime("bot", home, userHome, []string{"GIT_AUTHOR_NAME=hooksPath"})
	mustWrite(t, filepath.Join(ws, ".git", "config"), "[core]\n\trepositoryformatversion = 0\n")
	benign := shellReq("run_shell", "git status")
	benign.Cwd = ws
	benign.Workspace = ws
	if got := e.Evaluate(context.Background(), benign); got.Verdict != VerdictAllow {
		t.Fatalf("benign %+v", got)
	}
}

func TestGolden_GitProtectedPaths(t *testing.T) {
	e := testEngine(t)
	botHome := t.TempDir()
	userHome := t.TempDir()
	e.SetBotRuntime("bot", botHome, userHome, nil)
	paths := []string{
		".git/info/attributes",
		".git/info/exclude",
		".gitmodules",
		filepath.Join(botHome, ".config", "git", "config"),
		filepath.Join(userHome, ".config", "git", "config"),
	}
	for _, p := range paths {
		d := e.Evaluate(context.Background(), shellReq("Bash", "touch "+p))
		if d.Verdict == VerdictAllow || Rank(d.Level) < Rank(LevelHigh) {
			t.Fatalf("%s %+v", p, d)
		}
	}
	if d := e.Evaluate(context.Background(), shellReq("Bash", "git status")); d.Level == LevelCritical {
		t.Fatalf("git status %+v", d)
	}
}

type allowClassifier struct{}

func (allowClassifier) Escalate(context.Context, ClassInput) (Level, string) { return "", "" }
func (allowClassifier) Allow(context.Context, ClassInput) bool               { return true }

func TestGolden_ClassifierAllowNeedsPerBotContext(t *testing.T) {
	e := testEngine(t)
	e.SetClassifier(allowClassifier{})
	if e.ClassifierMayAllow("bot") {
		t.Fatal("guard is true without per-bot context")
	}
	req := shellReq("Bash", "git status")
	if d := e.Evaluate(context.Background(), req); d.Verdict == VerdictAllow {
		t.Fatalf("classifier allow %+v", d)
	}
	ws := t.TempDir()
	e.SetBotContext("bot", ws, nil)
	if e.ClassifierMayAllow("bot") {
		t.Fatal("guard is true without a git baseline")
	}
	e.SnapshotBot("bot")
	if !e.ClassifierMayAllow("bot") {
		t.Fatal("guard is false with per-bot context and a git baseline")
	}
	if d := e.Evaluate(context.Background(), req); d.Verdict == VerdictAllow {
		t.Fatalf("classifier allow with context %+v", d)
	}
}

func TestGolden_ApprovalTTL(t *testing.T) {
	e := testEngine(t)
	start := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	now := start
	e.now = func() time.Time { return now }
	ctx := context.Background()
	req := shellReq("Bash", "git status")

	first := e.Evaluate(ctx, req)
	if err := e.Decide(first.PendingID, "approve", ScopeOnce); err != nil {
		t.Fatal(err)
	}
	now = start.Add(DefaultApprovalTTL)
	if d := e.Evaluate(ctx, req); d.Verdict == VerdictAllow {
		t.Fatalf("once token still valid at ttl %+v", d)
	}

	// The clock stays forward so the expired token is not valid again.
	alive := e.Evaluate(ctx, req)
	if err := e.Decide(alive.PendingID, "approve", ScopeOnce); err != nil {
		t.Fatal(err)
	}
	born := now
	now = born.Add(DefaultApprovalTTL - time.Second)
	if d := e.Evaluate(ctx, req); d.Verdict != VerdictAllow {
		t.Fatalf("once token expired early %+v", d)
	}

	now = born.Add(DefaultApprovalTTL)
	e.NoteUserMessage("bot", "task")
	task := e.Evaluate(ctx, req)
	if err := e.Decide(task.PendingID, "approve", ScopeTask); err != nil {
		t.Fatal(err)
	}
	granted := now
	now = granted.Add(DefaultApprovalTTL - time.Second)
	if d := e.Evaluate(ctx, req); d.Verdict != VerdictAllow {
		t.Fatalf("task grant expired early %+v", d)
	}
	now = granted.Add(DefaultApprovalTTL)
	if d := e.Evaluate(ctx, req); d.Verdict == VerdictAllow {
		t.Fatalf("task grant outlived ttl %+v", d)
	}

	e.NoteUserMessage("bot", "later")
	req.TaskID = "later"
	pending := e.Evaluate(ctx, req)
	if pending.PendingID == "" {
		t.Fatal(pending)
	}
	now = now.Add(48 * time.Hour)
	again := e.Evaluate(ctx, req)
	if again.PendingID != pending.PendingID {
		t.Fatalf("pending expired %+v", again)
	}
}

func TestGolden_OnceTokenCwdCanonical(t *testing.T) {
	e := testEngine(t)
	root := t.TempDir()
	work := filepath.Join(root, "work")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(work, link); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "other")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	variants := []string{
		work + string(filepath.Separator),
		filepath.Join(work, "."),
		filepath.Join(root, "work", "..", "work"),
		link,
	}
	for _, cwd := range variants {
		req := bashReq("bot", "sess", "task", work, "git status")
		first := e.Evaluate(ctx, req)
		if err := e.Decide(first.PendingID, "approve", ScopeOnce); err != nil {
			t.Fatal(err)
		}
		req.Cwd = cwd
		if d := e.Evaluate(ctx, req); d.Verdict != VerdictAllow {
			t.Fatalf("cwd %s %+v", cwd, d)
		}
	}
	req := bashReq("bot", "sess", "task", work, "git status")
	first := e.Evaluate(ctx, req)
	if err := e.Decide(first.PendingID, "approve", ScopeOnce); err != nil {
		t.Fatal(err)
	}
	req.Cwd = other
	if d := e.Evaluate(ctx, req); d.Verdict == VerdictAllow {
		t.Fatalf("different dir %+v", d)
	}
}

func TestGolden_LegacyRuleMigration(t *testing.T) {
	e := testEngine(t)
	ws := t.TempDir()
	notes := filepath.Join(ws, "notes.txt")
	if err := os.WriteFile(notes, []byte("n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srcPath := filepath.Join(t.TempDir(), "user-permissions.json")
	original := []byte("Bash(git status)\nBash(git diff*)\n")
	if err := os.WriteFile(srcPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	rules := []LegacyRule{
		{BotID: "bot", Effect: EffectAllow, Text: "Bash(git status)"},
		{BotID: "bot", Effect: EffectAllow, Text: "Bash(git diff*)"},
		{BotID: "bot", Effect: EffectAllow, Text: "Bash(git diff -- *)"},
		{BotID: "bot", Effect: EffectDeny, Text: "Bash(git log **)"},
		{BotID: "bot", Effect: EffectAllow, Text: "Bash(gh **)"},
		{BotID: "bot", Effect: EffectAllow, Text: "Bash(git diff * --stat)"},
	}
	if err := e.MigrateLegacy(rules); err != nil {
		t.Fatal(err)
	}
	if e.RuleCount() != len(rules) || e.Ruleset() != 1 {
		t.Fatalf("count %d ruleset %d", e.RuleCount(), e.Ruleset())
	}
	body, err := os.ReadFile(filepath.Join(e.dir, "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{`"kind": "exact"`, `"kind": "pattern"`, `"kind": "legacy"`} {
		if !strings.Contains(string(body), kind) {
			t.Fatalf("missing %s\n%s", kind, body)
		}
	}
	if !strings.Contains(string(body), `"source": "migrated"`) || !strings.Contains(string(body), `"readonly": true`) {
		t.Fatalf("record %s", body)
	}
	if !strings.Contains(string(body), `"active": false`) || !strings.Contains(string(body), `"needs_confirm": true`) {
		t.Fatalf("inactive allow not stored\n%s", body)
	}
	if err := e.MigrateLegacy(rules); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(filepath.Join(e.dir, "rules.json"))
	if err != nil || !bytes.Equal(body, again) {
		t.Fatal("second migration changed rules.json")
	}
	kept, err := os.ReadFile(srcPath)
	if err != nil || string(kept) != string(original) {
		t.Fatalf("source changed %q", kept)
	}
	audit, err := os.ReadFile(filepath.Join(e.dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(audit), `"actor":"migrated"`) != len(rules) {
		t.Fatalf("audit %s", audit)
	}

	ctx := context.Background()
	status := bashReq("bot", "sess", "task", ws, "git status")
	if d := e.Evaluate(ctx, status); d.Verdict != VerdictAllow {
		t.Fatalf("exact %+v", d)
	}
	diff := bashReq("bot", "sess", "task", ws, "git diff")
	if d := e.Evaluate(ctx, diff); d.Verdict == VerdictAllow || d.PendingID == "" {
		t.Fatalf("legacy allow still active %+v", d)
	}
	stat := bashReq("bot", "sess", "task", ws, "git diff --stat")
	if d := e.Evaluate(ctx, stat); d.Verdict == VerdictAllow {
		t.Fatalf("pattern covered extra argv %+v", d)
	}
	compound := bashReq("bot", "sess", "task", ws, "git diff && true")
	if d := e.Evaluate(ctx, compound); d.Verdict == VerdictAllow {
		t.Fatalf("pattern covered compound %+v", d)
	}
	legacy := bashReq("bot", "sess", "task", ws, "git diff -- notes.txt")
	if d := e.Evaluate(ctx, legacy); d.Verdict == VerdictAllow || d.PendingID == "" {
		t.Fatalf("legacy allow still active %+v", d)
	}
	legacyCompound := bashReq("bot", "sess", "task", ws, "git diff -- notes.txt && true")
	if d := e.Evaluate(ctx, legacyCompound); d.Verdict == VerdictAllow {
		t.Fatalf("legacy compound %+v", d)
	}
	narrow := bashReq("bot", "sess", "task", ws, "git diff HEAD --stat")
	if d := e.Evaluate(ctx, narrow); d.Verdict == VerdictAllow || d.PendingID == "" {
		t.Fatalf("pattern allow still active %+v", d)
	}
	slash := bashReq("bot", "sess", "task", ws, "git diff a/b --stat")
	if d := e.Evaluate(ctx, slash); d.Verdict == VerdictAllow {
		t.Fatalf("pattern matched a path token %+v", d)
	}
	flag := bashReq("bot", "sess", "task", ws, "git diff -p --stat")
	if d := e.Evaluate(ctx, flag); d.Verdict == VerdictAllow {
		t.Fatalf("pattern matched a flag %+v", d)
	}
	denied := bashReq("bot", "sess", "task", ws, "git log --oneline")
	if d := e.Evaluate(ctx, denied); d.Verdict != VerdictDeny || d.PendingID != "" {
		t.Fatalf("deny %+v", d)
	}
	crit := bashReq("bot", "sess", "task", ws, "gh auth token")
	if d := e.Evaluate(ctx, crit); d.Verdict == VerdictAllow || d.Level != LevelCritical {
		t.Fatalf("critical allow %+v", d)
	}

	if err := e.MigrateLegacy(rules); err != nil {
		t.Fatal(err)
	}
	if e.RuleCount() != len(rules) || e.Ruleset() != 1 {
		t.Fatalf("second count %d ruleset %d", e.RuleCount(), e.Ruleset())
	}
	audit2, err := os.ReadFile(filepath.Join(e.dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(audit2), `"actor":"migrated"`) != len(rules) {
		t.Fatal("second migration wrote audit rows")
	}
}

func bashCmd(bot, cwd, ws, cmd string) Request {
	raw, _ := json.Marshal(map[string]string{"command": cmd})
	return Request{
		BotID: bot, SessionID: "sess", RunID: "run", TaskID: "task",
		Cwd: cwd, Workspace: ws, ToolName: "Bash", ToolInput: raw,
	}
}

func readReq(bot, cwd, ws, path string) Request {
	raw, _ := json.Marshal(map[string]string{"file_path": path})
	return Request{
		BotID: bot, SessionID: "sess", RunID: "run", TaskID: "task",
		Cwd: cwd, Workspace: ws, ToolName: "Read", ToolInput: raw,
	}
}

func riskyRepo(t *testing.T, e *Engine) (ws, home, userHome string) {
	t.Helper()
	ws = t.TempDir()
	home = t.TempDir()
	userHome = t.TempDir()
	if err := os.Mkdir(filepath.Join(ws, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(ws, ".git", "config"), "[core]\n\trepositoryformatversion = 0\n")
	e.SetBotContext("bot", ws, nil)
	e.SetBotRuntime("bot", home, userHome, nil)
	e.SnapshotBot("bot")
	if _, err := e.SaveRule(Rule{Effect: EffectAllow, Argv: []string{"git", "status"}, Tool: ToolShell, Scope: ScopeBot, BotID: "bot"}); err != nil {
		t.Fatal(err)
	}
	return ws, home, userHome
}

func writeGit(t *testing.T, ws, body string) {
	t.Helper()
	mustWrite(t, filepath.Join(ws, ".git", "config"), body)
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
