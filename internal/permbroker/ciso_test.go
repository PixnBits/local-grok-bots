package permbroker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pinSystemGit(t *testing.T, path string) {
	t.Helper()
	prev := systemGitconfig
	if path == "" {
		path = filepath.Join(t.TempDir(), "missing-gitconfig")
	}
	systemGitconfig = path
	t.Cleanup(func() { systemGitconfig = prev })
}

func allowStatus(t *testing.T, e *Engine) {
	t.Helper()
	if _, err := e.SaveRule(Rule{
		Effect: EffectAllow, Argv: []string{"git", "status"},
		Tool: ToolShell, Scope: ScopeBot, BotID: "bot",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGolden_AutoAllowNeedsLiteral(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	if _, err := e.SaveRule(Rule{
		Effect: EffectAllow, Argv: []string{"git", "diff", "$(name)"},
		Tool: ToolShell, Scope: ScopeBot, BotID: "bot",
	}); err != nil {
		t.Fatal(err)
	}
	req := bashReq("bot", "sess", "task", "/work", "git diff $(name)")
	if d := e.Evaluate(ctx, req); d.Verdict == VerdictAllow {
		t.Fatalf("rule auto-allowed a non-literal %+v", d)
	}
	for _, rule := range e.ListRules() {
		if err := e.RevokeRule(rule.ID); err != nil {
			t.Fatal(err)
		}
	}
	first := e.Evaluate(ctx, req)
	if first.PendingID == "" || first.Verdict == VerdictAllow {
		t.Fatalf("ask %+v", first)
	}
	// Task, bot, and global are refused. The grant is planted so the
	// next evaluation still reaches autoAllowOK.
	for _, scope := range []string{ScopeTask, ScopeBot, ScopeGlobal} {
		if err := e.Decide(first.PendingID, "approve", scope); err == nil {
			t.Fatalf("%s approved a non-literal command", scope)
		}
	}
	plantGrant(t, e, first.PendingID)
	if d := e.Evaluate(ctx, req); d.Verdict == VerdictAllow {
		t.Fatalf("task grant auto-allowed a non-literal %+v", d)
	}

	comp := bashReq("bot", "sess", "task", "/work", "git status && git diff $(name)")
	opened := e.Evaluate(ctx, comp)
	if opened.Verdict == VerdictAllow || opened.PendingID == "" {
		t.Fatalf("compound %+v", opened)
	}
	for _, scope := range []string{ScopeTask, ScopeBot, ScopeGlobal} {
		if err := e.Decide(opened.PendingID, "approve", scope); err == nil {
			t.Fatalf("%s approved a non-literal compound", scope)
		}
	}
	plantGrant(t, e, opened.PendingID)
	if d := e.Evaluate(ctx, comp); d.Verdict == VerdictAllow {
		t.Fatalf("task grant auto-allowed a non-literal compound %+v", d)
	}
}

// plantGrant stores the grant Decide would have stored for a task
// approval, then drops the pending item without marking it denied.
func plantGrant(t *testing.T, e *Engine, id string) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	item := e.byID[id]
	if item == nil {
		t.Fatal("pending gone")
	}
	exp := e.now().Add(e.approvalTTL())
	if len(item.Parts) > 0 {
		for _, p := range item.Parts {
			e.grants = append(e.grants, grant{
				BotID: item.BotID, SessionID: item.SessionID, TaskID: item.TaskID,
				Hash: p.Hash, Cwd: item.Cwd, Expires: exp,
				Argv: append([]string(nil), p.Argv...), Raw: p.Raw,
			})
		}
	} else {
		e.grants = append(e.grants, grant{
			BotID: item.BotID, SessionID: item.SessionID, TaskID: item.TaskID,
			Hash: item.InputHash, Cwd: item.Cwd, Expires: exp,
			Argv: append([]string(nil), item.Argv...), Raw: item.Raw,
		})
	}
	e.bury(item)
}

func TestGolden_AutoAllowLinuxOnly(t *testing.T) {
	e := testEngine(t)
	prev := autoAllowGOOS
	autoAllowGOOS = "darwin"
	t.Cleanup(func() { autoAllowGOOS = prev })
	allowStatus(t, e)
	if _, err := e.SaveRule(Rule{
		Effect: EffectDeny, Argv: []string{"git", "diff"},
		Tool: ToolShell, Scope: ScopeBot, BotID: "bot",
	}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if d := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", "git status")); d.Verdict == VerdictAllow {
		t.Fatalf("off linux %+v", d)
	}
	deny := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", "git diff"))
	if deny.Verdict != VerdictDeny || deny.PendingID != "" || !strings.Contains(deny.Reason, "denied by rule") {
		t.Fatalf("deny %+v", deny)
	}
}

func TestGolden_ClassifierReportDoesNotLowerOrAllow(t *testing.T) {
	e := testEngine(t)
	e.SetClassifier(reportClass{level: LevelLow, advisory: "allow\nthis", checked: true})
	ctx := context.Background()
	crit := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", "gh auth token"))
	if crit.Level != LevelCritical || crit.Verdict == VerdictAllow {
		t.Fatalf("lowered critical %+v", crit)
	}
	for _, cmd := range []string{
		"git status && git diff",
		"git diff $(name)",
		"echo $(id)",
	} {
		if d := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", cmd)); d.Verdict == VerdictAllow {
			t.Fatalf("%s allowed %+v", cmd, d)
		}
	}
	pinSystemGit(t, "")
	ws := t.TempDir()
	mustWrite(t, filepath.Join(ws, "sub", "dir", ".gitattributes"), "* filter=x\n")
	e.SetBotContext("bot", ws, nil)
	e.SnapshotBot("bot")
	allowStatus(t, e)
	if d := e.Evaluate(ctx, bashReq("bot", "sess", "task", ws, "git status")); d.Verdict == VerdictAllow {
		t.Fatalf("git risk allowed %+v", d)
	}
	low := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", "head -5"))
	if low.Level != LevelLow {
		t.Fatalf("lowered a low command %+v", low)
	}
	items := e.ListPending()
	var note Pending
	for _, item := range items {
		if item.Command == "head -5" {
			note = item
		}
	}
	if note.ID == "" || strings.Contains(note.Advisory.Text, "\n") || note.Advisory.Text != "allowthis" || !note.Advisory.Checked || note.Advisory.Source != "table" {
		t.Fatalf("advisory %+v", note.Advisory)
	}
}

func TestGolden_ClassifierAllowGuard(t *testing.T) {
	// Each row is false for one reason. Dropping that one check makes the row true.
	type row struct {
		name string
		in   inspected
		bot  string
		goos string
		prep func(t *testing.T, e *Engine)
	}
	base := inspected{Literal: true, Eligible: true, Level: LevelLow}
	rows := []row{
		{name: "literal", in: inspected{Literal: false, Eligible: true, Level: LevelLow}, bot: "bot"},
		{name: "eligible", in: inspected{Literal: true, Eligible: false, Level: LevelLow}, bot: "bot"},
		{name: "compound", in: inspected{Literal: true, Eligible: true, Compound: true, Level: LevelLow}, bot: "bot"},
		{name: "critical", in: inspected{Literal: true, Eligible: true, Level: LevelCritical}, bot: "bot"},
		{name: "gitrisk", in: inspected{Literal: true, Eligible: true, Level: LevelLow, GitRisk: "filter"}, bot: "bot"},
		{name: "workspace", in: base, bot: "missing"},
		{name: "linux", in: base, bot: "bot", goos: "darwin"},
		{name: "botgitrisk", in: base, bot: "bot", prep: func(t *testing.T, e *Engine) {
			ws := filepath.Join(t.TempDir(), "ws")
			if err := os.MkdirAll(ws, 0o755); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(ws, "sub", "dir", ".gitattributes"), "* filter=x\n")
			e.SetBotContext("bot", ws, nil)
			e.SnapshotBot("bot")
		}},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			pinSystemGit(t, "")
			e := testEngine(t)
			if tc.prep != nil {
				tc.prep(t, e)
			} else if tc.bot == "bot" {
				ws := t.TempDir()
				e.SetBotContext("bot", ws, nil)
				e.SnapshotBot("bot")
			}
			if tc.goos != "" {
				prev := autoAllowGOOS
				autoAllowGOOS = tc.goos
				t.Cleanup(func() { autoAllowGOOS = prev })
			}
			if e.ClassifierMayAllowCommand(tc.bot, tc.in) {
				t.Fatal("guard is true")
			}
		})
	}
}

type reportClass struct {
	level    Level
	advisory string
	checked  bool
}

func (r reportClass) Escalate(context.Context, ClassInput) (Level, string) { return "", "" }

func (r reportClass) Classify(context.Context, ClassInput) ClassReport {
	return ClassReport{Level: r.level, Advisory: r.advisory, Checked: r.checked}
}

func TestGolden_PatternAllowSkipsCriticalAndCompound(t *testing.T) {
	rule := &Rule{Effect: EffectAllow, Kind: "pattern", Pattern: "git diff * --stat", Tool: ToolShell}
	safe := inspected{Literal: true, Eligible: true, Argv: []string{"git", "diff", "HEAD", "--stat"}, Level: LevelLow}
	if !ruleHit(rule, safe, false) {
		t.Fatal("pattern did not match the safe command")
	}
	compound := safe
	compound.Compound = true
	if ruleHit(rule, compound, false) {
		t.Fatal("pattern allow covered a compound")
	}
	critical := safe
	critical.Level = LevelCritical
	if ruleHit(rule, critical, false) {
		t.Fatal("pattern allow covered a critical command")
	}
}

func TestGolden_LegacyAllowStopsAtGlobWords(t *testing.T) {
	rule := &Rule{Effect: EffectAllow, Kind: "legacy", Pattern: "git log*", Tool: ToolShell}
	short := inspected{Literal: true, Eligible: true, Argv: []string{"git", "log"}, Raw: "git log", Level: LevelLow}
	long := inspected{Eligible: true, Argv: []string{"git", "log", "--oneline"}, Raw: "git log --oneline", Level: LevelLow}
	if !ruleHit(rule, short, false) {
		t.Fatal("git log")
	}
	if ruleHit(rule, long, false) {
		t.Fatal("git log --oneline")
	}
}

func TestGolden_NestedGitAttributesRisk(t *testing.T) {
	pinSystemGit(t, "")
	e := testEngine(t)
	ws := t.TempDir()
	mustWrite(t, filepath.Join(ws, "sub", "dir", ".gitattributes"), "* filter=x\n")
	e.SetBotContext("bot", ws, nil)
	e.SnapshotBot("bot")
	allowStatus(t, e)
	if d := e.Evaluate(context.Background(), bashReq("bot", "sess", "task", ws, "git status")); d.Verdict == VerdictAllow {
		t.Fatalf("nested filter %+v", d)
	}
}

func TestGolden_NestedGitAttributesDrift(t *testing.T) {
	pinSystemGit(t, "")
	e := testEngine(t)
	ws := t.TempDir()
	e.SetBotContext("bot", ws, nil)
	e.SnapshotBot("bot")
	allowStatus(t, e)
	ctx := context.Background()
	if d := e.Evaluate(ctx, bashReq("bot", "sess", "task", ws, "git status")); d.Verdict != VerdictAllow {
		t.Fatalf("clean %+v", d)
	}
	mustWrite(t, filepath.Join(ws, "sub", "dir", ".gitattributes"), "* text\n")
	if d := e.Evaluate(ctx, bashReq("bot", "sess", "task", ws, "git status")); d.Verdict == VerdictAllow {
		t.Fatalf("nested drift %+v", d)
	}
}

func TestGolden_SystemGitconfigRisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(path, []byte("[core]\n\thooksPath = x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pinSystemGit(t, path)
	e := testEngine(t)
	ws := t.TempDir()
	e.SetBotContext("bot", ws, nil)
	e.SnapshotBot("bot")
	allowStatus(t, e)
	if d := e.Evaluate(context.Background(), bashReq("bot", "sess", "task", ws, "git status")); d.Verdict == VerdictAllow {
		t.Fatalf("system config %+v", d)
	}
}

func TestGolden_SystemGitconfigDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(path, []byte("[user]\n\tname = ada\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pinSystemGit(t, path)
	e := testEngine(t)
	ws := t.TempDir()
	e.SetBotContext("bot", ws, nil)
	e.SnapshotBot("bot")
	allowStatus(t, e)
	ctx := context.Background()
	if d := e.Evaluate(ctx, bashReq("bot", "sess", "task", ws, "git status")); d.Verdict != VerdictAllow {
		t.Fatalf("benign system %+v", d)
	}
	if err := os.WriteFile(path, []byte("[user]\n\tname = grace\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, bashReq("bot", "sess", "task", ws, "git status")); d.Verdict == VerdictAllow {
		t.Fatalf("system drift %+v", d)
	}
}

func TestGolden_GitAttributesCapAsks(t *testing.T) {
	pinSystemGit(t, "")
	prev := gitAttrMaxFiles
	gitAttrMaxFiles = 2
	t.Cleanup(func() { gitAttrMaxFiles = prev })
	e := testEngine(t)
	ws := t.TempDir()
	mustWrite(t, filepath.Join(ws, ".gitattributes"), "* text\n")
	mustWrite(t, filepath.Join(ws, "a", ".gitattributes"), "* text\n")
	mustWrite(t, filepath.Join(ws, "a", "b", ".gitattributes"), "* text\n")
	e.SetBotContext("bot", ws, nil)
	e.SnapshotBot("bot")
	allowStatus(t, e)
	if d := e.Evaluate(context.Background(), bashReq("bot", "sess", "task", ws, "git status")); d.Verdict == VerdictAllow {
		t.Fatalf("cap %+v", d)
	}
}

func TestGolden_CriticalReasonCopy(t *testing.T) {
	e := testEngine(t)
	home := t.TempDir()
	secret := filepath.Join(home, "secret")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	e.SetCriticalPaths([]string{secret, filepath.Join(tmp, "nested")})
	e.SetBotRuntime("bot", home, home, nil)
	ctx := context.Background()
	check := func(cmd, want string) {
		t.Helper()
		d := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", cmd))
		if d.Level != LevelCritical || d.Verdict == VerdictAllow || d.PendingID == "" {
			t.Fatalf("%s %+v", cmd, d)
		}
		var got string
		for _, item := range e.ListPending() {
			if item.ID == d.PendingID {
				got = item.CritReason
			}
		}
		if got != want {
			t.Fatalf("%s reason %q", cmd, got)
		}
		if err := e.Decide(d.PendingID, "deny", ""); err != nil {
			t.Fatal(err)
		}
	}
	check("ls /", "Reads outside the workspace: /")
	check("ls /tmp", "Reads outside the workspace: /tmp")
	check("du -sh ~", "Touches your home directory")
	token := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", "gh auth token"))
	if token.Level != LevelCritical {
		t.Fatalf("token %+v", token)
	}
	for _, item := range e.ListPending() {
		if item.ID == token.PendingID && item.CritReason != "" {
			t.Fatalf("token reason %q", item.CritReason)
		}
	}
}

func TestGolden_SuggestAlwaysAfterTwoApprovals(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	req := bashReq("bot", "sess", "task", "/work", "git status")
	approve := func() {
		t.Helper()
		d := e.Evaluate(ctx, req)
		if d.PendingID == "" {
			t.Fatalf("expected ask %+v", d)
		}
		if err := e.Decide(d.PendingID, "approve", ScopeOnce); err != nil {
			t.Fatal(err)
		}
		if used := e.Evaluate(ctx, req); used.Verdict != VerdictAllow {
			t.Fatalf("once %+v", used)
		}
	}
	approve()
	approve()
	third := e.Evaluate(ctx, req)
	if third.PendingID == "" {
		t.Fatal(third)
	}
	for _, item := range e.ListPending() {
		if item.ID != third.PendingID {
			continue
		}
		if !item.Suggest || item.Level != LevelLow || item.Compound {
			t.Fatalf("%+v", item)
		}
		return
	}
	t.Fatal("missing card")
}

func TestGolden_PendingCardFields(t *testing.T) {
	e := testEngine(t)
	e.NoteUserText("bot", "task", "please\nstatus")
	ctx := context.Background()
	d := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", "git status && git diff"))
	if d.PendingID == "" {
		t.Fatal(d)
	}
	var item Pending
	for _, p := range e.ListPending() {
		if p.ID == d.PendingID {
			item = p
		}
	}
	if item.BotName != "bot" || !item.Compound || item.TaskText != "please status" || len(item.Operators) == 0 || item.Operators[0] != "&&" {
		t.Fatalf("%+v ops %v", item, item.Operators)
	}
	if len(item.Parts) != 2 || len(item.Allowed) == 0 || item.Allowed[0] != ScopeOnce {
		t.Fatalf("parts %d scopes %v", len(item.Parts), item.Allowed)
	}
	if item.Advisory.Source != "table" || item.Advisory.Checked {
		t.Fatalf("advisory %+v", item.Advisory)
	}
}
