package permbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fcc6144Baseline is the piece set written by fcc6144. The test writes
// these bytes itself. It does not call gitBaselineBlobOld.
func fcc6144Baseline(ws string, homes []string) []byte {
	var b strings.Builder
	b.WriteString("v1\n")
	repo, repoOK := readRepoConfig(ws)
	writePiece(&b, "repo-config", repo, repoOK)
	digest := hooksDigest(ws)
	b.WriteString("hooks ")
	b.WriteString(digest)
	if !strings.HasSuffix(digest, "\n") {
		b.WriteByte('\n')
	}
	var infoData []byte
	var infoOK bool
	if dir, ok := gitDir(ws); ok {
		infoData, infoOK = readBaselineFile(filepath.Join(dir, "info", "attributes"))
	}
	writePiece(&b, "info-attributes", infoData, infoOK)
	attr, attrOK := readBaselineFile(filepath.Join(ws, ".gitattributes"))
	writePiece(&b, "gitattributes", attr, attrOK)
	writeHomes(&b, homes)
	return []byte(b.String())
}

func writeOldBaseline(t *testing.T, dir, bot string, blob []byte) {
	t.Helper()
	doc := gitBaselineDoc{Version: 1, Bots: []gitBaselineBot{{ID: bot, Blob: string(blob)}}}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if bytes.Contains(raw, []byte(`"format"`)) || bytes.Contains(blob, []byte("system-gitconfig")) {
		t.Fatalf("fixture is not the old piece set")
	}
	if !bytes.Contains(blob, []byte("gitattributes missing\n")) && !bytes.Contains(blob, []byte("gitattributes ")) {
		t.Fatal("fixture has no gitattributes piece")
	}
	if err := os.WriteFile(filepath.Join(dir, gitBaselineName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGolden_GitBaselineUpgrade(t *testing.T) {
	pinSystemGit(t, "")
	ws, home, userHome := cleanRepo(t)
	homes := []string{home, userHome}
	blob := fcc6144Baseline(ws, homes)
	if bytes.Contains(blob, []byte("system-gitconfig")) {
		t.Fatal("old blob includes system gitconfig")
	}
	dir := t.TempDir()
	writeOldBaseline(t, dir, "bot", blob)
	rules := rulesFile{Version: 1, Rules: []Rule{
		{ID: "r_status", Effect: EffectAllow, Tool: ToolShell, Scope: ScopeBot, BotID: "bot", Kind: "exact", Argv: []string{"git", "status"}},
		{ID: "r_diff", Effect: EffectAllow, Tool: ToolShell, Scope: ScopeGlobal, Kind: "exact", Argv: []string{"git", "diff"}},
	}}
	if err := saveRules(filepath.Join(dir, "rules.json"), rules); err != nil {
		t.Fatal(err)
	}
	e, err := Open(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.resolver = fakeBinary
	t.Cleanup(func() { _ = e.Close() })
	// Daemon boot is SetBotContext, SetBotRuntime, SnapshotBot.
	e.SetBotContext("bot", ws, nil)
	before, err := os.ReadFile(filepath.Join(dir, gitBaselineName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte("system-gitconfig")) {
		t.Fatal("upgraded before homes were known")
	}
	e.SetBotRuntime("bot", home, userHome, nil)
	e.SnapshotBot("bot")
	after, err := os.ReadFile(filepath.Join(dir, gitBaselineName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) || !bytes.Contains(after, []byte("system-gitconfig")) || !bytes.Contains(after, []byte(`"format"`)) {
		t.Fatal("baseline was not re-recorded")
	}
	ctx := context.Background()
	for _, cmd := range []string{"git status", "git diff"} {
		req := bashReq("bot", "sess", "task", ws, cmd)
		req.Workspace = ws
		if d := e.Evaluate(ctx, req); d.Verdict != VerdictAllow {
			t.Fatalf("%s %+v", cmd, d)
		}
	}
	aud, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil || !bytes.Contains(aud, []byte(`"actor":"upgrade"`)) || !bytes.Contains(aud, []byte(`"decision":"upgrade"`)) {
		t.Fatalf("audit %v %s", err, aud)
	}
}

func TestGolden_GitBaselineDriftReason(t *testing.T) {
	pinSystemGit(t, "")
	ws, home, userHome := cleanRepo(t)
	homes := []string{home, userHome}
	blob := fcc6144Baseline(ws, homes)
	if err := os.WriteFile(filepath.Join(ws, ".git", "config"), []byte("[core]\n\trepositoryformatversion = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeOldBaseline(t, dir, "bot", blob)
	e, err := Open(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.resolver = fakeBinary
	t.Cleanup(func() { _ = e.Close() })
	_, err = e.SaveRule(Rule{Effect: EffectAllow, Tool: ToolShell, Scope: ScopeBot, BotID: "bot", Argv: []string{"git", "status"}})
	if err != nil {
		t.Fatal(err)
	}
	e.SetBotContext("bot", ws, nil)
	e.SetBotRuntime("bot", home, userHome, nil)
	e.SnapshotBot("bot")
	req := bashReq("bot", "sess", "task", ws, "git status")
	req.Workspace = ws
	d := e.Evaluate(context.Background(), req)
	if d.Verdict == VerdictAllow || d.PendingID == "" {
		t.Fatalf("%+v", d)
	}
	pending := e.ListPending()
	if len(pending) != 1 || pending[0].GitReason != gitReasonConfig {
		t.Fatalf("%+v", pending)
	}
}

func TestGolden_TaskGrantCwd(t *testing.T) {
	e := testEngine(t)
	ws := t.TempDir()
	req := bashReq("bot", "sess", "task", ws, "grep hi notes.txt")
	first := e.Evaluate(context.Background(), req)
	if first.PendingID == "" {
		t.Fatal(first)
	}
	if err := e.Decide(first.PendingID, "approve", ScopeTask); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(context.Background(), req); d.Verdict != VerdictAllow {
		t.Fatalf("same cwd %+v", d)
	}
	for _, cwd := range []string{
		filepath.Join(ws, "sub"),
		filepath.Dir(ws),
		t.TempDir(),
		ws + string(os.PathSeparator),
		ws + "/./",
	} {
		next := req
		next.Cwd = cwd
		if d := e.Evaluate(context.Background(), next); d.Verdict == VerdictAllow {
			t.Fatalf("cwd %q covered %+v", cwd, d)
		}
	}
}

func TestGolden_TaskGrantDifferentTask(t *testing.T) {
	e := testEngine(t)
	req := bashReq("bot", "sess", "task-a", "/work", "grep hi notes.txt")
	first := e.Evaluate(context.Background(), req)
	if err := e.Decide(first.PendingID, "approve", ScopeTask); err != nil {
		t.Fatal(err)
	}
	in := inspected{Literal: true, Eligible: true, Level: LevelLow, Hash: first.InputHash}
	e.mu.Lock()
	same := e.grantCovers(req, in)
	req.TaskID = "task-b"
	other := e.grantCovers(req, in)
	e.mu.Unlock()
	if !same || other {
		t.Fatalf("same %v other %v", same, other)
	}
}

func TestGolden_NonLiteralOnceOnly(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	for _, cmd := range []string{`grep "$(id -u)" a.txt`, `grep A a.*`} {
		req := bashReq("bot", "sess", "task", "/work", cmd)
		d := e.Evaluate(ctx, req)
		if d.Verdict == VerdictAllow || d.PendingID == "" {
			t.Fatalf("%s %+v", cmd, d)
		}
		var item Pending
		for _, p := range e.ListPending() {
			if p.ID == d.PendingID {
				item = p
			}
		}
		if strings.Join(item.Allowed, ",") != ScopeOnce {
			t.Fatalf("%s scopes %v eligible %v hard %v level %s", cmd, item.Allowed, item.Eligible, item.HardAsk, item.Level)
		}
		for _, scope := range []string{ScopeTask, ScopeBot, ScopeGlobal} {
			if err := e.Decide(d.PendingID, "approve", scope); err == nil {
				t.Fatalf("%s %s allowed", cmd, scope)
			}
		}
		if err := e.Decide(d.PendingID, "approve", ScopeOnce); err != nil {
			t.Fatalf("%s once %v", cmd, err)
		}
	}
}

func TestGolden_LiveAllowGitRisk(t *testing.T) {
	e := testEngine(t)
	in := inspected{Literal: true, Eligible: true, Level: LevelLow, Argv: []string{"grep", "hi", "a.txt"}, GitRisk: "filter"}
	if allowFlex(in) {
		t.Fatal("allowFlex covered a git risk")
	}
	rule, err := e.SaveRule(Rule{Effect: EffectAllow, Scope: ScopeBot, BotID: "bot", Tool: ToolShell, Argv: []string{"grep", "hi", "a.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	d := e.applyRule(bashReq("bot", "sess", "task", "/work", "grep hi a.txt"), in, &rule)
	e.mu.Unlock()
	if d.Verdict == VerdictAllow {
		t.Fatal("applyRule covered a git risk")
	}
	plain := bashReq("bot", "sess", "task", "/work", "grep hi notes.txt")
	first := e.Evaluate(context.Background(), plain)
	if err := e.Decide(first.PendingID, "approve", ScopeTask); err != nil {
		t.Fatal(err)
	}
	covered := inspected{Literal: true, Eligible: true, Level: LevelLow, Hash: first.InputHash}
	e.mu.Lock()
	ok := e.grantCovers(plain, covered)
	risky := covered
	risky.GitRisk = "filter"
	bad := e.grantCovers(plain, risky)
	e.mu.Unlock()
	if !ok || bad {
		t.Fatalf("grant ok %v risk %v", ok, bad)
	}
}

func TestGolden_LiveAllowCritical(t *testing.T) {
	e := testEngine(t)
	in := inspected{Literal: true, Eligible: true, Level: LevelCritical, Argv: []string{"grep", "hi", "a.txt"}}
	if allowFlex(in) {
		t.Fatal("allowFlex covered critical")
	}
	rule, err := e.SaveRule(Rule{Effect: EffectAllow, Scope: ScopeBot, BotID: "bot", Tool: ToolShell, Argv: []string{"grep", "hi", "a.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	d := e.applyRule(bashReq("bot", "sess", "task", "/work", "grep hi a.txt"), in, &rule)
	e.mu.Unlock()
	if d.Verdict == VerdictAllow {
		t.Fatal("applyRule covered critical")
	}
	plain := bashReq("bot", "sess", "task", "/work", "grep hi notes.txt")
	first := e.Evaluate(context.Background(), plain)
	if err := e.Decide(first.PendingID, "approve", ScopeTask); err != nil {
		t.Fatal(err)
	}
	covered := inspected{Literal: true, Eligible: true, Level: LevelLow, Hash: first.InputHash}
	crit := covered
	crit.Level = LevelCritical
	e.mu.Lock()
	ok := e.grantCovers(plain, covered)
	bad := e.grantCovers(plain, crit)
	e.mu.Unlock()
	if !ok || bad {
		t.Fatalf("grant ok %v critical %v", ok, bad)
	}
}

func TestGolden_ClassifierRaiseBlocksBotRule(t *testing.T) {
	pinSystemGit(t, "")
	ctx := context.Background()
	t.Run("exact", func(t *testing.T) {
		e := testEngine(t)
		e.SetClassifier(fixedLevel(LevelHigh))
		if _, err := e.SaveRule(Rule{Effect: EffectAllow, Scope: ScopeBot, BotID: "bot", Tool: ToolShell, Argv: []string{"git", "status"}}); err != nil {
			t.Fatal(err)
		}
		cwd := t.TempDir()
		d := e.Evaluate(ctx, bashReq("bot", "sess", "task", cwd, "git status"))
		if d.Verdict == VerdictAllow || d.Level != LevelHigh {
			t.Fatalf("%+v", d)
		}
	})
	t.Run("pattern", func(t *testing.T) {
		e := testEngine(t)
		e.SetClassifier(fixedLevel(LevelHigh))
		_, err := e.CreateRule(RuleDraft{Kind: "pattern", Pattern: "git diff * --stat", Scope: ScopeBot, BotID: "bot", Effect: EffectAllow})
		if err != nil {
			t.Fatal(err)
		}
		cwd := t.TempDir()
		d := e.Evaluate(ctx, bashReq("bot", "sess", "task", cwd, "git diff HEAD --stat"))
		if d.Verdict == VerdictAllow || d.Level != LevelHigh {
			t.Fatalf("%+v", d)
		}
	})
}

func TestGolden_SymlinkAttrDirAsks(t *testing.T) {
	pinSystemGit(t, "")
	e := testEngine(t)
	ws, home, userHome := cleanRepo(t)
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, ".gitattributes"), []byte("* text\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(ws, "linked")); err != nil {
		t.Fatal(err)
	}
	e.SetBotContext("bot", ws, nil)
	e.SetBotRuntime("bot", home, userHome, nil)
	e.SnapshotBot("bot")
	allowStatus(t, e)
	assertGitAsk(t, e, ws)
	if err := e.RebaselineBot("bot"); err != nil {
		t.Fatal(err)
	}
	assertGitAsk(t, e, ws)
}

func TestGolden_ConfirmNeverMatches(t *testing.T) {
	e := testEngine(t)
	e.mu.Lock()
	e.rules.Rules = append(e.rules.Rules,
		Rule{ID: "r_cat", Effect: EffectAllow, Kind: "legacy", Pattern: "cat *", Tool: ToolShell, Scope: ScopeBot, BotID: "bot", NeedsConfirm: true},
		Rule{ID: "r_log", Effect: EffectAllow, Kind: "pattern", Pattern: "git log * --oneline", Tool: ToolShell, Scope: ScopeBot, BotID: "bot", NeedsConfirm: true},
	)
	e.mu.Unlock()
	views := e.ListRules()
	var cat, log RuleView
	for _, v := range views {
		switch v.ID {
		case "r_cat":
			cat = v
		case "r_log":
			log = v
		}
	}
	if cat.Confirmable || cat.NeverReason == "" {
		t.Fatalf("cat %+v", cat)
	}
	if !log.Confirmable || log.NeverReason != "" {
		t.Fatalf("log %+v", log)
	}
	_, err := e.ConfirmRule("r_cat")
	var input *InputError
	if !errors.As(err, &input) || input.Code != "never_matches" {
		t.Fatalf("confirm cat %v", err)
	}
	if _, err := e.ConfirmRule("r_log"); err != nil {
		t.Fatal(err)
	}
}

func TestGolden_CreateRuleCriticalDeny(t *testing.T) {
	e := testEngine(t)
	argv := []string{"git", "config", "user.name", "x"}
	_, err := e.CreateRule(RuleDraft{Kind: "exact", Argv: argv, Scope: ScopeBot, BotID: "bot", Effect: EffectAllow})
	var input *InputError
	if !errors.As(err, &input) || input.Code != "never_matches" {
		t.Fatalf("allow %v", err)
	}
	_, err = e.CreateRule(RuleDraft{Kind: "pattern", Pattern: "cp * b.txt", Scope: ScopeBot, BotID: "bot", Effect: EffectAllow})
	input = nil
	if !errors.As(err, &input) || input.Code != "never_matches" {
		t.Fatalf("cp %v", err)
	}
	rule, err := e.CreateRule(RuleDraft{Kind: "exact", Argv: argv, Scope: ScopeBot, BotID: "bot", Effect: EffectDeny})
	if err != nil || rule.Effect != EffectDeny {
		t.Fatalf("deny %v %+v", err, rule)
	}
	found := false
	for _, v := range e.ListRules() {
		if v.ID == rule.ID && v.Effect == EffectDeny {
			found = true
		}
	}
	if !found {
		t.Fatal("deny was not stored")
	}
}

func TestGolden_ReplaceKeepsBothWhenRevokeFails(t *testing.T) {
	e := testEngine(t)
	old, err := e.SaveRule(Rule{Effect: EffectAllow, Scope: ScopeBot, BotID: "bot", Tool: ToolShell, Argv: []string{"git", "status"}})
	if err != nil {
		t.Fatal(err)
	}
	e.SetRevokeFailure(errors.New("revoke failed"))
	created, revoked, err := e.ReplaceRule(old.ID, RuleDraft{
		Kind: "exact", Argv: []string{"git", "diff"}, Scope: ScopeBot, BotID: "bot", Effect: EffectAllow,
	})
	if revoked || created == "" || created == old.ID || err == nil || err.Error() != "revoke failed" {
		t.Fatalf("created %s revoked %v err %v", created, revoked, err)
	}
	if e.RuleCount() != 2 {
		t.Fatalf("rules %d", e.RuleCount())
	}
}

func TestGolden_ApproveAllSkipsUnknown(t *testing.T) {
	e := testEngine(t)
	one := e.Evaluate(context.Background(), bashReq("bot", "sess", "task", "/work", "grep hi a.txt"))
	two := e.Evaluate(context.Background(), bashReq("bot", "sess", "task", "/work", "grep hi b.txt"))
	if _, err := e.ApproveAll(nil); err == nil {
		t.Fatal("nil ids approved")
	}
	rep, err := e.ApproveAll([]string{one.PendingID, "missing"})
	if err != nil || rep.OKCount != 1 || rep.Skipped != 1 || rep.Approved != 1 {
		t.Fatalf("%v %+v", err, rep)
	}
	if len(e.ListPending()) != 1 || e.ListPending()[0].ID != two.PendingID {
		t.Fatalf("%+v", e.ListPending())
	}
	again := e.Evaluate(context.Background(), bashReq("bot", "sess", "task", "/work", "grep hi a.txt"))
	if again.Verdict != VerdictAllow {
		t.Fatalf("approved item %+v", again)
	}
}

func TestGolden_SystemGitconfigExecPath(t *testing.T) {
	root := t.TempDir()
	execPath := filepath.Join(root, "lib", "git-core")
	if err := os.MkdirAll(execPath, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(root, "etc", "gitconfig")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := systemGitconfigFromExecPath(execPath); got != cfg {
		t.Fatalf("got %s", got)
	}
	if err := os.Remove(cfg); err != nil {
		t.Fatal(err)
	}
	if got := systemGitconfigFromExecPath(execPath); got != "" {
		t.Fatalf("missing file returned %s", got)
	}
	text := "file:" + cfg + "\tcore.bare=false\n"
	if err := os.WriteFile(cfg, []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := firstSystemGitconfig(text); got != cfg {
		t.Fatalf("parse %s", got)
	}
}
