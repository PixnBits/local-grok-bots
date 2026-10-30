package permbroker

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := Open(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.resolver = fakeBinary
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func fakeBinary(argv0 string) (string, bool) {
	base := baseName(argv0)
	if !binaryAllowed(base) {
		return "", false
	}
	if strings.ContainsAny(argv0, `/\`) {
		if !filepath.IsAbs(argv0) || filepath.Base(argv0) != base {
			return "", false
		}
	}
	return "/usr/bin/" + base, true
}

func bashReq(bot, session, task, cwd, cmd string) Request {
	raw, _ := json.Marshal(map[string]string{"command": cmd})
	return Request{
		BotID: bot, SessionID: session, RunID: "run", TaskID: task,
		Cwd: cwd, ToolName: "Bash", ToolInput: raw,
	}
}

func TestGolden_AskApproveRetryOnce(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	req := bashReq("bot", "sess", "task", "/work", "git status")
	first := e.Evaluate(ctx, req)
	if first.Verdict != VerdictDeny || first.PendingID == "" || !strings.Contains(first.Reason, "pending approval "+first.PendingID) {
		t.Fatalf("%+v", first)
	}
	again := e.Evaluate(ctx, req)
	if again.PendingID != first.PendingID || again.Verdict != VerdictDeny {
		t.Fatalf("collapse %+v", again)
	}
	if err := e.Decide(first.PendingID, "approve", ScopeOnce); err != nil {
		t.Fatal(err)
	}
	allowed := e.Evaluate(ctx, req)
	if allowed.Verdict != VerdictAllow || allowed.Actor != "human" {
		t.Fatalf("retry %+v", allowed)
	}
	second := e.Evaluate(ctx, req)
	if second.Verdict == VerdictAllow {
		t.Fatalf("second retry allowed %+v", second)
	}
	if second.PendingID == "" {
		t.Fatal("second retry did not ask again")
	}
}

func TestGolden_SecondRetryDifferentArgvCwdSessionBlocked(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	req := bashReq("bot", "sess", "task", "/work", "git status")
	first := e.Evaluate(ctx, req)
	if err := e.Decide(first.PendingID, "approve", ScopeOnce); err != nil {
		t.Fatal(err)
	}
	otherArgv := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", "git status --short"))
	otherCwd := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/elsewhere", "git status"))
	otherSess := e.Evaluate(ctx, bashReq("bot", "other", "task", "/work", "git status"))
	for _, d := range []Decision{otherArgv, otherCwd, otherSess} {
		if d.Verdict == VerdictAllow {
			t.Fatalf("mismatched retry allowed %+v", d)
		}
	}
	same := e.Evaluate(ctx, req)
	if same.Verdict != VerdictAllow {
		t.Fatalf("matching retry %+v", same)
	}
	if again := e.Evaluate(ctx, req); again.Verdict == VerdictAllow {
		t.Fatalf("token reused %+v", again)
	}
}

func TestGolden_CriticalAndCompoundCannotBeRules(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	crit := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", "gh auth token"))
	if crit.Level != LevelCritical || crit.Verdict == VerdictAllow {
		t.Fatalf("%+v", crit)
	}
	for _, scope := range []string{ScopeTask, ScopeBot, ScopeGlobal} {
		if err := e.Decide(crit.PendingID, "approve", scope); err != ErrScope {
			t.Fatalf("scope %s err %v", scope, err)
		}
	}
	if err := e.Decide(crit.PendingID, "approve", ScopeOnce); err != nil {
		t.Fatal(err)
	}
	if e.RuleCount() != 0 {
		t.Fatal("critical became a rule")
	}

	comp := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", "git status && git diff"))
	if comp.Eligible || !comp.Compound || comp.Verdict == VerdictAllow {
		t.Fatalf("%+v", comp)
	}
	if err := e.Decide(comp.PendingID, "approve", ScopeBot); err != ErrScope {
		t.Fatal(err)
	}
	if err := e.Decide(comp.PendingID, "approve", ScopeGlobal); err != ErrScope {
		t.Fatal(err)
	}
	if err := e.Decide(comp.PendingID, "approve", ScopeTask); err != nil {
		t.Fatal(err)
	}
	if got := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", "git status && git diff")); got.Verdict != VerdictAllow {
		t.Fatalf("task grant %+v", got)
	}
	if e.RuleCount() != 0 {
		t.Fatal("compound became a rule")
	}
}

func TestGolden_ClassifierOnlyEscalates(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	e.SetClassifier(fixedLevel(LevelLow))
	crit := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", "gh auth token"))
	if crit.Level != LevelCritical || crit.Verdict == VerdictAllow {
		t.Fatalf("classifier lowered critical %+v", crit)
	}
	e.SetClassifier(fixedLevel(LevelCritical))
	low := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", "git status"))
	if low.Level != LevelCritical {
		t.Fatalf("classifier did not escalate %+v", low)
	}
	if err := e.Decide(low.PendingID, "approve", ScopeBot); err != ErrScope {
		t.Fatalf("escalated command became a rule: %v", err)
	}
	if low.Verdict == VerdictAllow {
		t.Fatal("classifier allowed")
	}
}

type fixedLevel Level

func (f fixedLevel) Escalate(context.Context, ClassInput) (Level, string) {
	return Level(f), "classifier"
}

func TestGolden_JailSocketCannotApproveOrCreateRules(t *testing.T) {
	e := testEngine(t)
	e.NoteTurn("bot", "sess", "run", "task")
	sock := filepath.Join(t.TempDir(), "dir", "sock")
	ln, err := e.Listen("bot", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	before := e.Ruleset()
	for _, op := range []string{"approve", "deny", "create-rule", "list", "list-rules", "revoke"} {
		rep := sockRound(t, sock, map[string]any{"op": op, "id": "p_x"})
		if rep.Verdict != VerdictDeny {
			t.Fatalf("op %s %+v", op, rep)
		}
	}
	if e.Ruleset() != before || e.RuleCount() != 0 || len(e.ListPending()) != 0 {
		t.Fatal("socket changed broker state")
	}
	rep := sockRound(t, sock, map[string]any{
		"op": "evaluate", "hook_event_name": "PreToolUse",
		"session_id": "liar", "cwd": "/work", "tool_name": "Bash",
		"tool_input": map[string]string{"command": "git status"},
	})
	if rep.Verdict != VerdictDeny || !strings.Contains(rep.Reason, "pending approval ") {
		t.Fatalf("evaluate %+v", rep)
	}
	if len(e.ListPending()) != 1 {
		t.Fatalf("pending %+v", e.ListPending())
	}
	saved, err := e.SaveRule(Rule{Effect: EffectAllow, Argv: []string{"git", "status"}, Tool: ToolShell, Scope: ScopeBot, BotID: "bot"})
	if err != nil {
		t.Fatal(err)
	}
	beforeSet, beforeCount := e.Ruleset(), e.RuleCount()
	rev := sockRound(t, sock, map[string]any{"op": "revoke", "id": saved.ID})
	listed := sockRound(t, sock, map[string]any{"op": "list-rules"})
	if rev.Verdict != VerdictDeny || listed.Verdict != VerdictDeny {
		t.Fatalf("socket revoke %+v list %+v", rev, listed)
	}
	if e.Ruleset() != beforeSet || e.RuleCount() != beforeCount {
		t.Fatal("socket revoke changed rules")
	}
	if e.ListRules()[0].ID != saved.ID {
		t.Fatal("socket removed a rule")
	}
}

func openAuditEngine(t *testing.T) (*Engine, string) {
	t.Helper()
	dir := t.TempDir()
	e, err := Open(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.resolver = fakeBinary
	t.Cleanup(func() { _ = e.Close() })
	return e, dir
}

func readPermAudit(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func decodeAudit(t *testing.T, raw string) []AuditRow {
	t.Helper()
	var rows []AuditRow
	for _, line := range strings.Split(strings.TrimRight(raw, "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row AuditRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	return rows
}

func checkAuditChain(t *testing.T, rows []AuditRow) {
	t.Helper()
	prev := ""
	for i, row := range rows {
		if row.PrevHash != prev || len(row.Hash) != 64 {
			t.Fatalf("row %d prev %q hash %q", i, row.PrevHash, row.Hash)
		}
		prev = row.Hash
	}
}

func humanDecision(t *testing.T, rows []AuditRow, pending, decision string) AuditRow {
	t.Helper()
	var found *AuditRow
	for i := range rows {
		row := &rows[i]
		if row.Actor == "human" && row.Decision == decision && row.PendingID == pending {
			if found != nil {
				t.Fatalf("duplicate %s %s", decision, pending)
			}
			found = row
		}
	}
	if found == nil {
		t.Fatalf("missing %s for %s", decision, pending)
	}
	return *found
}

func humanDenyCount(rows []AuditRow) int {
	n := 0
	for _, row := range rows {
		if row.Actor == "human" && row.Decision == "deny" {
			n++
		}
	}
	return n
}

func ruleSaveAudited(rows []AuditRow, scope string) bool {
	for _, row := range rows {
		if row.Actor == "human" && row.Decision == EffectAllow && row.Scope == scope && row.RuleID != "" && row.TableVersion == TableVersion {
			return true
		}
	}
	return false
}

func sockRound(t *testing.T, sock string, msg any) wireReply {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := json.NewEncoder(c).Encode(msg); err != nil {
		t.Fatal(err)
	}
	if uc, ok := c.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	var rep wireReply
	if err := json.NewDecoder(c).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestDenyDoesNotCreateAnotherPending(t *testing.T) {
	e := testEngine(t)
	req := bashReq("bot", "sess", "task", "/work", "echo no")
	first := e.Evaluate(context.Background(), req)
	if err := e.Decide(first.PendingID, "deny", ""); err != nil {
		t.Fatal(err)
	}
	second := e.Evaluate(context.Background(), req)
	if second.Verdict != VerdictDeny || second.PendingID != "" {
		t.Fatalf("after deny %+v", second)
	}
}

func TestApproveAuditedBeforeRetry(t *testing.T) {
	const secret = "ghp_abcdefghijklmnopqrstuvwxyz"
	e, dir := openAuditEngine(t)
	ctx := context.Background()
	req := bashReq("bot", "sess", "task", "/work", "echo "+secret)
	first := e.Evaluate(ctx, req)
	if first.PendingID == "" || first.Verdict == VerdictAllow {
		t.Fatalf("%+v", first)
	}
	if err := e.Decide(first.PendingID, "approve", ScopeOnce); err != nil {
		t.Fatal(err)
	}
	raw := readPermAudit(t, dir)
	if strings.Contains(raw, secret) {
		t.Fatal("audit kept a secret")
	}
	rows := decodeAudit(t, raw)
	checkAuditChain(t, rows)
	for _, row := range rows {
		if row.Decision == VerdictAllow {
			t.Fatal("allow was written before retry")
		}
	}
	row := humanDecision(t, rows, first.PendingID, "approve")
	if row.Actor != "human" || row.Scope != ScopeOnce || row.BotID != "bot" || row.SessionID != "sess" || row.Cwd != "/work" || row.InputHash == "" || row.InputHash != first.InputHash || row.Level == "" || row.TableVersion != TableVersion || row.RulesetVersion != e.Ruleset() {
		t.Fatalf("%+v", row)
	}
	if got := e.Evaluate(ctx, req); got.Verdict != VerdictAllow {
		t.Fatalf("retry %+v", got)
	}
}

func TestApproveScopesAreAudited(t *testing.T) {
	for _, scope := range []string{ScopeOnce, ScopeTask, ScopeBot, ScopeGlobal} {
		t.Run(scope, func(t *testing.T) {
			e, dir := openAuditEngine(t)
			req := bashReq("bot", "sess", "task", "/work", "git status")
			first := e.Evaluate(context.Background(), req)
			if first.PendingID == "" || first.Level != LevelLow {
				t.Fatalf("%+v", first)
			}
			before := e.Ruleset()
			if err := e.Decide(first.PendingID, "approve", scope); err != nil {
				t.Fatal(err)
			}
			rows := decodeAudit(t, readPermAudit(t, dir))
			checkAuditChain(t, rows)
			row := humanDecision(t, rows, first.PendingID, "approve")
			if row.Actor != "human" || row.Scope != scope || row.BotID != "bot" || row.SessionID != "sess" || row.Cwd != "/work" || row.InputHash != first.InputHash || row.Level != LevelLow || row.TableVersion != TableVersion || row.RulesetVersion != e.Ruleset() {
				t.Fatalf("%+v", row)
			}
			if scope != ScopeBot && scope != ScopeGlobal {
				return
			}
			if e.Ruleset() != before+1 || e.RuleCount() != 1 || !ruleSaveAudited(rows, scope) {
				t.Fatalf("ruleset %d rules %d", e.Ruleset(), e.RuleCount())
			}
		})
	}
}

func TestDenyAllAuditsEachItem(t *testing.T) {
	t.Run("deny", func(t *testing.T) {
		e, dir := openAuditEngine(t)
		first := e.Evaluate(context.Background(), bashReq("bot", "sess", "task", "/work", "echo no"))
		if first.PendingID == "" {
			t.Fatal(first)
		}
		if err := e.Decide(first.PendingID, "deny", ""); err != nil {
			t.Fatal(err)
		}
		rows := decodeAudit(t, readPermAudit(t, dir))
		row := humanDecision(t, rows, first.PendingID, "deny")
		if row.Actor != "human" || row.BotID != "bot" || row.SessionID != "sess" || row.Cwd != "/work" || row.InputHash != first.InputHash || row.Level == "" || row.TableVersion != TableVersion || row.RulesetVersion != e.Ruleset() {
			t.Fatalf("%+v", row)
		}
	})
	t.Run("deny-all", func(t *testing.T) {
		e, dir := openAuditEngine(t)
		one := e.Evaluate(context.Background(), bashReq("bot", "sess", "task", "/work", "echo one"))
		two := e.Evaluate(context.Background(), bashReq("bot", "sess", "task", "/work", "echo two"))
		if one.PendingID == "" || two.PendingID == "" || one.PendingID == two.PendingID {
			t.Fatalf("%+v %+v", one, two)
		}
		if err := e.DenyAll([]string{one.PendingID, "missing"}); err != ErrNotFound {
			t.Fatalf("partial %v", err)
		}
		if len(e.ListPending()) != 2 {
			t.Fatal("partial deny changed pending")
		}
		early := decodeAudit(t, readPermAudit(t, dir))
		if humanDenyCount(early) != 0 {
			t.Fatal("partial deny wrote an audit row")
		}
		if err := e.DenyAll(nil); err != nil {
			t.Fatal(err)
		}
		rows := decodeAudit(t, readPermAudit(t, dir))
		checkAuditChain(t, rows)
		for _, id := range []string{one.PendingID, two.PendingID} {
			row := humanDecision(t, rows, id, "deny")
			if row.Actor != "human" || row.BotID != "bot" || row.SessionID != "sess" || row.Cwd != "/work" || row.InputHash == "" || row.Level == "" || row.TableVersion != TableVersion || row.RulesetVersion != e.Ruleset() {
				t.Fatalf("%s %+v", id, row)
			}
		}
		if humanDenyCount(rows) != 2 {
			t.Fatalf("human deny rows %d", humanDenyCount(rows))
		}
	})
}

func TestCancelledApprovalIsRefused(t *testing.T) {
	e := testEngine(t)
	first := e.Evaluate(context.Background(), bashReq("bot", "sess", "task", "/work", "echo x"))
	e.CancelSession("bot", "sess")
	if err := e.Decide(first.PendingID, "approve", ScopeOnce); err != ErrStale {
		t.Fatalf("err %v", err)
	}
}

func TestPolicyRaiseAndLower(t *testing.T) {
	if err := ValidateRisk([]RiskEntry{{Tool: "shell", Argv: []string{"git", "status"}, Level: LevelUnclassified}}); err != ErrLevelLowered && (err == nil || !strings.Contains(err.Error(), ErrLevelLowered.Error())) {
		t.Fatalf("lower: %v", err)
	}
	if err := ValidateRisk([]RiskEntry{{Tool: "shell", Argv: []string{"git", "status"}, Level: LevelHigh}}); err != nil {
		t.Fatal(err)
	}
	e, err := Open(t.TempDir(), []RiskEntry{{Tool: "shell", Argv: []string{"echo", "ok"}, Level: LevelHigh}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	d := e.Evaluate(context.Background(), bashReq("bot", "sess", "t", "/work", "echo ok"))
	if d.Level != LevelHigh {
		t.Fatalf("%+v", d)
	}
	if err := e.SetRisks([]RiskEntry{{Tool: "shell", Argv: []string{"git", "status"}, Level: LevelLow}}); err == nil {
		// equal to shipped is allowed
	}
	if err := e.SetRisks([]RiskEntry{{Tool: "shell", Argv: []string{"git", "push"}, Level: LevelLow}}); err == nil {
		t.Fatal("lowered git push")
	}
	if err := ValidateRisk([]RiskEntry{{Tool: "shell", Argv: []string{"git", "push", "origin"}, Level: LevelLow}}); err == nil {
		t.Fatal("lowered git push origin")
	}
	if err := ValidateRisk([]RiskEntry{{Tool: "shell", Argv: []string{"gh", "pr", "view"}, Level: LevelUnclassified}}); err == nil {
		t.Fatal("lowered gh pr view")
	}
	if err := ValidateRisk([]RiskEntry{{Tool: "shell", Argv: []string{"gh", "auth", "token"}, Level: LevelHigh}}); err == nil {
		t.Fatal("lowered gh auth token")
	}
}

func TestRedactSecrets(t *testing.T) {
	got := Redact("curl -H 'Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz' --token=sekrit password=hunter2 gho_abcdefghijklmnopqrstuvwxyz")
	for _, secret := range []string{"ghp_", "gho_", "sekrit", "hunter2", "Bearer "} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %s in %s", secret, got)
		}
	}
}
