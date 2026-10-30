package permbroker

import (
	"context"
	"encoding/json"
	"net"
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
	for _, op := range []string{"approve", "deny", "create-rule", "list"} {
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
