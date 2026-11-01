package permbroker

import (
	"context"
	"os"
	"strings"
	"testing"
)

func readAudit(t *testing.T, e *Engine) string {
	t.Helper()
	b, err := os.ReadFile(e.dir + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func policyCount(raw, decision, pending string) int {
	n := 0
	for _, line := range strings.Split(raw, "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, `"actor":"policy"`) && strings.Contains(line, `"decision":"`+decision+`"`) && strings.Contains(line, `"pending_id":"`+pending+`"`) {
			n++
		}
	}
	return n
}

// TestGolden_ResumeEvalBindIsOneShot fails if the critical bind can allow
// a second ResumeEval. The delete in consumeBind is the guard. markConsumed
// is not involved.
func TestGolden_ResumeEvalBindIsOneShot(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	req := bashReq("bot", "sess", "task", "/work", "gh auth token")
	req.Origin = OriginNative
	first := e.Evaluate(ctx, req)
	if first.Verdict == VerdictAllow || first.PendingID == "" || first.Level != LevelCritical {
		t.Fatalf("%+v", first)
	}
	if err := e.Decide(first.PendingID, "approve", ScopeOnce); err != nil {
		t.Fatal(err)
	}
	if len(e.tokens) != 0 {
		t.Fatalf("once-token %d", len(e.tokens))
	}
	allowed := e.ResumeEval(ctx, req, first.PendingID)
	if allowed.Verdict != VerdictAllow {
		t.Fatalf("resume %+v", allowed)
	}
	second := e.ResumeEval(ctx, req, first.PendingID)
	if second.Verdict == VerdictAllow {
		t.Fatalf("second resume %+v", second)
	}
	raw := readAudit(t, e)
	if policyCount(raw, "ask", first.PendingID) < 1 {
		t.Fatal("ask was not audited")
	}
	if n := policyDecisions(raw, "deny"); n != 1 {
		t.Fatalf("resume without a bind audited %d deny rows\n%s", n, raw)
	}
}

func policyDecisions(raw, decision string) int {
	n := 0
	for _, line := range strings.Split(raw, "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, `"actor":"policy"`) && strings.Contains(line, `"decision":"`+decision+`"`) {
			n++
		}
	}
	return n
}

// TestGolden_ApproveAllCriticalIsBindNotToken fails if approve-all stores
// a once-token for a native critical item. takeToken still refuses critical,
// so the check is the engine state and a second ResumeEval.
func TestGolden_ApproveAllCriticalIsBindNotToken(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	req := bashReq("bot", "sess", "task", "/work", "gh auth token")
	req.Origin = OriginNative
	first := e.Evaluate(ctx, req)
	if first.Level != LevelCritical || first.PendingID == "" {
		t.Fatalf("%+v", first)
	}
	rep, err := e.ApproveAll([]string{first.PendingID})
	if err != nil || rep.OKCount != 1 || !rep.Results[0].OK {
		t.Fatalf("%v %+v", err, rep)
	}
	if len(e.tokens) != 0 {
		t.Fatalf("once-token %d", len(e.tokens))
	}
	if _, ok := e.binds[first.PendingID]; !ok {
		t.Fatal("critical bind missing")
	}
	plain := e.Evaluate(ctx, req)
	if plain.Verdict == VerdictAllow {
		t.Fatalf("plain evaluate %+v", plain)
	}
	allowed := e.ResumeEval(ctx, req, first.PendingID)
	if allowed.Verdict != VerdictAllow {
		t.Fatalf("resume %+v", allowed)
	}
	second := e.ResumeEval(ctx, req, first.PendingID)
	if second.Verdict == VerdictAllow {
		t.Fatalf("second resume %+v", second)
	}
}

// TestGolden_ApproveAllHookCriticalRejectsOnce fails if approve-all accepts
// scope once for a hook-originated critical item.
func TestGolden_ApproveAllHookCriticalRejectsOnce(t *testing.T) {
	e := testEngine(t)
	req := bashReq("bot", "sess", "task", "/work", "gh auth token")
	req.Origin = OriginHook
	first := e.Evaluate(context.Background(), req)
	if first.Level != LevelCritical || first.PendingID == "" || first.Verdict == VerdictAllow {
		t.Fatalf("%+v", first)
	}
	rep, err := e.ApproveAll([]string{first.PendingID})
	if err != nil || len(rep.Results) != 1 || rep.Results[0].OK || rep.Results[0].Error != ErrScope.Error() {
		t.Fatalf("%v %+v", err, rep)
	}
	if len(e.tokens) != 0 || len(e.binds) != 0 {
		t.Fatalf("tokens %d binds %d", len(e.tokens), len(e.binds))
	}
	if err := e.Decide(first.PendingID, "deny", ""); err != nil {
		t.Fatal(err)
	}
}

// TestAskAuditsAskNotDeny fails if the pre-suspend row is recorded as a deny.
func TestAskAuditsAskNotDeny(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	req := bashReq("bot", "sess", "task", "/work", "git status")
	first := e.Evaluate(ctx, req)
	if first.PendingID == "" || first.Verdict != VerdictDeny {
		t.Fatalf("%+v", first)
	}
	again := e.Evaluate(ctx, req)
	if again.PendingID != first.PendingID {
		t.Fatalf("collapse %+v", again)
	}
	raw := readAudit(t, e)
	if policyCount(raw, "ask", first.PendingID) < 2 {
		t.Fatalf("ask rows %s", raw)
	}
	if policyCount(raw, "deny", first.PendingID) != 0 {
		t.Fatalf("ask audited as deny %s", raw)
	}
}
