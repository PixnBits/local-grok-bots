package permbroker

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestStickyAskSkipsOnceToken(t *testing.T) {
	e := testEngine(t)
	start := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	var nano atomic.Int64
	nano.Store(start.UnixNano())
	e.SetClock(func() time.Time { return time.Unix(0, nano.Load()).UTC() })

	req := shellReq("Bash", "git status")
	req.Sticky = true
	req.SessionID = "job:abc"
	first := e.Evaluate(context.Background(), req)
	if first.PendingID == "" || first.Verdict == VerdictAllow {
		t.Fatalf("%+v", first)
	}
	nano.Store(start.Add(DefaultApprovalTTL + time.Second).UnixNano())
	found := false
	for _, item := range e.ListPending() {
		if item.ID == first.PendingID {
			found = true
		}
	}
	if !found {
		t.Fatal("sticky card dropped after the approval ttl")
	}
	if err := e.Decide(first.PendingID, "approve", ScopeOnce); err != nil {
		t.Fatal(err)
	}
	again := e.Evaluate(context.Background(), req)
	if again.Verdict == VerdictAllow || again.PendingID == "" {
		t.Fatalf("once token %+v", again)
	}
}

// A sticky card with a run id is listed immediately. It is not staged
// behind a checkpoint.
func TestStickyCardStaysListed(t *testing.T) {
	e := testEngine(t)
	req := shellReq("Bash", "git status")
	req.Sticky = true
	req.Origin = OriginNative
	req.RunID = "run-1"
	req.SessionID = "job:abc"
	first := e.Evaluate(context.Background(), req)
	if first.PendingID == "" || first.Verdict == VerdictAllow {
		t.Fatalf("%+v", first)
	}
	found := false
	for _, item := range e.ListPending() {
		if item.ID == first.PendingID {
			found = true
			if item.JobID != "abc" {
				t.Fatalf("job id %q", item.JobID)
			}
		}
	}
	if !found {
		t.Fatal("sticky card was hidden")
	}
}

// A sticky approval for this task does not mint a once-token. The next
// task asks again.
func TestStickyTaskScopeSkipsOnceToken(t *testing.T) {
	e := testEngine(t)
	req := shellReq("Bash", "git status")
	req.Sticky = true
	req.SessionID = "job:abc"
	req.Origin = OriginNative
	first := e.Evaluate(context.Background(), req)
	if first.PendingID == "" || first.Verdict == VerdictAllow {
		t.Fatalf("%+v", first)
	}
	var allowed []string
	for _, item := range e.ListPending() {
		if item.ID == first.PendingID {
			allowed = item.Allowed
		}
	}
	okScope := false
	for _, scope := range allowed {
		if scope == ScopeTask {
			okScope = true
		}
	}
	if !okScope {
		t.Fatalf("scopes %v", allowed)
	}
	if err := e.Decide(first.PendingID, "approve", ScopeTask); err != nil {
		t.Fatal(err)
	}
	e.NoteUserText(req.BotID, "task-2", "next message")
	req.TaskID = "task-2"
	again := e.Evaluate(context.Background(), req)
	if again.Verdict == VerdictAllow || again.PendingID == "" {
		t.Fatalf("once token %+v", again)
	}
}

// Approving every listed card still does not mint a once-token for a
// sticky item.
func TestStickyApproveAllSkipsOnceToken(t *testing.T) {
	e := testEngine(t)
	req := shellReq("Bash", "git status")
	req.Sticky = true
	req.SessionID = "job:abc"
	first := e.Evaluate(context.Background(), req)
	if first.PendingID == "" || first.Verdict == VerdictAllow {
		t.Fatalf("%+v", first)
	}
	if _, err := e.ApproveAll([]string{first.PendingID}); err != nil {
		t.Fatal(err)
	}
	again := e.Evaluate(context.Background(), req)
	if again.Verdict == VerdictAllow || again.PendingID == "" {
		t.Fatalf("once token %+v", again)
	}
}
