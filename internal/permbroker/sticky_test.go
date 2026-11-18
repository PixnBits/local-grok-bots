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
