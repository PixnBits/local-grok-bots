package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestOnceTimerFiresOnce(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b, err := s.CreateBot("Once", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(time.Minute)
	tm, err := s.CreateTimerAt(b.ID, "", "walk the dog", at)
	if err != nil || tm.Schedule != OnceSchedule || tm.NextFireAt != FormatTime(at) {
		t.Fatalf("create %#v %v", tm, err)
	}
	if due, _ := s.ClaimDueTimers(time.Now()); len(due) != 0 {
		t.Fatal("fired early")
	}
	if due, _ := s.ClaimDueTimers(at.Add(time.Second)); len(due) != 1 {
		t.Fatalf("due = %d", len(due))
	}
	if due, _ := s.ClaimDueTimers(at.Add(time.Hour)); len(due) != 0 {
		t.Fatal("one-shot fired twice")
	}
	got, _ := s.GetTimer(tm.ID)
	if got.Enabled || got.LastFireAt == nil {
		t.Fatalf("after fire %#v", got)
	}
}
