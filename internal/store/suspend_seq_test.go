package store

import (
	"path/filepath"
	"testing"
)

// TestSuspendRunSeqCAS fails if SuspendRun applies a sequence that is not
// the one currently stored. A stale prevSeq is rejected. The next seq is
// accepted after that rejection.
func TestSuspendRunSeqCAS(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bot, err := st.CreateBot("Seq", "stay", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	run, err := st.CreateRun(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := st.SuspendRun(run.ID, "pend", 1, 0)
	if err != nil || !ok {
		t.Fatalf("first suspend %v %v", ok, err)
	}
	ok, err = st.ResumeRun(run.ID)
	if err != nil || !ok {
		t.Fatalf("resume %v %v", ok, err)
	}
	ok, err = st.SuspendRun(run.ID, "pend", 9, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("stale sequence was accepted")
	}
	got, err := st.GetRun(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "running" || got.WaitingSeq != 1 || got.WaitingPendingID != "" {
		t.Fatalf("stale suspend changed the run: %+v", got)
	}
	ok, err = st.SuspendRun(run.ID, "pend", 2, 1)
	if err != nil || !ok {
		t.Fatalf("newer sequence %v %v", ok, err)
	}
	got, err = st.GetRun(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "waiting" || got.WaitingSeq != 2 || got.WaitingPendingID != "pend" {
		t.Fatalf("newer suspend %+v", got)
	}
}
