package store

import (
	"path/filepath"
	"testing"
)

func TestTakeCOICapPersistsAcrossOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := st.TakeCOICap("bot", "grok", 1); err != nil || !ok {
		t.Fatalf("first take %v %v", ok, err)
	}
	if ok, err := st.TakeCOICap("bot", "grok", 1); err != nil || ok {
		t.Fatalf("second take %v %v", ok, err)
	}
	if ok, err := st.TakeCOICap("bot", "other", 1); err != nil || !ok {
		t.Fatalf("other cli %v %v", ok, err)
	}
	if ok, err := st.TakeCOICap("bot", "grok", 0); err != nil || ok {
		t.Fatalf("zero limit %v %v", ok, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if ok, err := st.TakeCOICap("bot", "grok", 1); err != nil || ok {
		t.Fatalf("after reopen %v %v", ok, err)
	}
}
