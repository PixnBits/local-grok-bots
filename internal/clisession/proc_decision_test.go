package clisession

import "testing"

func TestMaySignalRequiresIdentity(t *testing.T) {
	self, selfPG := 10, 10
	stored := StoredCLI{PID: 40, PGID: 40, Start: "999", Exe: "/usr/bin/claude", Marker: "run-1"}
	live := liveCLI{PID: 40, PGID: 40, Start: "999", Exe: "/usr/bin/claude", MarkerOK: true}
	if !maySignal(self, selfPG, stored, live, true) {
		t.Fatal("matching identity was refused")
	}
	// A command line that merely contains the name is not a match.
	live.Exe = "local-grok-bots --claude"
	if maySignal(self, selfPG, stored, live, true) {
		t.Fatal("substring command was accepted")
	}
	live.Exe = "/usr/bin/claude --resume abc"
	if !maySignal(self, selfPG, stored, live, true) {
		t.Fatal("absolute path prefix was refused")
	}
	named := stored
	named.Exe = "claude"
	if maySignal(self, selfPG, named, liveCLI{PID: 40, PGID: 40, Start: "999", Exe: "claude --foo", MarkerOK: true}, true) {
		t.Fatal("bare name matched a longer command")
	}
	for _, mutate := range []func(*StoredCLI, *liveCLI){
		func(s *StoredCLI, l *liveCLI) { l.Start = "1000" },
		func(s *StoredCLI, l *liveCLI) { l.PGID = 41 },
		func(s *StoredCLI, l *liveCLI) { l.MarkerOK = false },
		func(s *StoredCLI, l *liveCLI) { s.Marker = "" },
		func(s *StoredCLI, l *liveCLI) { s.Start = "" },
		func(s *StoredCLI, l *liveCLI) { s.PGID = 7 },
		func(s *StoredCLI, l *liveCLI) { s.PID = self },
		func(s *StoredCLI, l *liveCLI) { s.PGID = selfPG; s.PID = selfPG },
		func(s *StoredCLI, l *liveCLI) { l.PGID = selfPG; l.PID = 40 },
	} {
		s, l := stored, live
		l.Exe = "/usr/bin/claude"
		mutate(&s, &l)
		if maySignal(self, selfPG, s, l, true) {
			t.Fatalf("signaled after %+v %+v", s, l)
		}
	}
	// Darwin does not require the marker bit. Start time and pgid still do.
	live.MarkerOK = false
	live.Exe = "/usr/bin/claude"
	if maySignal(self, selfPG, stored, live, false) != true {
		t.Fatal("darwin match required the marker")
	}
	live.Start = "1"
	if maySignal(self, selfPG, stored, live, false) {
		t.Fatal("darwin match ignored start time")
	}
}

func TestValidMarker(t *testing.T) {
	for _, ok := range []string{"abc", "run-1", "ABC_2"} {
		if !validMarker(ok) {
			t.Fatalf("%s rejected", ok)
		}
	}
	for _, bad := range []string{"", "a b", "a=b", "a\nb", "m/../x"} {
		if validMarker(bad) {
			t.Fatalf("%q accepted", bad)
		}
	}
}
