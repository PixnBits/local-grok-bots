//go:build linux

package clisession

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestParseProcStatComm(t *testing.T) {
	// comm holds spaces and a closing parenthesis. starttime is field 22.
	raw := []byte("12 (claude) grok) S 1 12 99 0 12 0 0 0 0 0 0 0 0 0 20 0 1 0 4242 1 2 3 4 5 6\n")
	pgid, start, err := parseProcStat(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pgid != 12 || start != "4242" {
		t.Fatalf("pgid %d start %s", pgid, start)
	}
	if _, _, err := parseProcStat([]byte("1 (x) S 0 1\n")); err == nil {
		t.Fatal("short stat accepted")
	}
}

func TestSelfStatAgrees(t *testing.T) {
	pgid, start, err := readProcStat(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	got, err := syscall.Getpgid(os.Getpid())
	if err != nil || got != pgid {
		t.Fatalf("pgrp stat %d getpgid %d err %v", pgid, got, err)
	}
	if start == "" {
		t.Fatal("empty starttime")
	}
	_, start2, err := readProcStat(os.Getpid())
	if err != nil || start2 != start {
		t.Fatalf("starttime changed %s %s %v", start, start2, err)
	}
}

func TestKillStoredRequiresLinuxMarker(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "sleep 30")
	prepareProc(cmd)
	applySessionMarker(cmd, "run-marker")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	leader := cmd.Process.Pid
	t.Cleanup(func() {
		if processAlive(leader) {
			_ = syscall.Kill(-leader, syscall.SIGKILL)
			_, _ = cmd.Process.Wait()
		}
	})
	stored, err := Identify(leader, "run-marker", cmd.Path)
	if err != nil {
		t.Fatal(err)
	}
	wrong := stored
	wrong.Marker = "other-run"
	KillStoredCLI(wrong)
	if !stillRunning(leader) {
		t.Fatal("mismatched marker was signaled")
	}
}
