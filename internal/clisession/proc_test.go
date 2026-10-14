//go:build linux || darwin

package clisession

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestProcessGroupKillStopsChildren does not use claude or grok.
// It starts a shell in its own process group and a grandchild sleep,
// then checks that one group kill stops both.
func TestProcessGroupKillStopsChildren(t *testing.T) {
	dir := t.TempDir()
	childFile := filepath.Join(dir, "child")
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf(
		"sleep 120 &\necho $! > %q\nsleep 120\n", childFile,
	))
	prepareProc(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil && processAlive(cmd.Process.Pid) {
			killGroup(cmd.Process)
			_, _ = cmd.Process.Wait()
		}
	})

	leader := cmd.Process.Pid
	pgid, err := syscall.Getpgid(leader)
	if err != nil {
		t.Fatal(err)
	}
	if pgid != leader {
		_ = cmd.Process.Kill()
		t.Fatalf("shell is not a process-group leader: pid %d pgid %d", leader, pgid)
	}

	child := waitPIDFile(t, childFile)
	childGroup, err := syscall.Getpgid(child)
	if err != nil {
		t.Fatal(err)
	}
	if childGroup != leader {
		t.Fatalf("grandchild group %d, leader %d", childGroup, leader)
	}

	killGroup(cmd.Process)
	waitDone := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(3 * time.Second):
		t.Fatal("process-group kill did not reap the shell")
	}
	if stillRunning(leader) || stillRunning(child) {
		t.Fatalf("still running leader=%v child=%v", stillRunning(leader), stillRunning(child))
	}
}

func waitPIDFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err == nil {
			pid, conv := strconv.Atoi(strings.TrimSpace(string(b)))
			if conv == nil && pid > 0 && processAlive(pid) {
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pid file %s was not written", path)
	return 0
}

func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// stillRunning ignores zombies. kill(pid, 0) succeeds for a zombie.
func stillRunning(pid int) bool {
	if !processAlive(pid) {
		return false
	}
	out, err := exec.Command("ps", "-o", "state=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return false
	}
	state := strings.TrimSpace(string(out))
	return state != "" && !strings.HasPrefix(state, "Z")
}
