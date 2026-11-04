//go:build linux

package sandbox

import (
	"bufio"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func countFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

func procState(pid int) (string, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", err
	}
	s := string(b)
	i := strings.LastIndex(s, ")")
	if i < 0 || i+2 >= len(s) {
		return "", os.ErrInvalid
	}
	fields := strings.Fields(strings.TrimSpace(s[i+1:]))
	if len(fields) == 0 {
		return "", os.ErrInvalid
	}
	return fields[0], nil
}

func waitState(t *testing.T, pid int, want string) string {
	t.Helper()
	var last string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st, err := procState(pid)
		if err != nil {
			return ""
		}
		last = st
		if st == want || (want == "dead" && (st == "Z" || st == "X")) {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	return last
}

func startSleep(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "120")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})
	return cmd
}

func startTree(t *testing.T) (root *exec.Cmd, push, extra int) {
	t.Helper()
	cmd := exec.Command("bash", "-c", "sleep 120 &\necho $!\nsleep 120 &\necho $!\nwait\n")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(stdout)
	var kids []int
	for i := 0; i < 2; i++ {
		if !sc.Scan() {
			t.Fatalf("tree output: %v", sc.Err())
		}
		n, err := strconv.Atoi(strings.TrimSpace(sc.Text()))
		if err != nil || n <= 1 {
			t.Fatalf("tree pid %q", sc.Text())
		}
		kids = append(kids, n)
	}
	t.Cleanup(func() {
		for _, pid := range kids {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})
	return cmd, kids[0], kids[1]
}

func TestShellGuardClosesPidfds(t *testing.T) {
	child := startSleep(t)
	before := countFDs(t)
	g := &ShellGuard{}
	g.noteJail(os.Getpid())
	g.notePush(child.Process.Pid)
	g.notePush(child.Process.Pid)
	g.clearPush(child.Process.Pid)
	g.Close()
	g.Close()
	if got := countFDs(t); got != before {
		t.Fatalf("fds before %d after %d", before, got)
	}
}

func TestTrimSignalsDescendant(t *testing.T) {
	root, push, extra := startTree(t)
	if parentPID(push) != root.Process.Pid || parentPID(extra) != root.Process.Pid {
		t.Fatalf("tree parents push=%d extra=%d root=%d", parentPID(push), parentPID(extra), root.Process.Pid)
	}
	g := &ShellGuard{}
	defer g.Close()
	g.noteJail(root.Process.Pid)
	g.notePush(push)
	var refused []int
	g.OnRefused = func(pid int, reason string) {
		refused = append(refused, pid)
	}
	if !g.Trim() {
		t.Fatal("Trim returned false")
	}
	if len(refused) != 0 {
		t.Fatalf("refused %v", refused)
	}
	if st := waitState(t, extra, "dead"); st == "R" || st == "S" || st == "T" || st == "t" {
		t.Fatalf("extra state %q", st)
	}
	st, err := procState(push)
	if err != nil || st == "T" || st == "t" || st == "Z" {
		t.Fatalf("push state %q %v", st, err)
	}
	rst, err := procState(root.Process.Pid)
	if err != nil || rst == "T" || rst == "t" || rst == "Z" {
		t.Fatalf("root state %q %v", rst, err)
	}
}

func TestTrimRefusesNonDescendant(t *testing.T) {
	root := startSleep(t)
	sib := startSleep(t)
	g := &ShellGuard{}
	defer g.Close()
	g.noteJail(root.Process.Pid)
	g.notePush(sib.Process.Pid)
	var reasons []string
	g.OnRefused = func(pid int, reason string) {
		if pid == sib.Process.Pid {
			reasons = append(reasons, reason)
		}
	}
	if g.Trim() {
		t.Fatal("Trim signalled")
	}
	if len(reasons) == 0 {
		t.Fatal("refusal hook did not fire")
	}
	st, err := procState(sib.Process.Pid)
	if err != nil || st == "T" || st == "t" || st == "Z" {
		t.Fatalf("sibling state %q %v", st, err)
	}
}

func TestTrimRefusesReusedPushPID(t *testing.T) {
	root := startSleep(t)
	procA := startSleep(t)
	procB := startSleep(t)
	g := &ShellGuard{}
	defer g.Close()
	g.noteJail(root.Process.Pid)
	g.notePush(procA.Process.Pid)
	if err := procA.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = procA.Wait()
	aPID := procA.Process.Pid
	bPID := procB.Process.Pid
	bParent := parentPID(bPID)
	g.parentOf = func(pid int) int {
		if pid == aPID || pid == bPID {
			return bParent
		}
		if pid == bParent {
			return 1
		}
		return parentPID(pid)
	}
	g.childrenOf = func() map[int][]int {
		return map[int][]int{root.Process.Pid: {bPID}}
	}
	var sawB, sawA bool
	g.OnRefused = func(pid int, reason string) {
		if pid == bPID {
			sawB = true
		}
		if pid == aPID {
			sawA = true
		}
		if reason == "" {
			t.Errorf("empty reason for %d", pid)
		}
	}
	if g.Trim() {
		t.Fatal("Trim signalled")
	}
	if !sawA || !sawB {
		t.Fatalf("refusals A=%v B=%v", sawA, sawB)
	}
	st, err := procState(bPID)
	if err != nil || st == "T" || st == "t" || st == "Z" {
		t.Fatalf("B state %q %v", st, err)
	}
}

func TestTrimDeadRootPidfdSendsNothing(t *testing.T) {
	root, push, extra := startTree(t)
	g := &ShellGuard{}
	defer g.Close()
	g.noteJail(root.Process.Pid)
	g.notePush(push)
	if err := root.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = root.Wait()
	rootPID := root.Process.Pid
	g.parentOf = func(pid int) int {
		if pid == extra || pid == push {
			return rootPID
		}
		return 1
	}
	g.childrenOf = func() map[int][]int {
		return map[int][]int{rootPID: {extra}}
	}
	var reasons []string
	g.OnRefused = func(pid int, reason string) {
		if pid == extra {
			reasons = append(reasons, reason)
		}
	}
	if g.Trim() {
		t.Fatal("Trim signalled")
	}
	if len(reasons) == 0 || reasons[0] != "jail root pidfd is dead" {
		t.Fatalf("reasons %v", reasons)
	}
	st, err := procState(extra)
	if err != nil || st == "T" || st == "t" || st == "Z" {
		t.Fatalf("extra state %q %v", st, err)
	}
	st, err = procState(push)
	if err != nil || st == "T" || st == "t" || st == "Z" {
		t.Fatalf("push state %q %v", st, err)
	}
}
