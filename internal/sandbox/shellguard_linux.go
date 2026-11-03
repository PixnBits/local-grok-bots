//go:build linux

package sandbox

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Trim stops processes in the jail other than the push client and its
// ancestors. It returns false when there is nothing else to stop, so a
// foreground push is left to finish. The jail root is not signalled here.
func (g *ShellGuard) Trim() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	root := g.root
	pushes := make([]int, 0, len(g.pushPIDs))
	for pid := range g.pushPIDs {
		if pid > 1 {
			pushes = append(pushes, pid)
		}
	}
	g.mu.Unlock()
	if root <= 1 || len(pushes) == 0 {
		return false
	}
	spare := map[int]bool{root: true}
	pushSet := map[int]bool{}
	for _, pid := range pushes {
		pushSet[pid] = true
		spare[pid] = true
		seen := map[int]bool{}
		for p := parentPID(pid); p > 1 && !seen[p]; p = parentPID(p) {
			seen[p] = true
			spare[p] = true
			if p == root {
				break
			}
		}
	}
	kids := procChildren()
	var extras []int
	stack := append([]int{}, kids[root]...)
	seen := map[int]bool{root: true}
	for len(stack) > 0 {
		pid := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if pid <= 1 || seen[pid] {
			continue
		}
		seen[pid] = true
		if !spare[pid] {
			extras = append(extras, pid)
		}
		stack = append(stack, kids[pid]...)
	}
	if len(extras) == 0 {
		return false
	}
	// Stop ancestors before the other processes, so a shell waiting on one
	// of them cannot continue to the next command.
	for pid := range spare {
		if pid == root || pushSet[pid] || pid <= 1 {
			continue
		}
		_ = syscall.Kill(pid, syscall.SIGSTOP)
	}
	for _, pid := range extras {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	return true
}

func parentPID(pid int) int {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
		if err != nil || n <= 0 {
			return 0
		}
		return n
	}
	return 0
}

func procChildren() map[int][]int {
	out := map[int][]int{}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, ent := range ents {
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid <= 1 {
			continue
		}
		ppid := parentPID(pid)
		if ppid <= 0 {
			continue
		}
		out[ppid] = append(out[ppid], pid)
	}
	return out
}
