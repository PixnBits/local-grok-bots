//go:build linux

package sandbox

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func openPidfd(pid int) (int, error) {
	return unix.PidfdOpen(pid, 0)
}

func closePidfd(fd int) {
	_ = unix.Close(fd)
}

func dupPidfd(fd int) (int, error) {
	return unix.Dup(fd)
}

func pidfdLive(fd int) error {
	return unix.PidfdSendSignal(fd, 0, nil, 0)
}

func pidfdSignal(fd int, sig unix.Signal) error {
	return unix.PidfdSendSignal(fd, sig, nil, 0)
}

// Trim stops processes in the jail other than the push client and its
// ancestors. It returns false when there is nothing else to stop, so a
// foreground push is left to finish. The jail root is not signalled here.
// Each signal uses a pidfd opened for that PID, and only after the parent
// walk reaches the jail root and both pidfds still accept signal 0.
func (g *ShellGuard) Trim() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	root := g.root
	rootFD := g.rootFD
	var rootDup int
	rootDupOK := false
	if rootFD.open {
		if d, err := dupPidfd(rootFD.n); err == nil {
			rootDup = d
			rootDupOK = true
		}
	}
	type noted struct {
		pid int
		dup int
		ok  bool
	}
	notedPush := make([]noted, 0, len(g.pushPIDs))
	var pushDups []int
	for pid, held := range g.pushPIDs {
		if pid <= 1 {
			continue
		}
		n := noted{pid: pid}
		if held.open {
			if d, err := dupPidfd(held.n); err == nil {
				n.dup = d
				n.ok = true
				pushDups = append(pushDups, d)
			}
		}
		notedPush = append(notedPush, n)
	}
	parentOf := g.parentOf
	childrenOf := g.childrenOf
	onRefused := g.OnRefused
	g.mu.Unlock()
	defer func() {
		if rootDupOK {
			closePidfd(rootDup)
		}
		for _, fd := range pushDups {
			closePidfd(fd)
		}
	}()
	if parentOf == nil {
		parentOf = parentPID
	}
	if childrenOf == nil {
		childrenOf = procChildren
	}
	refuse := func(pid int, reason string) {
		if onRefused != nil {
			onRefused(pid, reason)
		}
	}
	if root <= 1 || len(notedPush) == 0 {
		return false
	}

	spare := map[int]bool{root: true}
	pushSet := map[int]bool{}
	for _, n := range notedPush {
		pushSet[n.pid] = true
		if !n.ok || pidfdLive(n.dup) != nil {
			refuse(n.pid, "push pidfd is dead")
			continue
		}
		if !reachesRoot(n.pid, root, parentOf) {
			refuse(n.pid, "not a descendant of the jail root")
			continue
		}
		spare[n.pid] = true
		seen := map[int]bool{}
		for p := parentOf(n.pid); p > 1 && !seen[p]; p = parentOf(p) {
			seen[p] = true
			spare[p] = true
			if p == root {
				break
			}
		}
	}

	kids := childrenOf()
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
	signalled := false
	// Stop ancestors before the other processes, so a shell waiting on one
	// of them cannot continue to the next command.
	for pid := range spare {
		if pid == root || pushSet[pid] || pid <= 1 {
			continue
		}
		if signalDescendant(pid, unix.SIGSTOP, root, rootDup, rootDupOK, parentOf, refuse) {
			signalled = true
		}
	}
	for _, pid := range extras {
		if signalDescendant(pid, unix.SIGKILL, root, rootDup, rootDupOK, parentOf, refuse) {
			signalled = true
		}
	}
	return signalled
}

func signalDescendant(pid int, sig unix.Signal, root, rootFD int, rootOK bool, parentOf func(int) int, refuse func(int, string)) bool {
	fd, err := openPidfd(pid)
	if err != nil {
		refuse(pid, "pidfd_open failed")
		return false
	}
	defer closePidfd(fd)
	if !reachesRoot(pid, root, parentOf) {
		refuse(pid, "not a descendant of the jail root")
		return false
	}
	if !rootOK || pidfdLive(rootFD) != nil {
		refuse(pid, "jail root pidfd is dead")
		return false
	}
	if pidfdLive(fd) != nil {
		refuse(pid, "target pidfd is dead")
		return false
	}
	if err := pidfdSignal(fd, sig); err != nil {
		refuse(pid, "pidfd_send_signal failed")
		return false
	}
	return true
}

func reachesRoot(pid, root int, parentOf func(int) int) bool {
	if pid <= 1 || root <= 1 || pid == root {
		return false
	}
	seen := map[int]bool{}
	for p := parentOf(pid); p > 1 && !seen[p]; p = parentOf(p) {
		if p == root {
			return true
		}
		seen[p] = true
	}
	return false
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
