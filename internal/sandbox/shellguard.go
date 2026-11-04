package sandbox

import "sync"

// heldFD is a pidfd captured when a process was noted.
// open is false when no descriptor is held.
type heldFD struct {
	n    int
	open bool
}

// ShellGuard records the jail root and push clients for one shell.
// Trim stops other processes in that jail while a push is still running.
// OnRefused is called when a PID is not signalled.
type ShellGuard struct {
	mu        sync.Mutex
	root      int
	rootFD    heldFD
	pushPIDs  map[int]heldFD
	OnRefused func(pid int, reason string)

	// parentOf and childrenOf replace the /proc readers in tests.
	parentOf   func(pid int) int
	childrenOf func() map[int][]int
}

func (g *ShellGuard) noteJail(pid int) {
	if g == nil || pid <= 1 {
		return
	}
	fd, err := openPidfd(pid)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closeHeld(&g.rootFD)
	g.root = pid
	if err == nil {
		g.rootFD = heldFD{n: fd, open: true}
	}
}

func (g *ShellGuard) notePush(pid int) {
	if g == nil || pid <= 1 {
		return
	}
	fd, err := openPidfd(pid)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pushPIDs == nil {
		g.pushPIDs = map[int]heldFD{}
	}
	if prev, ok := g.pushPIDs[pid]; ok {
		g.closeHeld(&prev)
	}
	held := heldFD{}
	if err == nil {
		held = heldFD{n: fd, open: true}
	}
	g.pushPIDs[pid] = held
}

func (g *ShellGuard) clearPush(pid int) {
	if g == nil || pid <= 1 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	held, ok := g.pushPIDs[pid]
	if !ok {
		return
	}
	g.closeHeld(&held)
	delete(g.pushPIDs, pid)
}

// Close releases pidfds captured for the jail root and any push still noted.
func (g *ShellGuard) Close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closeHeld(&g.rootFD)
	for pid, held := range g.pushPIDs {
		g.closeHeld(&held)
		delete(g.pushPIDs, pid)
	}
}

func (g *ShellGuard) closeHeld(h *heldFD) {
	if h == nil || !h.open {
		return
	}
	closePidfd(h.n)
	h.open = false
	h.n = -1
}

func (g *ShellGuard) refuse(pid int, reason string) {
	if g == nil || g.OnRefused == nil {
		return
	}
	g.OnRefused(pid, reason)
}
