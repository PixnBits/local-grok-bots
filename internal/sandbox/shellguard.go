package sandbox

import "sync"

// ShellGuard records the jail root and push clients for one shell.
// Trim stops other processes in that jail while a push is still running.
type ShellGuard struct {
	mu       sync.Mutex
	root     int
	pushPIDs map[int]struct{}
}

func (g *ShellGuard) noteJail(pid int) {
	if g == nil || pid <= 1 {
		return
	}
	g.mu.Lock()
	g.root = pid
	g.mu.Unlock()
}

func (g *ShellGuard) notePush(pid int) {
	if g == nil || pid <= 1 {
		return
	}
	g.mu.Lock()
	if g.pushPIDs == nil {
		g.pushPIDs = map[int]struct{}{}
	}
	g.pushPIDs[pid] = struct{}{}
	g.mu.Unlock()
}

func (g *ShellGuard) clearPush(pid int) {
	if g == nil || pid <= 1 {
		return
	}
	g.mu.Lock()
	delete(g.pushPIDs, pid)
	g.mu.Unlock()
}
