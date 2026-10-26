package daemon

import "github.com/PixnBits/local-grok-bots/internal/sandbox"

// protectSnap is the inode set taken from shellProtect. The pointer is
// replaced whole. The slice is not mutated after Store.
type protectSnap struct {
	inodes []sandbox.ProtectInode
}

// RefreshProtectSnapshot records shellProtect paths and their ancestor
// directories. It runs at startup, on every SIGHUP, and after a successful
// AUTH_TOKENS_FILE reload.
func (a *App) RefreshProtectSnapshot() {
	if a == nil {
		return
	}
	snap := sandbox.SnapshotProtect(a.shellProtect())
	cp := append([]sandbox.ProtectInode(nil), snap...)
	a.protectSnap.Store(&protectSnap{inodes: cp})
}

// protectInodes copies the current snapshot for one turn. Nil means the
// snapshot was never taken. The sandbox then refuses every build bind.
func (a *App) protectInodes() []sandbox.ProtectInode {
	if a == nil {
		return nil
	}
	p := a.protectSnap.Load()
	if p == nil || len(p.inodes) == 0 {
		return nil
	}
	return append([]sandbox.ProtectInode(nil), p.inodes...)
}
