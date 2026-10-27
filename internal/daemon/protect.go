package daemon

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

// protectSnap is the inode set taken at startup. The pointer is replaced
// only to append paths that were not already recorded. Entries already in
// the slice keep their device and inode for the life of the process.
type protectSnap struct {
	inodes []sandbox.ProtectInode
}

// protectTripState is the first snapshot failure. Nothing clears it.
type protectTripState struct {
	path   string
	reason string
}

type protectSpec struct {
	path     string
	required bool
}

// RefreshProtectSnapshot unions shell-protect paths into the baseline.
// It runs at startup and after a successful AUTH_TOKENS_FILE reload.
// A path already recorded is left as it was. A required path that is
// missing, and was not already recorded, trips the process.
func (a *App) RefreshProtectSnapshot() {
	if a == nil {
		return
	}
	prev := a.protectSnap.Load()
	var base []sandbox.ProtectInode
	if prev != nil {
		base = append([]sandbox.ProtectInode(nil), prev.inodes...)
	}
	have := map[string]struct{}{}
	for _, ent := range base {
		have[ent.Path] = struct{}{}
	}
	var extra []sandbox.ProtectInode
	tripPath := ""
	tripReason := ""
	for _, sp := range a.protectSpecs() {
		if _, ok := have[sp.path]; ok {
			continue
		}
		added, present := snapshotAdds(sp.path, have)
		extra = append(extra, added...)
		if !present && sp.required && tripPath == "" {
			tripPath = sp.path
			tripReason = "protected path missing: " + sp.path
		}
	}
	a.protectSnap.Store(&protectSnap{inodes: append(base, extra...)})
	if tripPath != "" {
		a.latchProtect(tripPath, tripReason)
	}
}

// snapshotAdds records path and its existing ancestors that are not already
// in have. present is false when path itself could not be stat'd.
func snapshotAdds(path string, have map[string]struct{}) (added []sandbox.ProtectInode, present bool) {
	path = filepath.Clean(path)
	for _, ent := range sandbox.SnapshotProtect([]string{path}) {
		if ent.Path == path {
			present = true
		}
		if _, ok := have[ent.Path]; ok {
			continue
		}
		have[ent.Path] = struct{}{}
		added = append(added, ent)
	}
	return added, present
}

// protectSpecs classifies the paths the snapshot watches.
// A required path must exist. An optional path may be created later.
// An unconfigured path is omitted. This does not create directories.
func (a *App) protectSpecs() []protectSpec {
	if a == nil {
		return nil
	}
	var specs []protectSpec
	seen := map[string]struct{}{}
	add := func(p string, required bool) {
		p, ok := cleanProtectPath(p)
		if !ok {
			return
		}
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		specs = append(specs, protectSpec{path: p, required: required})
	}
	data, ok := cleanProtectPath(a.cfg.DataDir)
	if ok {
		add(data, true)
	}
	if data != "" {
		token := filepath.Join(data, adminTokenFile)
		if protectPathExists(token) {
			add(token, true)
		}
		for _, name := range []string{"state.db", "state.db-wal", "state.db-shm"} {
			add(filepath.Join(data, name), false)
		}
		for _, name := range secretDirNames {
			add(filepath.Join(data, name), false)
		}
	}
	if p := strings.TrimSpace(a.cfg.PolicyPath); p != "" && a.policy.Loaded {
		add(p, true)
	}
	if p := strings.TrimSpace(a.cfg.AuthTokensFile); p != "" {
		add(p, true)
	}
	if p := strings.TrimSpace(a.policy.GitHub.TokenFile); p != "" {
		add(p, true)
	}
	if key := a.sshKeyPath(); protectPathExists(key) {
		add(key, true)
	}
	for _, tool := range a.policy.CLITools {
		add(tool.CredentialHome, true)
	}
	if a.policy.VoiceEnabled {
		bin, model, _, _ := whisperPaths(a.policy, a.cfg)
		addVoiceProtect(add, bin)
		addVoiceProtect(add, model)
	}
	if p := auditSecretPath(a.policy.AuditLog); p != "" {
		add(p, false)
	}
	return specs
}

func addVoiceProtect(add func(string, bool), path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	add(path, false)
	parent := filepath.Dir(path)
	if parent == "" || parent == "." || parent == path {
		return
	}
	add(parent, false)
}

func cleanProtectPath(p string) (string, bool) {
	p = strings.TrimSpace(p)
	if p == "" || p == "." || p == "/" {
		return "", false
	}
	if !filepath.IsAbs(p) {
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", false
		}
		p = abs
	}
	p = filepath.Clean(p)
	if p == "" || p == "." || p == "/" {
		return "", false
	}
	return p, true
}

func protectPathExists(p string) bool {
	p = filepath.Clean(strings.TrimSpace(p))
	if p == "" || p == "." || p == "/" {
		return false
	}
	_, err := os.Lstat(p)
	return err == nil
}

// protectInodes copies the current snapshot for one turn. Nil means the
// snapshot was never taken. The sandbox then refuses every build bind.
func (a *App) protectInodes() []sandbox.ProtectInode {
	if a == nil {
		return nil
	}
	p := a.protectSnap.Load()
	if p == nil {
		return nil
	}
	return append([]sandbox.ProtectInode(nil), p.inodes...)
}

// observeProtectBaseline compares the baseline directories before a turn.
// The first change latches a trip. Later calls do not write another row.
func (a *App) observeProtectBaseline() {
	if a == nil || a.protectBlockReason() != "" {
		return
	}
	path := sandbox.ProtectChanged(a.protectInodes())
	if path == "" {
		return
	}
	a.latchProtect(path, "protected path changed: "+path)
}

// protectBlockReason is the bind refusal suffix while the snapshot is
// tripped. It is empty when the baseline is still intact.
func (a *App) protectBlockReason() string {
	if a == nil {
		return ""
	}
	rec := a.protectTrip.Load()
	if rec == nil || rec.reason == "" {
		return ""
	}
	if strings.Contains(rec.reason, "missing") {
		return "protected path missing (restart required)"
	}
	return "protected path changed (restart required)"
}

// latchProtect records the first trip, one audit row, and one log line.
func (a *App) latchProtect(path, reason string) {
	if a == nil || path == "" || reason == "" {
		return
	}
	if !a.protectTrip.CompareAndSwap(nil, &protectTripState{path: path, reason: reason}) {
		return
	}
	a.writeStartup("local-grok-bots: protect snapshot tripped: %s\n", reason)
	if a.audit != nil && a.audit.Enabled() {
		a.audit.Write(map[string]any{
			"action": "protect_snapshot_tripped",
			"path":   path,
			"reason": reason,
		})
	}
}
