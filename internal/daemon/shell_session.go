package daemon

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/permbroker"
)

var errShellCwd = errors.New("cd stays inside the workspace")

// errShellCwdReset is returned when the stored session directory no longer
// resolves to a directory inside the workspace. The stored cwd is put back
// at the workspace root.
var errShellCwdReset = errors.New("working directory is no longer inside the workspace; reset to the workspace root")

// shellCwdPlan is applied only after the allowed command exits 0.
type shellCwdPlan struct {
	next   string
	update bool
}

func (a *App) shellSessionDir(botID, workspace string) string {
	ws := filepath.Clean(workspace)
	if a == nil {
		return ws
	}
	a.shellCwdMu.Lock()
	defer a.shellCwdMu.Unlock()
	cur := ""
	if a.shellCwd != nil {
		cur = a.shellCwd[botID]
	}
	if cur == "" {
		return ws
	}
	cur = filepath.Clean(cur)
	if !insideWorkspace(cur, ws) {
		return ws
	}
	return cur
}

func (a *App) noteShellPlan(botID string, plan shellCwdPlan) {
	if a == nil {
		return
	}
	a.shellCwdMu.Lock()
	defer a.shellCwdMu.Unlock()
	if a.shellPlan == nil {
		a.shellPlan = map[string]shellCwdPlan{}
	}
	if !plan.update {
		delete(a.shellPlan, botID)
		return
	}
	a.shellPlan[botID] = plan
}

func (a *App) commitShellPlan(botID, workspace string) {
	if a == nil {
		return
	}
	ws := filepath.Clean(workspace)
	a.shellCwdMu.Lock()
	defer a.shellCwdMu.Unlock()
	plan, ok := a.shellPlan[botID]
	delete(a.shellPlan, botID)
	if !ok || !plan.update || !insideWorkspace(plan.next, ws) {
		return
	}
	if a.shellCwd == nil {
		a.shellCwd = map[string]string{}
	}
	a.shellCwd[botID] = filepath.Clean(plan.next)
}

// resetShellCwd stores the workspace root and drops a pending plan.
// shellSessionDir and commitShellPlan still refuse a path that was never inside.
func (a *App) resetShellCwd(botID, workspace string) {
	if a == nil {
		return
	}
	a.shellCwdMu.Lock()
	defer a.shellCwdMu.Unlock()
	delete(a.shellPlan, botID)
	if a.shellCwd == nil {
		a.shellCwd = map[string]string{}
	}
	a.shellCwd[botID] = filepath.Clean(workspace)
}

func (a *App) clearShellPlan(botID string) {
	if a == nil {
		return
	}
	a.shellCwdMu.Lock()
	defer a.shellCwdMu.Unlock()
	delete(a.shellPlan, botID)
}

// confirmShellCwd re-resolves stored. A directory that is no longer inside
// the workspace is reset to the workspace root and the call is refused.
func (a *App) confirmShellCwd(botID, workspace, stored string) (resolved, rel string, err error) {
	resolved, rel, err = resolveStoredCwd(workspace, stored)
	if err != nil {
		a.resetShellCwd(botID, workspace)
		return "", "", errShellCwdReset
	}
	return resolved, rel, nil
}

// shellExecRel re-resolves the stored cwd immediately before the jail runs.
func (a *App) shellExecRel(botID, workspace string) (string, error) {
	cur := a.shellSessionDir(botID, workspace)
	_, rel, err := a.confirmShellCwd(botID, workspace, cur)
	return rel, err
}

func (a *App) prepareShellCwd(botID, workspace, command string) (string, shellCwdPlan, error) {
	cur := a.shellSessionDir(botID, workspace)
	resolved, _, err := a.confirmShellCwd(botID, workspace, cur)
	if err != nil {
		return filepath.Clean(workspace), shellCwdPlan{}, err
	}
	base := cur
	if insideWorkspace(resolved, filepath.Clean(workspace)) {
		base = resolved
	}
	next, reject, update := permbroker.ShellCwdAfter(workspace, base, command)
	if reject {
		return resolved, shellCwdPlan{}, errShellCwd
	}
	return resolved, shellCwdPlan{next: next, update: update}, nil
}

func insideWorkspace(path, workspace string) bool {
	path = filepath.Clean(path)
	workspace = filepath.Clean(workspace)
	if path == workspace {
		return true
	}
	rel, err := filepath.Rel(workspace, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
