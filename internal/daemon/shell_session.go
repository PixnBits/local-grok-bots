package daemon

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/permbroker"
)

var errShellCwd = errors.New("cd stays inside the workspace")

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

func (a *App) clearShellPlan(botID string) {
	if a == nil {
		return
	}
	a.shellCwdMu.Lock()
	defer a.shellCwdMu.Unlock()
	delete(a.shellPlan, botID)
}

// shellRunCommand runs command in the session directory. The jail starts
// at /work, so a subdirectory is a cd prefix after the broker has already
// seen the original command.
func (a *App) shellRunCommand(botID, workspace, command string) string {
	cur := a.shellSessionDir(botID, workspace)
	rel, err := filepath.Rel(filepath.Clean(workspace), cur)
	if err != nil || rel == "." || rel == "" {
		return command
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return command
	}
	return "cd -- " + quoteShell(rel) + " && " + command
}

func (a *App) prepareShellCwd(botID, workspace, command string) (string, shellCwdPlan, error) {
	cur := a.shellSessionDir(botID, workspace)
	next, reject, update := permbroker.ShellCwdAfter(workspace, cur, command)
	if reject {
		return cur, shellCwdPlan{}, errShellCwd
	}
	return cur, shellCwdPlan{next: next, update: update}, nil
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
