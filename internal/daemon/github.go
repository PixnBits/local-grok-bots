package daemon

import (
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/github"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// readGitHubToken reads the root-owned token file. Tests replace it.
var readGitHubToken = github.ReadToken

// openGitHubProxy listens on a private socket for this shell. The token
// stays in the proxy. A nil proxy means GitHub fetch is unavailable.
func (a *App) openGitHubProxy(bot store.Bot) (*github.Proxy, error) {
	if a == nil || !granted(bot.Grants, "github") {
		return nil, nil
	}
	repos := a.policy.EffectiveGitHubRepos(bot.GitHubAllow)
	p, err := github.New(github.Config{
		Repos:   repos,
		Token:   func() (string, error) { return readGitHubToken(a.policy.GitHub.TokenFile) },
		GitBase: a.githubGitBase,
		APIBase: a.githubAPIBase,
		Audit:   func(ev github.Audit) { a.auditGitHub(bot.ID, ev) },
	})
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(a.cfg.DataDir, "github")
	if err := p.ListenUnix(dir); err != nil {
		_ = p.Close()
		return nil, err
	}
	p.Bind(safeAuditID(bot.ID), safeAuditID(a.loopRunID(bot.ID)))
	return p, nil
}

func (a *App) loopRunID(botID string) string {
	if a == nil {
		return ""
	}
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	if st := a.loops[botID]; st != nil {
		return st.runID
	}
	return ""
}

func (a *App) auditGitHub(botID string, ev github.Audit) {
	if ev.Bot == "" {
		ev.Bot = safeAuditID(botID)
	}
	rec := map[string]any{
		"bot": ev.Bot, "run": ev.Run, "action": ev.Action,
		"owner": ev.Owner, "repo": ev.Repo, "decision": ev.Decision,
		"reason": ev.Reason, "path": ev.Path, "status": ev.Status,
	}
	if a.audit != nil {
		a.audit.Write(rec)
	}
	a.log(botID, ev.Action, rec)
}

func granted(grants []string, name string) bool {
	for _, g := range grants {
		if strings.EqualFold(strings.TrimSpace(g), name) {
			return true
		}
	}
	return false
}

func safeAuditID(s string) string {
	if len(s) > 128 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return ""
		}
	}
	return s
}
