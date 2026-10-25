package daemon

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/github"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
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
	if os.Geteuid() == 0 {
		uid, gid := sandbox.JailIDs()
		if err := sandbox.Chown(p.Sock(), uid, gid); err != nil {
			_ = p.Close()
			return nil, err
		}
		if err := sandbox.Chown(filepath.Dir(p.Sock()), uid, gid); err != nil {
			_ = p.Close()
			return nil, err
		}
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
		"reason": ev.Reason, "method": ev.Method, "path": ev.Path, "status": ev.Status,
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

// auditSandboxGitHub records a jail denial of GitHub. The row has no token.
func (a *App) auditSandboxGitHub(botID string, ev sandbox.Event) {
	if a == nil || ev.Kind != "grant_denied" || ev.Grant != "github" {
		return
	}
	if ev.Detail != sandbox.GitHubNetworkDenied && ev.Detail != sandbox.GitHubProxyDenied {
		return
	}
	rec := map[string]any{
		"bot":      safeAuditID(botID),
		"run":      safeAuditID(a.loopRunID(botID)),
		"action":   "github_refuse",
		"decision": "deny",
		"reason":   ev.Detail,
	}
	if ev.Host != "" {
		rec["host"] = ev.Host
	}
	if a.audit != nil {
		a.audit.Write(rec)
	}
}

func (a *App) noteGitHubSock(botID, sock string) {
	if a == nil {
		return
	}
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	if a.githubReadSock == nil {
		a.githubReadSock = map[string]string{}
	}
	if sock == "" {
		delete(a.githubReadSock, botID)
		return
	}
	a.githubReadSock[botID] = sock
}

func (a *App) gitHubReadSock(botID string) string {
	if a == nil {
		return ""
	}
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	return a.githubReadSock[botID]
}

func (a *App) writeProxyUp() bool {
	return a != nil && a.githubWriteUp.Load()
}

// githubUnixClient dials a read proxy. The URL host is ignored.
func githubUnixClient(sock string) *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// openGitHubReadProxy is the jail-style read proxy. It does not listen on TCP.
func (a *App) openGitHubReadProxy(bot store.Bot) (*github.Proxy, error) {
	return a.openGitHubProxy(bot)
}

// openGitHubWriteGate listens only after an approval card. The caller closes it.
// The listener is not the jail socket. win is the only route it forwards.
func (a *App) openGitHubWriteGate(bot store.Bot, win github.Window) (string, func(), error) {
	noop := func() {}
	if a == nil {
		return "", noop, errors.New("proxy unavailable")
	}
	p, err := github.New(github.Config{
		Repos:   a.policy.EffectiveGitHubRepos(bot.GitHubAllow),
		Token:   func() (string, error) { return readGitHubToken(a.policy.GitHub.TokenFile) },
		GitBase: a.githubGitBase,
		APIBase: a.githubAPIBase,
		Audit:   func(ev github.Audit) { a.auditGitHub(bot.ID, ev) },
		Access:  github.AccessWrite,
		Window:  win,
	})
	if err != nil {
		return "", noop, errors.New("proxy unavailable")
	}
	p.Bind(safeAuditID(bot.ID), safeAuditID(a.loopRunID(bot.ID)))
	a.githubWriteUp.Store(true)
	base, err := p.ListenTCP()
	if err != nil || base == "" {
		a.githubWriteUp.Store(false)
		_ = p.Close()
		return "", noop, errors.New("proxy unavailable")
	}
	var once bool
	return base, func() {
		if once {
			return
		}
		once = true
		_ = p.Close()
		a.githubWriteUp.Store(false)
	}, nil
}
