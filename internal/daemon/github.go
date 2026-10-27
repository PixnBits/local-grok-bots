package daemon

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/github"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// readGitHubToken reads the token file owned by the daemon user. Tests replace it.
var readGitHubToken = github.ReadToken

// openGitHubProxy listens on a private socket for this shell. The token
// stays in the proxy. A nil proxy means GitHub fetch is unavailable.
func (a *App) openGitHubProxy(bot store.Bot) (*github.Proxy, error) {
	turnPol := a.effPol(bot.ID)

	if a == nil || !granted(bot.Grants, "github") {
		return nil, nil
	}
	repos := turnPol.EffectiveGitHubRepos(bot.GitHubAllow)
	p, err := github.New(github.Config{
		Repos:   repos,
		Token:   func() (string, error) { return readGitHubToken(turnPol.GitHub.TokenFile) },
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
	if sandbox.EUID() == 0 {
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

func allowlistNames(owner, repo string) (string, string, bool) {
	name, err := github.NormalizeRepo(owner + "/" + repo)
	if err != nil {
		return "", "", false
	}
	owner, repo, _ = strings.Cut(name, "/")
	return owner, repo, true
}

// auditSandboxGitHub records a jail denial of GitHub. The row has no token.
func (a *App) auditSandboxGitHub(botID string, ev sandbox.Event) {
	if a == nil || ev.Untrusted || ev.Kind == "jail_report" || ev.Kind == "jail_report_truncated" {
		return
	}
	if ev.Kind != "grant_denied" || ev.Grant != "github" {
		return
	}
	switch ev.Detail {
	case sandbox.GitHubNetworkDenied, sandbox.GitHubProxyDenied, sandbox.GitHubAllowlistDenied:
	default:
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
	if ev.Detail == sandbox.GitHubAllowlistDenied {
		if owner, repo, ok := allowlistNames(ev.Owner, ev.Repo); ok {
			rec["owner"] = owner
			rec["repo"] = repo
		}
	}
	if a.audit != nil {
		a.audit.Write(rec)
	}
}

// auditSandboxNet records a trusted net or ssh grant_denied, or a
// net_request, when the audit log is enabled. GitHub rows stay with
// auditSandboxGitHub. The fields are the action, the bot id, the grant,
// the host when one was named, and a short clipped detail.
func (a *App) auditSandboxNet(botID string, ev sandbox.Event) {
	if a == nil || a.audit == nil || !a.audit.Enabled() || ev.Untrusted {
		return
	}
	action := netAuditAction(ev)
	if action == "" {
		return
	}
	a.writeNetAudit(botID, ev, action, 0)
}

// netAuditAction is the audit action for one trusted net or ssh event.
// An off-allowlist net denial is grant_denied. Any other net_request stays
// net_request. An empty result is not an audit row.
func netAuditAction(ev sandbox.Event) string {
	if ev.Untrusted {
		return ""
	}
	switch ev.Kind {
	case "grant_denied":
		if ev.Grant == "net" || ev.Grant == "ssh" {
			return "grant_denied"
		}
	case "net_request":
		if strings.TrimSpace(ev.Detail) == "not allowlisted" {
			return "grant_denied"
		}
		return "net_request"
	}
	return ""
}

// writeNetAudit writes one trusted net or ssh audit row. count is omitted
// when it is below 2 so a single event keeps the original fields.
func (a *App) writeNetAudit(botID string, ev sandbox.Event, action string, count int) {
	if a == nil || a.audit == nil || !a.audit.Enabled() || action == "" {
		return
	}
	rec := map[string]any{
		"action": action,
		"bot_id": safeAuditID(botID),
		"grant":  clipASCII(ev.Grant),
		"detail": clipASCII(ev.Detail),
	}
	if ev.Host != "" {
		rec["host"] = clipASCII(ev.Host)
	}
	if count > 1 {
		rec["count"] = count
	}
	a.audit.Write(rec)
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
// The second result is the gate secret. It belongs in the X-LGB-Gate header,
// not in a URL.
func (a *App) openGitHubWriteGate(bot store.Bot, win github.Window) (string, string, func(), error) {
	turnPol := a.effPol(bot.ID)

	noop := func() {}
	if a == nil {
		return "", "", noop, errors.New("proxy unavailable")
	}
	p, err := github.New(github.Config{
		Repos:   turnPol.EffectiveGitHubRepos(bot.GitHubAllow),
		Token:   func() (string, error) { return readGitHubToken(turnPol.GitHub.TokenFile) },
		GitBase: a.githubGitBase,
		APIBase: a.githubAPIBase,
		Audit:   func(ev github.Audit) { a.auditGitHub(bot.ID, ev) },
		Access:  github.AccessWrite,
		Window:  win,
	})
	if err != nil {
		return "", "", noop, errors.New("proxy unavailable")
	}
	p.Bind(safeAuditID(bot.ID), safeAuditID(a.loopRunID(bot.ID)))
	a.githubWriteUp.Store(true)
	base, err := p.ListenTCP()
	if err != nil || base == "" || p.Gate() == "" {
		a.githubWriteUp.Store(false)
		_ = p.Close()
		return "", "", noop, errors.New("proxy unavailable")
	}
	var once bool
	return base, p.Gate(), func() {
		if once {
			return
		}
		once = true
		_ = p.Close()
		a.githubWriteUp.Store(false)
	}, nil
}

// gateRoundTripper adds X-LGB-Gate on a clone of the request. It does not
// log the value.
type gateRoundTripper struct {
	base http.RoundTripper
	gate string
}

func (g gateRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if r == nil || g.gate == "" || strings.ContainsAny(g.gate, "\r\n\x00") {
		return nil, errors.New("gate")
	}
	r2 := r.Clone(r.Context())
	r2.Header.Set("X-LGB-Gate", g.gate)
	rt := g.base
	if rt == nil {
		rt = http.DefaultTransport
	}
	return rt.RoundTrip(r2)
}

// fetchUploadAdvertisement reads one smart-HTTP info/refs body through the
// read proxy. The body is capped. A transport or status failure is "remote ref".
func (a *App) fetchUploadAdvertisement(ctx context.Context, px *github.Proxy, owner, repo string) ([]byte, error) {
	if px == nil || px.Sock() == "" {
		return nil, errors.New("remote ref")
	}
	name, err := github.NormalizeRepo(owner + "/" + repo)
	if err != nil || name != owner+"/"+repo {
		return nil, errors.New("remote ref")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	lctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	rawURL := "http://proxy/github/" + owner + "/" + repo + ".git/info/refs?service=git-upload-pack"
	req, err := http.NewRequestWithContext(lctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("remote ref")
	}
	resp, err := githubUnixClient(px.Sock()).Do(req)
	if err != nil {
		return nil, errors.New("remote ref")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, errors.New("remote ref")
	}
	return body, nil
}

// githubBranchOID reads refs/heads/<branch> through the read proxy. An absent
// ref is the zero id. A transport or parse failure is "remote ref" with no body.
func (a *App) githubBranchOID(ctx context.Context, px *github.Proxy, owner, repo, branch string) (string, error) {
	if !github.BranchOK(branch) {
		return "", errors.New("remote ref")
	}
	body, err := a.fetchUploadAdvertisement(ctx, px, owner, repo)
	if err != nil {
		return "", err
	}
	oid, err := github.AdvertisedOID(body, "refs/heads/"+branch)
	if err != nil {
		return "", errors.New("remote ref")
	}
	return oid, nil
}

// githubAdvertisedHeads reads every advertised refs/heads tip in one
// info/refs response. zero is the id length for a missing ref. The map
// does not include the bot's refs/remotes.
func (a *App) githubAdvertisedHeads(ctx context.Context, px *github.Proxy, owner, repo string) (map[string]string, string, error) {
	body, err := a.fetchUploadAdvertisement(ctx, px, owner, repo)
	if err != nil {
		return nil, "", err
	}
	heads, zero, err := github.AdvertisedHeads(body)
	if err != nil {
		return nil, "", errors.New("remote ref")
	}
	return heads, zero, nil
}
