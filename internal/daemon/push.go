package daemon

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/github"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// gitHubGate is the host TCP address of the credential proxy. The token is
// not part of the URL.
type gitHubGate struct {
	px   *github.Proxy
	once sync.Once
	url  string
	err  error
}

func (g *gitHubGate) URL() (string, error) {
	if g == nil || g.px == nil {
		return "", errors.New("proxy unavailable")
	}
	g.once.Do(func() {
		g.url, g.err = g.px.ListenTCP()
	})
	return g.url, g.err
}

type pushSpec struct {
	src    string
	dst    string
	branch string
}

// handleGitPush rebuilds the push on the host. Hard denies return before
// Evaluate. A push that is still allowed always asks, then the daemon pushes.
func (a *App) handleGitPush(pctx, parent context.Context, bot store.Bot, gate *gitHubGate, args []string) sandbox.PushResult {
	if parent == nil {
		parent = context.Background()
	}
	if pctx == nil {
		pctx = parent
	}
	parsed, err := github.ParsePushArgs(args)
	if err != nil {
		return a.pushDenied(bot, "", "", err.Error())
	}
	if !granted(bot.Grants, "git") || !granted(bot.Grants, "github") {
		return a.pushDenied(bot, "", "", "missing grant")
	}
	ws := a.ws
	owner, repo, specs, reason := a.resolvePush(pctx, ws, parsed)
	if reason != "" {
		return a.pushDenied(bot, owner, repo, reason)
	}
	if !repoAllowed(a.policy.EffectiveGitHubRepos(bot.GitHubAllow), owner, repo) {
		return a.pushDenied(bot, owner, repo, "allowlist")
	}
	if _, err := readGitHubToken(a.policy.GitHub.TokenFile); err != nil {
		return a.pushDenied(bot, owner, repo, "token")
	}
	base, err := gate.URL()
	if err != nil || base == "" {
		return a.pushDenied(bot, owner, repo, "proxy unavailable")
	}
	lctx, lcancel := context.WithTimeout(pctx, 20*time.Second)
	defer lcancel()
	def, err := github.DefaultBranch(lctx, nil, base+"/api/repos/"+owner+"/"+repo)
	if err != nil {
		return a.pushDenied(bot, owner, repo, "default branch lookup")
	}
	var branches []string
	for _, sp := range specs {
		if sp.branch == def {
			return a.pushDenied(bot, owner, repo, "default branch")
		}
		branches = append(branches, sp.branch)
	}
	commits := clip(gitText(pctx, ws, "log", "-n", "20", "--stat", "--format=%h %s"), 4000)
	ectx, cancel := context.WithTimeout(parent, a.policy.EffectivePromptTimeout())
	defer cancel()
	stop := context.AfterFunc(pctx, cancel)
	defer stop()
	out := a.perm.Evaluate(ectx, a.policy.Permission(), a.withUserRules(bot.ID, permission.Request{
		RunID:     a.loopRunID(bot.ID),
		BotID:     bot.ID,
		Tool:      "git_push",
		ForceAsk:  true,
		Workspace: ws,
		Args: map[string]any{
			"repo":    owner + "/" + repo,
			"branch":  strings.Join(branches, ","),
			"remote":  github.RemoteURL(owner, repo),
			"commits": commits,
		},
	}))
	if out.Behavior != "allow" {
		reason := "not approved"
		if out.Source == "no_ui" {
			reason = "prompts disabled"
		}
		return a.pushDenied(bot, owner, repo, reason)
	}
	if msg, err := hostGitPush(pctx, ws, base, owner, repo, specs); err != nil {
		res := a.pushDenied(bot, owner, repo, "push failed")
		res.Stderr += sanitizePush(msg, a.policy.GitHub.TokenFile)
		return res
	}
	ev := a.auditPush(bot, owner, repo, "allow", "sent")
	return sandbox.PushResult{
		Code:   0,
		Stdout: "git push sent\n",
		Events: []sandbox.Event{ev},
	}
}

func (a *App) pushDenied(bot store.Bot, owner, repo, reason string) sandbox.PushResult {
	if reason == "" {
		reason = "not sent"
	}
	ev := a.auditPush(bot, owner, repo, "deny", reason)
	return sandbox.PushResult{
		Code:   1,
		Stderr: "git push denied: " + reason + "\n",
		Events: []sandbox.Event{ev},
	}
}

func (a *App) auditPush(bot store.Bot, owner, repo, decision, reason string) sandbox.Event {
	action := "github_push_denied"
	kind := "grant_denied"
	if decision == "allow" {
		action = "github_push_allowed"
		kind = "grant_use"
	}
	if a != nil && a.audit != nil {
		a.audit.Write(map[string]any{
			"bot":      safeAuditID(bot.ID),
			"run":      safeAuditID(a.loopRunID(bot.ID)),
			"action":   action,
			"owner":    owner,
			"repo":     repo,
			"decision": decision,
			"reason":   reason,
		})
	}
	return sandbox.Event{Kind: kind, Grant: "github", Detail: reason}
}

func repoAllowed(repos []string, owner, repo string) bool {
	want := owner + "/" + repo
	for _, r := range repos {
		if r == want {
			return true
		}
	}
	return false
}

func (a *App) resolvePush(ctx context.Context, ws string, parsed github.PushArgs) (owner, repo string, specs []pushSpec, reason string) {
	remotes := gitRemotes(ctx, ws)
	url := parsed.URL
	refs := append([]string(nil), parsed.Names...)
	if url == "" {
		var named []string
		refs = nil
		for _, n := range parsed.Names {
			if u, ok := remotes[n]; ok {
				named = append(named, u)
				continue
			}
			refs = append(refs, n)
		}
		switch len(named) {
		case 1:
			url = named[0]
		case 0:
			if len(remotes) != 1 {
				return "", "", nil, "remote"
			}
			for _, u := range remotes {
				url = u
			}
		default:
			return "", "", nil, "remote"
		}
	}
	var err error
	owner, repo, err = github.ParseGitHubRemote(url)
	if err != nil {
		return "", "", nil, "remote"
	}
	if len(refs) == 0 {
		head, herr := gitCurrentBranch(ctx, ws)
		if herr != nil {
			return owner, repo, nil, "refspec"
		}
		refs = []string{head}
	}
	if len(refs) > 8 {
		return owner, repo, nil, "refspec"
	}
	for _, raw := range refs {
		src, dst, serr := github.SplitRefspec(raw)
		if serr != nil {
			return owner, repo, nil, serr.Error()
		}
		sp, sreason := resolveSpec(ctx, ws, src, dst)
		if sreason != "" {
			return owner, repo, nil, sreason
		}
		specs = append(specs, sp)
	}
	return owner, repo, specs, ""
}

func resolveSpec(ctx context.Context, ws, src, dst string) (pushSpec, string) {
	if src != "HEAD" && gitTagExists(ctx, ws, src) {
		return pushSpec{}, "tag"
	}
	if dst != "HEAD" && gitTagExists(ctx, ws, dst) {
		return pushSpec{}, "tag"
	}
	if dst == "HEAD" || src == "HEAD" {
		head, err := gitCurrentBranch(ctx, ws)
		if err != nil {
			return pushSpec{}, "refspec"
		}
		if dst == "HEAD" {
			dst = head
		}
	}
	branch, err := github.BranchOf(dst)
	if err != nil {
		return pushSpec{}, "refspec"
	}
	sp := pushSpec{dst: "refs/heads/" + branch, branch: branch}
	if src == "HEAD" {
		sp.src = "HEAD"
		return sp, ""
	}
	srcBranch, err := github.BranchOf(src)
	if err != nil {
		return pushSpec{}, "refspec"
	}
	if !gitRefExists(ctx, ws, "refs/heads/"+srcBranch) {
		return pushSpec{}, "refspec"
	}
	sp.src = "refs/heads/" + srcBranch
	return sp, ""
}

func gitTagExists(ctx context.Context, ws, name string) bool {
	ref := name
	if !strings.HasPrefix(ref, "refs/tags/") {
		if !github.BranchOK(name) && name != "HEAD" {
			return false
		}
		ref = "refs/tags/" + name
	} else if rest := strings.TrimPrefix(ref, "refs/tags/"); !github.BranchOK(rest) {
		return false
	}
	return gitRefExists(ctx, ws, ref)
}

func gitRemotes(ctx context.Context, ws string) map[string]string {
	out := gitText(ctx, ws, "remote")
	got := map[string]string{}
	for _, name := range strings.Split(out, "\n") {
		name = strings.TrimSpace(name)
		if !remoteNameOK(name) {
			continue
		}
		u := strings.TrimSpace(gitText(ctx, ws, "remote", "get-url", name))
		if u == "" || strings.ContainsAny(u, "\r\n\t\x00") {
			continue
		}
		got[name] = u
	}
	return got
}

func remoteNameOK(s string) bool {
	if s == "" || len(s) > 100 || s[0] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func gitCurrentBranch(ctx context.Context, ws string) (string, error) {
	name := strings.TrimSpace(gitText(ctx, ws, "symbolic-ref", "--short", "HEAD"))
	if !github.BranchOK(name) {
		return "", errors.New("branch")
	}
	return name, nil
}

func gitRefExists(ctx context.Context, ws, ref string) bool {
	if ref == "" || strings.ContainsAny(ref, " \t\r\n\x00") {
		return false
	}
	_, err := gitRun(ctx, ws, "rev-parse", "--verify", "--quiet", ref)
	return err == nil
}

func gitText(ctx context.Context, ws string, args ...string) string {
	b, err := gitRun(ctx, ws, args...)
	if err != nil {
		return ""
	}
	return string(b)
}

func gitRun(ctx context.Context, ws string, args ...string) ([]byte, error) {
	cmdArgs := append([]string{"-C", ws, "--no-pager", "-c", "core.pager=cat", "-c", "safe.directory=" + ws}, args...)
	cmd := exec.CommandContext(ctx, "git", cmdArgs...)
	cmd.Env = gitPushEnv()
	return cmd.Output()
}

func sanitizePush(msg, tokenFile string) string {
	msg = clip(msg, 2000)
	tok, err := readGitHubToken(tokenFile)
	if err == nil && tok != "" {
		msg = strings.ReplaceAll(msg, tok, "")
	}
	return msg
}

func hostGitPush(ctx context.Context, ws, gate, owner, repo string, specs []pushSpec) (string, error) {
	args := []string{
		"-C", ws,
		"--no-pager",
		"-c", "safe.directory=" + ws,
		"-c", "http.proxy=",
		"-c", "http.followRedirects=false",
		"-c", "core.sshCommand=/bin/false",
		"-c", "core.hooksPath=/dev/null",
		"-c", "protocol.version=1",
		"-c", "url." + gate + "/github/.insteadOf=https://github.com/",
		"push",
		github.RemoteURL(owner, repo),
	}
	for _, sp := range specs {
		if !strings.HasPrefix(sp.dst, "refs/heads/") || (sp.src != "HEAD" && !strings.HasPrefix(sp.src, "refs/heads/")) {
			return "", errors.New("refspec")
		}
		args = append(args, sp.src+":"+sp.dst)
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = gitPushEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), err
	}
	return "", nil
}

func gitPushEnv() []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/bin:/bin"
	}
	return []string{
		"PATH=" + path,
		"HOME=/nonexistent",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"LANG=C",
	}
}
