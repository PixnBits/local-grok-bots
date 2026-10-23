package daemon

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/github"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func (a *App) toolCreatePR(ctx context.Context, bot store.Bot, args map[string]any) (string, error) {
	bot = a.freshBot(bot)
	in, owner, repo, reason := parseCreatePR(args)
	if reason != "" {
		return a.prDeny(bot, "github_pr_denied", owner, repo, reason)
	}
	if !granted(bot.Grants, "github") {
		return a.prDeny(bot, "github_pr_denied", owner, repo, "missing grant")
	}
	if !repoAllowed(a.policy.EffectiveGitHubRepos(bot.GitHubAllow), owner, repo) {
		return a.prDeny(bot, "github_pr_denied", owner, repo, "allowlist")
	}
	if _, err := readGitHubToken(a.policy.GitHub.TokenFile); err != nil {
		return a.prDeny(bot, "github_pr_denied", owner, repo, "token")
	}
	base, closeGate, err := a.openGitHubGate(bot)
	if err != nil {
		return a.prDeny(bot, "github_pr_denied", owner, repo, "proxy")
	}
	defer closeGate()
	def, err := a.githubDefaultBranch(ctx, base, owner, repo)
	if err != nil {
		return a.prDeny(bot, "github_pr_denied", owner, repo, "default branch lookup")
	}
	if in.Head == def {
		return a.prDeny(bot, "github_pr_denied", owner, repo, "default branch")
	}
	out := a.perm.Evaluate(ctx, a.policy.Permission(), a.withUserRules(bot.ID, permission.Request{
		RunID:     a.loopRunID(bot.ID),
		BotID:     bot.ID,
		Tool:      "create_pr",
		ForceAsk:  true,
		Workspace: a.ws,
		Args: map[string]any{
			"repo":  owner + "/" + repo,
			"head":  in.Head,
			"base":  in.Base,
			"title": in.Title,
			"draft": in.Draft,
			"body":  clip(in.Body, 2000),
		},
	}))
	if out.Behavior != "allow" {
		reason := "not approved"
		if out.Source == "no_ui" {
			reason = "prompts disabled"
		}
		return a.prDeny(bot, "github_pr_denied", owner, repo, reason)
	}
	pctx, pcancel := context.WithTimeout(ctx, 20*time.Second)
	defer pcancel()
	pr, err := github.CreatePull(pctx, nil, base+"/api/repos/"+owner+"/"+repo+"/pulls", owner, repo, in)
	if err != nil {
		return a.prDeny(bot, "github_pr_denied", owner, repo, githubErrReason(err))
	}
	text := mustJSON(map[string]string{"html_url": pr.URL})
	if strings.Contains(text, "\n") || strings.Contains(text, "\r") {
		return a.prDeny(bot, "github_pr_denied", owner, repo, "github response")
	}
	a.auditGitHubDecision(bot, "github_pr_allowed", owner, repo, "allow", "sent")
	return text, nil
}

func (a *App) toolPRStatus(ctx context.Context, bot store.Bot, args map[string]any) (string, error) {
	bot = a.freshBot(bot)
	owner, repo, number, reason := parsePRStatus(args)
	if reason != "" {
		return a.prDeny(bot, "github_pr_status_denied", owner, repo, reason)
	}
	if !granted(bot.Grants, "github") {
		return a.prDeny(bot, "github_pr_status_denied", owner, repo, "missing grant")
	}
	if !repoAllowed(a.policy.EffectiveGitHubRepos(bot.GitHubAllow), owner, repo) {
		return a.prDeny(bot, "github_pr_status_denied", owner, repo, "allowlist")
	}
	if _, err := readGitHubToken(a.policy.GitHub.TokenFile); err != nil {
		return a.prDeny(bot, "github_pr_status_denied", owner, repo, "token")
	}
	base, closeGate, err := a.openGitHubGate(bot)
	if err != nil {
		return a.prDeny(bot, "github_pr_status_denied", owner, repo, "proxy")
	}
	defer closeGate()
	lctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	pr, err := github.GetPull(lctx, nil, base+"/api/repos/"+owner+"/"+repo+"/pulls/"+strconv.Itoa(number), owner, repo)
	if err != nil {
		return a.prDeny(bot, "github_pr_status_denied", owner, repo, githubErrReason(err))
	}
	text := mustJSON(map[string]any{
		"html_url": pr.URL,
		"state":    pr.State,
		"draft":    pr.Draft,
		"head":     pr.Head,
		"base":     pr.Base,
	})
	a.auditGitHubDecision(bot, "github_pr_status", owner, repo, "allow", "read")
	return text, nil
}

func parseCreatePR(args map[string]any) (github.NewPull, string, string, string) {
	repoArg, ok := plainString(args, "repo")
	if !ok {
		return github.NewPull{}, "", "", "arguments"
	}
	name, err := github.NormalizeRepo(repoArg)
	if err != nil {
		return github.NewPull{}, "", "", "arguments"
	}
	owner, repo, _ := strings.Cut(name, "/")
	head, ok := plainString(args, "head")
	if !ok || !github.PullBranch(head) {
		return github.NewPull{}, owner, repo, "arguments"
	}
	base, ok := plainString(args, "base")
	if !ok || !github.PullBranch(base) {
		return github.NewPull{}, owner, repo, "arguments"
	}
	title, ok := plainString(args, "title")
	if !ok || !github.ValidPullTitle(title) {
		return github.NewPull{}, owner, repo, "arguments"
	}
	body := ""
	if _, present := args["body"]; present {
		body, ok = plainString(args, "body")
		if !ok || !github.ValidPullBody(body) {
			return github.NewPull{}, owner, repo, "arguments"
		}
	}
	draft := true
	if _, present := args["draft"]; present {
		v, isBool := args["draft"].(bool)
		if !isBool {
			return github.NewPull{}, owner, repo, "arguments"
		}
		draft = v
	}
	return github.NewPull{Title: title, Body: body, Head: head, Base: base, Draft: draft}, owner, repo, ""
}

func parsePRStatus(args map[string]any) (owner, repo string, number int, reason string) {
	repoArg, ok := plainString(args, "repo")
	if !ok {
		return "", "", 0, "arguments"
	}
	name, err := github.NormalizeRepo(repoArg)
	if err != nil {
		return "", "", 0, "arguments"
	}
	owner, repo, _ = strings.Cut(name, "/")
	n, ok := prNumber(args["number"])
	if !ok {
		return owner, repo, 0, "arguments"
	}
	return owner, repo, n, ""
}

func plainString(args map[string]any, key string) (string, bool) {
	v, ok := args[key]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func prNumber(v any) (int, bool) {
	f, ok := v.(float64)
	if !ok || f < 1 || f > 1_000_000_000 || f != float64(int(f)) {
		return 0, false
	}
	return int(f), true
}

func (a *App) prDeny(bot store.Bot, action, owner, repo, reason string) (string, error) {
	if reason == "" {
		reason = "not approved"
	}
	a.auditGitHubDecision(bot, action, owner, repo, "deny", reason)
	return "", errors.New(prDenyText(reason))
}

func prDenyText(reason string) string {
	switch reason {
	case "arguments":
		return "invalid arguments"
	case "missing grant":
		return "github grant required"
	case "allowlist":
		return "repository is not allowlisted"
	case "token":
		return "github token unavailable"
	case "proxy":
		return "github proxy unavailable"
	case "default branch lookup":
		return "default branch lookup failed"
	case "default branch":
		return "head is the default branch"
	case "prompts disabled":
		return "prompts disabled"
	case "not approved":
		return "not approved"
	default:
		if reason == "github unavailable" || reason == "github response" || strings.HasPrefix(reason, "github status ") {
			return reason
		}
		return "not approved"
	}
}

func githubErrReason(err error) string {
	var api *github.APIError
	if errors.As(err, &api) {
		return api.Error()
	}
	return "github response"
}

func (a *App) auditGitHubDecision(bot store.Bot, action, owner, repo, decision, reason string) {
	if a == nil {
		return
	}
	if a.audit != nil {
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
	kind := "grant_denied"
	if decision == "allow" {
		kind = "grant_use"
	}
	a.log(bot.ID, kind, map[string]any{"grant": "github", "detail": reason})
}

func (a *App) freshBot(bot store.Bot) store.Bot {
	if a != nil && a.st != nil {
		if fresh, err := a.st.GetBot(bot.ID); err == nil {
			return fresh
		}
	}
	return bot
}

func (a *App) githubDefaultBranch(ctx context.Context, base, owner, repo string) (string, error) {
	lctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return github.DefaultBranch(lctx, nil, base+"/api/repos/"+owner+"/"+repo)
}

func (a *App) openGitHubGate(bot store.Bot) (string, func(), error) {
	noop := func() {}
	px, err := a.openGitHubProxy(bot)
	if err != nil || px == nil {
		return "", noop, errors.New("proxy unavailable")
	}
	base, err := px.ListenTCP()
	if err != nil || base == "" {
		_ = px.Close()
		return "", noop, errors.New("proxy unavailable")
	}
	return base, func() { _ = px.Close() }, nil
}
