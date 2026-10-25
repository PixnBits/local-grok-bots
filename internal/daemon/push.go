package daemon

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/github"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// gitHubGate is the read proxy mounted in the jail. Push does not call
// ListenTCP on it. Writes use a separate proxy opened after the card.
type gitHubGate struct {
	px *github.Proxy
}

type pushSpec struct {
	src    string
	dst    string
	branch string
}

// handleGitPush rebuilds the push on the host from a mirror. Hard denies
// return before Evaluate. A push that is still allowed always asks.
func (a *App) handleGitPush(pctx, parent context.Context, bot store.Bot, gate *gitHubGate, cwd string, args []string) sandbox.PushResult {
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
	repos := []string(nil)
	ws := ""
	if a != nil {
		repos = a.policy.EffectiveGitHubRepos(bot.GitHubAllow)
		ws = a.ws
	}
	owner, repo, reason := pushTarget(parsed, repos)
	if reason != "" {
		return a.pushDenied(bot, owner, repo, reason)
	}
	if !repoAllowed(repos, owner, repo) {
		return a.pushDenied(bot, owner, repo, "allowlist")
	}
	tokenFile := ""
	if a != nil {
		tokenFile = a.policy.GitHub.TokenFile
	}
	if _, err := readGitHubToken(tokenFile); err != nil {
		return a.pushDenied(bot, owner, repo, "token")
	}
	if gate == nil || gate.px == nil || gate.px.Sock() == "" {
		return a.pushDenied(bot, owner, repo, "proxy unavailable")
	}
	held, locReason := resolveWorkspaceRepo(ws, cwd)
	defer held.Close()
	if locReason != "" || held == nil {
		if locReason == "" {
			locReason = "repository not found in workspace"
		}
		return a.pushDenied(bot, owner, repo, locReason)
	}
	if held.configReason() == "config" {
		return a.pushDenied(bot, owner, repo, "config")
	}
	parentDir := filepath.Join(a.cfg.DataDir, "mirrors")
	mirror, err := copyGitMirror(parentDir, held)
	if err != nil {
		return a.pushDenied(bot, owner, repo, "mirror")
	}
	defer os.RemoveAll(mirror)
	if !held.stable() {
		return a.pushDenied(bot, owner, repo, "mirror")
	}
	if held.configReason() == "config" {
		return a.pushDenied(bot, owner, repo, "config")
	}
	specs, reason := resolvePushRefs(mirror, parsed)
	if reason != "" {
		return a.pushDenied(bot, owner, repo, reason)
	}
	def, err := a.githubDefaultBranch(pctx, gate.px, owner, repo)
	if err != nil {
		return a.pushDenied(bot, owner, repo, "default branch lookup")
	}
	var branches []string
	for _, sp := range specs {
		if strings.EqualFold(sp.branch, def) {
			return a.pushDenied(bot, owner, repo, "default branch")
		}
		branches = append(branches, sp.branch)
	}
	if len(specs) == 0 {
		return a.pushDenied(bot, owner, repo, "refspec")
	}
	old, oerr := a.githubBranchOID(pctx, gate.px, owner, repo, specs[0].branch)
	if oerr != nil {
		return a.pushDenied(bot, owner, repo, "remote ref")
	}
	commits, err := mirrorLog(pctx, mirror, specs)
	if err != nil {
		return a.pushDenied(bot, owner, repo, "mirror")
	}
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
			"commits": clip(commits, 4000),
		},
	}))
	if out.Behavior != "allow" {
		reason := "not approved"
		if out.Source == "no_ui" {
			reason = "prompts disabled"
		}
		return a.pushDenied(bot, owner, repo, reason)
	}
	if !held.stable() {
		return a.pushDenied(bot, owner, repo, "mirror")
	}
	if held.configReason() == "config" {
		return a.pushDenied(bot, owner, repo, "config")
	}
	branch := ""
	if len(specs) > 0 {
		branch = specs[0].branch
	}
	base, gateSecret, closeWrite, err := a.openGitHubWriteGate(bot, github.Window{
		Kind: github.WindowPush, Owner: owner, Repo: repo, Branch: branch, Default: def, Old: old,
	})
	if err != nil {
		return a.pushDenied(bot, owner, repo, "proxy unavailable")
	}
	defer closeWrite()
	remote, err := proxyGitURL(base, owner, repo)
	if err != nil {
		return a.pushDenied(bot, owner, repo, "proxy unavailable")
	}
	if msg, err := mirrorPush(pctx, mirror, remote, gateSecret, specs); err != nil {
		res := a.pushDenied(bot, owner, repo, "push failed")
		res.Stderr += sanitizePush(msg, tokenFile, gateSecret)
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
	for _, r := range repos {
		o, n, ok := strings.Cut(r, "/")
		if ok && strings.EqualFold(o, owner) && strings.EqualFold(n, repo) {
			return true
		}
	}
	return false
}

func pushTarget(parsed github.PushArgs, repos []string) (owner, repo, reason string) {
	if parsed.URL != "" {
		owner, repo, err := github.ParseGitHubRemote(parsed.URL)
		if err != nil {
			return "", "", "remote"
		}
		return owner, repo, ""
	}
	if len(repos) != 1 {
		return "", "", "remote"
	}
	owner, repo, ok := strings.Cut(repos[0], "/")
	if !ok {
		return "", "", "remote"
	}
	name, err := github.NormalizeRepo(owner + "/" + repo)
	if err != nil || name != owner+"/"+repo {
		return "", "", "remote"
	}
	return owner, repo, ""
}

func proxyGitURL(base, owner, repo string) (string, error) {
	name, err := github.NormalizeRepo(owner + "/" + repo)
	if err != nil || name != owner+"/"+repo {
		return "", errors.New("remote")
	}
	u, err := url.Parse(base)
	if err != nil || u.User != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" {
		return "", errors.New("proxy")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.Port() == "" {
		return "", errors.New("proxy")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("proxy")
	}
	u.Path = "/github/" + owner + "/" + repo + ".git"
	u.RawPath = ""
	return u.String(), nil
}

func resolvePushRefs(mirror string, parsed github.PushArgs) ([]pushSpec, string) {
	names := append([]string(nil), parsed.Names...)
	if parsed.URL == "" && len(names) >= 2 {
		first := names[0]
		if first != "HEAD" && !strings.Contains(first, ":") && github.BranchOK(first) {
			ok, err := refPresent(mirror, "refs/heads/"+first)
			if err != nil {
				return nil, "refspec"
			}
			if !ok {
				names = names[1:]
			}
		}
	}
	if len(names) == 0 {
		names = []string{"HEAD"}
	}
	if len(names) > 8 {
		return nil, "refspec"
	}
	var specs []pushSpec
	for _, raw := range names {
		src, dst, err := github.SplitRefspec(raw)
		if err != nil {
			return nil, err.Error()
		}
		sp, reason := resolveSpec(mirror, src, dst)
		if reason != "" {
			return nil, reason
		}
		specs = append(specs, sp)
	}
	return specs, ""
}

func resolveSpec(mirror, src, dst string) (pushSpec, string) {
	if src != "HEAD" {
		ok, reason := tagPresent(mirror, src)
		if reason != "" {
			return pushSpec{}, reason
		}
		if ok {
			return pushSpec{}, "tag"
		}
	}
	if dst != "HEAD" {
		ok, reason := tagPresent(mirror, dst)
		if reason != "" {
			return pushSpec{}, reason
		}
		if ok {
			return pushSpec{}, "tag"
		}
	}
	if src == "HEAD" || dst == "HEAD" {
		head, err := mirrorHEAD(mirror)
		if err != nil {
			return pushSpec{}, "refspec"
		}
		if src == "HEAD" {
			src = head
		}
		if dst == "HEAD" {
			dst = head
		}
	}
	branch, err := github.BranchOf(dst)
	if err != nil {
		return pushSpec{}, "refspec"
	}
	srcBranch, err := github.BranchOf(src)
	if err != nil {
		return pushSpec{}, "refspec"
	}
	ok, err := refPresent(mirror, "refs/heads/"+srcBranch)
	if err != nil || !ok {
		return pushSpec{}, "refspec"
	}
	return pushSpec{src: "refs/heads/" + srcBranch, dst: "refs/heads/" + branch, branch: branch}, ""
}

func tagPresent(mirror, name string) (bool, string) {
	if name == "" || name == "HEAD" || strings.Contains(name, ":") {
		return false, ""
	}
	ref := name
	if strings.HasPrefix(name, "refs/tags/") {
		ref = name
		if !github.BranchOK(strings.TrimPrefix(name, "refs/tags/")) {
			return false, "refspec"
		}
	} else if !github.BranchOK(name) {
		return false, ""
	} else {
		ref = "refs/tags/" + name
	}
	ok, err := refPresent(mirror, ref)
	if err != nil {
		return false, "refspec"
	}
	return ok, ""
}

func mirrorHEAD(root string) (string, error) {
	path := filepath.Join(root, "HEAD")
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 300 {
		return "", errors.New("refspec")
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 300 {
		return "", errors.New("refspec")
	}
	s := strings.TrimSpace(string(b))
	rest, ok := strings.CutPrefix(s, "ref: ")
	if !ok || strings.ContainsAny(rest, " \t\r\n\x00") {
		return "", errors.New("refspec")
	}
	name, ok := strings.CutPrefix(rest, "refs/heads/")
	if !ok || !github.BranchOK(name) {
		return "", errors.New("refspec")
	}
	present, err := refPresent(root, "refs/heads/"+name)
	if err != nil || !present {
		return "", errors.New("refspec")
	}
	return name, nil
}

func refPresent(root, rel string) (bool, error) {
	if rel == "" || strings.Contains(rel, "..") || strings.HasPrefix(rel, "/") || strings.ContainsAny(rel, " \t\r\n\x00") {
		return false, errors.New("ref")
	}
	full := filepath.Join(root, filepath.Clean(rel))
	back, err := filepath.Rel(root, full)
	if err != nil || back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) {
		return false, errors.New("ref")
	}
	st, err := os.Lstat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return packedHas(root, rel), nil
		}
		return false, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return false, errors.New("ref")
	}
	return true, nil
}

func packedHas(root, ref string) bool {
	path := filepath.Join(root, "packed-refs")
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") {
			continue
		}
		sha, name, ok := strings.Cut(line, " ")
		if !ok || name != ref || !hexSHA(sha) {
			continue
		}
		return true
	}
	return false
}

func hexSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func sanitizePush(msg, tokenFile, gate string) string {
	msg = clip(msg, 2000)
	tok, err := readGitHubToken(tokenFile)
	if err == nil && tok != "" {
		msg = strings.ReplaceAll(msg, tok, "")
	}
	if gate != "" {
		msg = strings.ReplaceAll(msg, gate, "")
	}
	return msg
}
