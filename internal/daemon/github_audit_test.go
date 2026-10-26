package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/github"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestAuditSandboxGitHubDenial(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lg.Close() })
	app.audit = lg
	app.recordSandbox("bot_1", sandbox.Event{
		Kind: "grant_denied", Grant: "github", Host: "github.com", Detail: sandbox.GitHubNetworkDenied,
	})
	app.recordSandbox("bot_1", sandbox.Event{
		Kind: "grant_denied", Grant: "github", Detail: sandbox.GitHubProxyDenied,
	})
	app.recordSandbox("bot_1", sandbox.Event{Kind: "grant_denied", Grant: "net", Detail: "no"})
	raw := readAudit(t, auditPath)
	if strings.Count(raw, `"action":"github_refuse"`) != 2 || !strings.Contains(raw, sandbox.GitHubNetworkDenied) || !strings.Contains(raw, sandbox.GitHubProxyDenied) {
		t.Fatalf("audit:\n%s", raw)
	}
	if !strings.Contains(raw, `"decision":"deny"`) || !strings.Contains(raw, `"host":"github.com"`) {
		t.Fatalf("audit fields:\n%s", raw)
	}
	if strings.Contains(raw, "github_refuse") && strings.Contains(raw, `"grant":"net"`) && strings.Count(raw, "github_refuse") != 2 {
		t.Fatalf("net denial audited as github:\n%s", raw)
	}
}

func TestAuditSandboxGitHubAllowlist(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lg.Close() })
	app.audit = lg
	app.recordSandbox("bot_1", sandbox.Event{
		Kind: "grant_denied", Grant: "github", Detail: sandbox.GitHubAllowlistDenied,
		Owner: "Other", Repo: "Nope",
	})
	app.recordSandbox("bot_1", sandbox.Event{
		Kind: "grant_denied", Grant: "github", Detail: sandbox.GitHubAllowlistDenied,
		Owner: "bad\nowner", Repo: "nope",
	})
	app.recordSandbox("bot_1", sandbox.Event{Kind: "grant_denied", Grant: "git", Detail: "clone"})
	app.recordSandbox("bot_1", sandbox.Event{
		Kind: "jail_report", Untrusted: true, Reported: "grant_denied",
		Grant: "github", Detail: sandbox.GitHubAllowlistDenied,
		Owner: "Other", Repo: "Nope",
	})
	raw := readAudit(t, auditPath)
	if strings.Count(raw, `"action":"github_refuse"`) != 2 || strings.Count(raw, `"reason":"allowlist"`) != 2 {
		t.Fatalf("audit:\n%s", raw)
	}
	if !strings.Contains(raw, `"owner":"other"`) || !strings.Contains(raw, `"repo":"nope"`) {
		t.Fatalf("owner/repo:\n%s", raw)
	}
	if strings.Contains(raw, "bad") || strings.Contains(raw, "\nowner") {
		t.Fatalf("unsafe owner reached the audit:\n%s", raw)
	}
	if strings.Count(raw, "\n") != 2 {
		t.Fatalf("audit line split:\n%s", raw)
	}
}

func TestAuditSandboxNetAndSSH(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lg.Close() })
	app.audit = lg
	app.recordSandbox("bot_1", sandbox.Event{Kind: "grant_denied", Grant: "net", Host: "evil.test", Detail: "missing net grant"})
	app.recordSandbox("bot_1", sandbox.Event{Kind: "grant_denied", Grant: "ssh", Host: "ssh.test", Detail: "not allowlisted"})
	app.recordSandbox("bot_1", sandbox.Event{Kind: "net_request", Grant: "net", Host: "nope.test", Detail: "not allowlisted"})
	app.recordSandbox("bot_1", sandbox.Event{Kind: "grant_denied", Grant: "github", Host: "github.com", Detail: sandbox.GitHubNetworkDenied})
	app.recordSandbox("bot_1", sandbox.Event{Kind: "grant_denied", Grant: "git", Detail: "clone"})
	app.recordSandbox("bot_1", sandbox.Event{Kind: "jail_report", Untrusted: true, Reported: "grant_denied", Grant: "net", Host: "evil.test", Detail: "missing net grant"})
	raw := readAudit(t, auditPath)
	if strings.Count(raw, `"action":"grant_denied"`) != 2 || strings.Count(raw, `"action":"net_request"`) != 1 || strings.Count(raw, `"action":"github_refuse"`) != 1 {
		t.Fatalf("audit:\n%s", raw)
	}
	if strings.Contains(raw, `"action":"grant_denied"`) && strings.Count(raw, "\n") != 4 {
		t.Fatalf("extra audit rows:\n%s", raw)
	}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		action, _ := rec["action"].(string)
		if action != "grant_denied" && action != "net_request" {
			continue
		}
		for k := range rec {
			switch k {
			case "action", "bot_id", "grant", "detail", "host", "ts":
			default:
				t.Fatalf("field %s in %s", k, line)
			}
		}
		if rec["bot_id"] != "bot_1" || rec["detail"] == "" || rec["grant"] == "" || rec["host"] == "" {
			t.Fatalf("row %s", line)
		}
	}
}

func TestOffAllowlistPushAuditsOnce(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	app.policy.GitHub.Repos = []string{"acme/widgets"}
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lg.Close() })
	app.audit = lg
	bot := store.Bot{
		ID: "bot_1", Grants: []string{"git", "github"}, GitHubAllow: []string{"acme/widgets"},
	}
	res := app.handleGitPush(t.Context(), t.Context(), bot, nil, ".", []string{
		"git", "push", "https://github.com/other/nope.git", "feature",
	})
	if res.Code == 0 || !strings.Contains(res.Stderr, "allowlist") {
		t.Fatalf("push result %+v", res)
	}
	if len(res.Events) != 1 || res.Events[0].Detail != "push allowlist (claimed other/nope from argv)" {
		t.Fatalf("detail %+v", res.Events)
	}
	for _, ev := range res.Events {
		if ev.Detail == sandbox.GitHubAllowlistDenied {
			t.Fatalf("daemon denial reused the allowlist detail: %+v", ev)
		}
		app.recordSandbox(bot.ID, ev)
	}
	raw := readAudit(t, auditPath)
	if strings.Count(raw, `"action":"github_push_denied"`) != 1 || strings.Contains(raw, `"action":"github_refuse"`) {
		t.Fatalf("audit:\n%s", raw)
	}
	if !strings.Contains(raw, `"owner":"other"`) || !strings.Contains(raw, `"repo":"nope"`) || !strings.Contains(raw, `"reason":"allowlist"`) || !strings.Contains(raw, `"claimed_from":"argv"`) {
		t.Fatalf("audit fields:\n%s", raw)
	}
}

func TestDeniedForceURLIgnoresParsedArgs(t *testing.T) {
	args := []string{"git", "push", "--force", "https://github.com/acme/widgets.git", "feature"}
	got, err := github.ParsePushArgs(args)
	if !errors.Is(err, github.ErrPushForce) || got.URL != "" || got.Names != nil {
		t.Fatalf("parsed %+v %v", got, err)
	}
	if github.PushAuditRemote(args) != "https://github.com/acme/widgets.git" {
		t.Fatalf("audit remote %q", github.PushAuditRemote(args))
	}
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	app.policy.GitHub.Repos = []string{"acme/widgets"}
	bot := store.Bot{
		ID: "bot_1", Grants: []string{"git", "github"}, GitHubAllow: []string{"acme/widgets"},
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	lg, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	res := app.handleGitPush(t.Context(), t.Context(), bot, nil, ".", args)
	_ = lg.Close()
	if res.Code == 0 {
		t.Fatalf("push result %+v", res)
	}
	raw := readAudit(t, path)
	if !strings.Contains(raw, `"owner":"acme"`) || !strings.Contains(raw, `"repo":"widgets"`) || !strings.Contains(raw, `"reason":"force push denied"`) || !strings.Contains(raw, `"claimed_from":"argv"`) {
		t.Fatalf("audit:\n%s", raw)
	}
}

func TestForceAndTagDenialNamesTheRepo(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	app.policy.GitHub.Repos = []string{"acme/widgets"}
	evals := 0
	app.perm.AddHook(func(req permission.Request) permission.HookResult {
		if req.Tool == "git_push" {
			evals++
		}
		return permission.HookResult{}
	})
	bot := store.Bot{
		ID: "bot_1", Grants: []string{"git", "github"}, GitHubAllow: []string{"acme/widgets"},
	}
	cases := []struct {
		args   []string
		reason string
		owner  string
		repo   string
	}{
		{[]string{"git", "push", "--force", "https://github.com/acme/widgets.git", "feature"}, "force push denied", "acme", "widgets"},
		{[]string{"git", "push", "--tags", "https://github.com/acme/widgets.git"}, "tag push denied", "acme", "widgets"},
		{[]string{"git", "push", "https://github.com/acme/widgets.git", "refs/tags/v1"}, "tag push denied", "acme", "widgets"},
		{[]string{"git", "push", "https://github.com/acme/widgets.git", "+feature"}, "force push denied", "acme", "widgets"},
		{[]string{"git", "push", "--force", "origin", "feature"}, "force push denied", "", ""},
		{[]string{"git", "push", "--force", "https://evil.example/acme/widgets.git"}, "force push denied", "", ""},
	}
	for _, tc := range cases {
		path := filepath.Join(t.TempDir(), "audit.log")
		lg, err := audit.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		app.audit = lg
		res := app.handleGitPush(t.Context(), t.Context(), bot, nil, ".", tc.args)
		_ = lg.Close()
		if res.Code == 0 || !strings.Contains(res.Stderr, tc.reason) {
			t.Fatalf("%v: %+v", tc.args, res)
		}
		raw := readAudit(t, path)
		if strings.Count(raw, `"action":"github_push_denied"`) != 1 || strings.Contains(raw, `"action":"github_refuse"`) {
			t.Fatalf("%v audit:\n%s", tc.args, raw)
		}
		if !strings.Contains(raw, `"reason":"`+tc.reason+`"`) || !strings.Contains(raw, `"owner":"`+tc.owner+`"`) || !strings.Contains(raw, `"repo":"`+tc.repo+`"`) {
			t.Fatalf("%v audit:\n%s", tc.args, raw)
		}
	}
	if evals != 0 {
		t.Fatalf("Evaluate ran %d times", evals)
	}
}

func TestDeniedPushNamesConfigRemote(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	app.policy.GitHub.Repos = []string{"acme/widgets"}
	writeGitRemote(t, app.ws, "https://github.com/other/lib.git")
	bot := store.Bot{
		ID: "bot_1", Grants: []string{"git", "github"}, GitHubAllow: []string{"acme/widgets"},
	}
	cases := []struct {
		args  []string
		owner string
		repo  string
		from  string
		ban   []string
	}{
		{[]string{"git", "push", "--force", "origin", "feature"}, "other", "lib", "config", []string{"acme", "widgets"}},
		{[]string{"git", "push", "--force"}, "other", "lib", "config", []string{"acme", "widgets"}},
		{[]string{"git", "push", "--force", "upstream"}, "", "", "", []string{"acme", "other", "widgets", "lib"}},
		{[]string{"git", "push", "--force", "ori\ngin"}, "", "", "", []string{"acme", "other", "widgets", "lib"}},
		{[]string{"git", "push", "--force", "https://github.com/zzz/yyy.git"}, "zzz", "yyy", "argv", []string{"acme", "other", "widgets", "lib"}},
		{[]string{"git", "push", "--force", "https://evil.example/acme/widgets.git"}, "", "", "", []string{"acme", "other", "widgets", "lib"}},
	}
	for _, tc := range cases {
		raw := deniedPushAudit(t, app, bot, tc.args)
		if !strings.Contains(raw, `"owner":"`+tc.owner+`"`) || !strings.Contains(raw, `"repo":"`+tc.repo+`"`) {
			t.Fatalf("%v audit:\n%s", tc.args, raw)
		}
		if tc.from == "" {
			if strings.Contains(raw, "claimed_from") {
				t.Fatalf("%v claim:\n%s", tc.args, raw)
			}
		} else if !strings.Contains(raw, `"claimed_from":"`+tc.from+`"`) {
			t.Fatalf("%v claim:\n%s", tc.args, raw)
		}
		for _, word := range tc.ban {
			if strings.Contains(raw, word) {
				t.Fatalf("%v contains %s:\n%s", tc.args, word, raw)
			}
		}
	}
	writeGitRemote(t, app.ws, "https://gitlab.com/other/lib.git")
	raw := deniedPushAudit(t, app, bot, []string{"git", "push", "--force", "origin"})
	if !strings.Contains(raw, `"owner":""`) || !strings.Contains(raw, `"repo":""`) || strings.Contains(raw, "claimed_from") || strings.Contains(raw, "other") || strings.Contains(raw, "gitlab") || strings.Contains(raw, "acme") {
		t.Fatalf("non-github url:\n%s", raw)
	}
}

func TestPushDenyDetail(t *testing.T) {
	app := &App{}
	cases := []struct {
		reason string
		detail string
	}{
		{"force push denied", "force push denied"},
		{"tag push denied", "tag push denied"},
		{"push option denied", "push option denied"},
		{"push failed", "push failed"},
		{"allowlist", "push allowlist"},
		{"not approved", "push not approved"},
		{"branch delete denied", "push branch delete denied"},
		{"missing grant", "push missing grant"},
	}
	for _, tc := range cases {
		ev := app.auditPush(store.Bot{ID: "bot_1"}, "acme", "widgets", "deny", tc.reason, "")
		if ev.Detail != tc.detail {
			t.Fatalf("%q detail %q", tc.reason, ev.Detail)
		}
		if ev.Detail == sandbox.GitHubAllowlistDenied {
			t.Fatalf("detail %q", ev.Detail)
		}
	}
	claimed := []struct {
		reason string
		from   string
		detail string
	}{
		{"allowlist", "argv", "push allowlist (claimed acme/widgets from argv)"},
		{"force push denied", "config", "force push denied (claimed acme/widgets from .git/config)"},
		{"missing grant", "argv", "push missing grant"},
	}
	for _, tc := range claimed {
		owner, repo := "acme", "widgets"
		if tc.reason == "missing grant" {
			owner, repo = "", ""
		}
		ev := app.auditPush(store.Bot{ID: "bot_1"}, owner, repo, "deny", tc.reason, tc.from)
		if ev.Detail != tc.detail {
			t.Fatalf("%q %q detail %q", tc.reason, tc.from, ev.Detail)
		}
	}
	ev := app.auditPush(store.Bot{ID: "bot_1"}, "acme", "widgets", "allow", "sent", "")
	if ev.Detail != "sent" || ev.Kind != "grant_use" {
		t.Fatalf("allow %+v", ev)
	}
	ev = app.auditPush(store.Bot{ID: "bot_1"}, "acme", "widgets", "allow", "sent", "argv")
	if ev.Detail != "sent" || ev.Kind != "grant_use" {
		t.Fatalf("allow with claim %+v", ev)
	}
}

func TestAllowedPushOmitsClaimedFrom(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	path := filepath.Join(t.TempDir(), "audit.log")
	lg, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	app.auditPush(store.Bot{ID: "bot_1"}, "acme", "widgets", "allow", "sent", "argv")
	app.auditPush(store.Bot{ID: "bot_1"}, "", "", "deny", "missing grant", "")
	_ = lg.Close()
	raw := readAudit(t, path)
	lines := strings.Split(strings.TrimRight(raw, "\n"), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"action":"github_push_allowed"`) || !strings.Contains(lines[1], `"action":"github_push_denied"`) {
		t.Fatalf("audit:\n%s", raw)
	}
	if strings.Contains(raw, "claimed_from") {
		t.Fatalf("claim on an unchanged row:\n%s", raw)
	}
}

func writeGitRemote(t *testing.T, root, url string) {
	t.Helper()
	writePlainGit(t, root)
	body := "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = " + url + "\n"
	if err := os.WriteFile(filepath.Join(root, ".git", "config"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func deniedPushAudit(t *testing.T, app *App, bot store.Bot, args []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	lg, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	res := app.handleGitPush(t.Context(), t.Context(), bot, nil, ".", args)
	_ = lg.Close()
	if res.Code == 0 || !strings.Contains(res.Stderr, "force push denied") {
		t.Fatalf("%v: %+v", args, res)
	}
	return readAudit(t, path)
}
