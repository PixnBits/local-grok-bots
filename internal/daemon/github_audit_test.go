package daemon

import (
	"path/filepath"
	"strings"
	"testing"

	"errors"

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
	if !strings.Contains(raw, `"owner":"other"`) || !strings.Contains(raw, `"repo":"nope"`) || !strings.Contains(raw, `"reason":"allowlist"`) {
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
	if !strings.Contains(raw, `"owner":"acme"`) || !strings.Contains(raw, `"repo":"widgets"`) || !strings.Contains(raw, `"reason":"force push denied"`) {
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
		{[]string{"git", "push", "--force", "origin", "feature"}, "force push denied", "acme", "widgets"},
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
