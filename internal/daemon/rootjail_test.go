package daemon

import (
	"bytes"
	"errors"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

func TestRootWithoutBwrapWarnsAndRefusesShell(t *testing.T) {
	prevE, prevL, prevC := sandbox.EUID, sandbox.LookPath, sandbox.Chown
	sandbox.Chown = func(string, int, int) error { return nil }
	sandbox.EUID = func() int { return 0 }
	sandbox.LookPath = func(name string) (string, error) {
		if name == "bwrap" {
			return "", errors.New("not found")
		}
		return exec.LookPath(name)
	}
	t.Cleanup(func() { sandbox.EUID, sandbox.LookPath, sandbox.Chown = prevE, prevL, prevC })

	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	_ = w.Close()
	os.Stderr = old
	var stderr bytes.Buffer
	if _, err := io.Copy(&stderr, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "root requires bwrap") {
		t.Fatalf("startup stderr %q", stderr.String())
	}

	srv := serve(t, app)
	res, body := do(t, "GET", srv.URL+"/api/health", nil, "")
	if res.StatusCode != 200 || !strings.Contains(string(body), "root requires bwrap") || !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf("health %d %s", res.StatusCode, body)
	}

	bot := createGrantedBot(t, srv.URL, "Ada", []string{"git", "github"})
	out, err := app.dispatchTool(t.Context(), bot, "run_shell", map[string]any{"command": "git status"})
	if err == nil || !strings.Contains(err.Error(), "shell sandbox unavailable: root requires bwrap") {
		t.Fatalf("run_shell %v %s", err, out)
	}
	if strings.Contains(out, "On branch") || strings.Contains(err.Error(), "On branch") {
		t.Fatalf("git ran: %v %s", err, out)
	}

	sandbox.LookPath = func(name string) (string, error) {
		if name == "bwrap" {
			return "/usr/bin/bwrap", nil
		}
		return exec.LookPath(name)
	}
	res, body = do(t, "GET", srv.URL+"/api/health", nil, "")
	if res.StatusCode != 200 || strings.Contains(string(body), "warning") || strings.Contains(string(body), "bwrap") {
		t.Fatalf("root with bwrap health %d %s", res.StatusCode, body)
	}

	sandbox.EUID = func() int { return 1000 }
	sandbox.LookPath = func(string) (string, error) { return "", errors.New("not found") }
	res, body = do(t, "GET", srv.URL+"/api/health", nil, "")
	if res.StatusCode != 200 || strings.Contains(string(body), "warning") {
		t.Fatalf("non-root health %d %s", res.StatusCode, body)
	}
}

func TestRootWithoutBwrapRefusesGitHubTools(t *testing.T) {
	prevE, prevL, prevC, prevTok := sandbox.EUID, sandbox.LookPath, sandbox.Chown, readGitHubToken
	sandbox.Chown = func(string, int, int) error { return nil }
	sandbox.EUID = func() int { return 0 }
	sandbox.LookPath = func(name string) (string, error) {
		if name == "bwrap" {
			return "", errors.New("not found")
		}
		return exec.LookPath(name)
	}
	readGitHubToken = func(string) (string, error) {
		t.Error("token file was read")
		return "", errors.New("token")
	}
	t.Cleanup(func() {
		sandbox.EUID, sandbox.LookPath, sandbox.Chown, readGitHubToken = prevE, prevL, prevC, prevTok
	})

	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	app.editPol(func(p *policy.Policy) { p.GitHub.Repos = []string{"acme/widgets"} })
	var asked atomic.Bool
	app.perm.AddHook(func(req permission.Request) permission.HookResult {
		if req.Tool == "create_pr" || req.Tool == "pr_status" {
			asked.Store(true)
		}
		return permission.HookResult{}
	})
	srv := serve(t, app)
	bot := createGrantedBot(t, srv.URL, "Ada", []string{"github"})
	res, body := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"github_allow": []string{"acme/widgets"}}, "")
	if res.StatusCode != 200 {
		t.Fatalf("allow %d %s", res.StatusCode, body)
	}
	createArgs := map[string]any{
		"repo": "acme/widgets", "head": "feature", "base": "main", "title": "Add a widget",
	}
	out, err := app.dispatchTool(t.Context(), bot, "create_pr", createArgs)
	if err == nil || !strings.Contains(err.Error(), "root requires bwrap") {
		t.Fatalf("create_pr %v %s", err, out)
	}
	out, err = app.dispatchTool(t.Context(), bot, "pr_status", map[string]any{"repo": "acme/widgets", "number": float64(7)})
	if err == nil || !strings.Contains(err.Error(), "root requires bwrap") {
		t.Fatalf("pr_status %v %s", err, out)
	}
	if asked.Load() || len(app.perm.Pending(bot.ID)) != 0 {
		t.Fatal("root without bwrap opened a card")
	}
}
