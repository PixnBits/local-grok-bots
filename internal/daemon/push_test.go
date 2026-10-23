package daemon

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

const pushSecret = "lgb-github-test-secret-value"

func TestGitPushHostApproval(t *testing.T) {
	for _, bin := range []string{"git", "bwrap", "gcc"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Fatalf("%s is required", bin)
		}
	}
	bare := t.TempDir()
	gitOK(t, "init", "--bare", bare)
	gitOK(t, "-C", bare, "symbolic-ref", "HEAD", "refs/heads/main")

	var mu sync.Mutex
	var auths []string
	var paths []string
	var packs atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/info/refs"):
			w.Header().Set("Content-Type", "application/x-git-receive-pack-advertisement")
			w.Header().Set("Cache-Control", "no-cache")
			pkt := "# service=git-receive-pack\n"
			fmt.Fprintf(w, "%04x%s0000", len(pkt)+4, pkt)
			cmd := exec.Command("git", "receive-pack", "--stateless-rpc", "--advertise-refs", bare)
			cmd.Stdout = w
			_ = cmd.Run()
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git-receive-pack"):
			packs.Add(1)
			w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
			cmd := exec.Command("git", "receive-pack", "--stateless-rpc", bare)
			cmd.Stdin = r.Body
			cmd.Stdout = w
			_ = cmd.Run()
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"default_branch":"main"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)

	prev := readGitHubToken
	readGitHubToken = func(string) (string, error) { return pushSecret, nil }
	t.Cleanup(func() { readGitHubToken = prev })

	newPushApp := func(t *testing.T) (*App, *atomic.Int32, string) {
		t.Helper()
		app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
			return model.ChatResponse{Content: "no"}, nil
		}})
		app.githubGitBase = upstream.URL
		app.githubAPIBase = upstream.URL
		app.policy.GitHub.Repos = []string{"acme/widgets"}
		app.policy.GitHub.TokenFile = "/etc/local-grok-bots/github.token"
		app.policy.UIPrompts = true
		app.policy.PromptTimeout = 20 * time.Second
		auditPath := filepath.Join(t.TempDir(), "audit.log")
		lg, err := audit.Open(auditPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lg.Close() })
		app.audit = lg
		var evals atomic.Int32
		var notForced atomic.Bool
		app.perm.AddHook(func(req permission.Request) permission.HookResult {
			if req.Tool == "git_push" {
				evals.Add(1)
				if !req.ForceAsk {
					notForced.Store(true)
				}
			}
			return permission.HookResult{}
		})
		t.Cleanup(func() {
			if notForced.Load() {
				t.Errorf("git_push was not ForceAsk")
			}
		})
		return app, &evals, auditPath
	}

	runPush := func(t *testing.T, app *App, auditPath string, repos []string, command string, approve bool) (string, error) {
		t.Helper()
		srv := serve(t, app)
		bot := createGrantedBot(t, srv.URL, "Ada", []string{"git", "github"})
		if repos != nil {
			res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"github_allow": repos}, "")
			if res.StatusCode != 200 {
				t.Fatalf("allow %d %s", res.StatusCode, b)
			}
		}
		var done <-chan error
		if approve {
			done = approveGitPush(app, bot.ID)
		}
		out, err := app.dispatchTool(t.Context(), bot, "run_shell", map[string]any{"command": command})
		if done != nil {
			if aerr := <-done; aerr != nil {
				t.Error(aerr)
			}
		}
		assertNoPushSecret(t, app, auditPath, out, logBody(t, srv.URL))
		return out, err
	}

	feature := func(branch, msg, extra string) string {
		return fmt.Sprintf(`set -e
env
printf '%%s' "$0"
cat /proc/self/mountinfo
git init
git checkout -b %s
echo hello > readme.txt
git add readme.txt
git commit -m %q
%s
echo PUSH_DONE
`, branch, msg, extra)
	}

	t.Run("card and send", func(t *testing.T) {
		app, evals, auditPath := newPushApp(t)
		packsBefore := packs.Load()
		out, err := runPush(t, app, auditPath, []string{"acme/widgets"}, feature("feature", "note-sent", "git push https://github.com/acme/widgets.git feature"), true)
		if err != nil || !strings.Contains(out, "git push sent") || !strings.Contains(out, "PUSH_DONE") {
			t.Fatalf("send: %v\n%s", err, out)
		}
		if !strings.Contains(readAudit(t, auditPath), "github_push_allowed") {
			t.Fatal("audit missing github_push_allowed")
		}
		if evals.Load() == 0 {
			t.Fatal("card path did not call Evaluate")
		}
		if packs.Load() <= packsBefore {
			t.Fatal("receive-pack was not called")
		}
		log := gitOK(t, "--git-dir", bare, "log", "--all", "--format=%s")
		if !strings.Contains(log, "note-sent") {
			t.Fatalf("bare repo log:\n%s", log)
		}
		mu.Lock()
		gotAuth := append([]string(nil), auths...)
		gotPaths := append([]string(nil), paths...)
		mu.Unlock()
		if len(gotAuth) == 0 {
			t.Fatal("upstream saw no requests")
		}
		for _, h := range gotAuth {
			if h != "Bearer "+pushSecret {
				t.Fatalf("upstream auth %q", h)
			}
		}
		var sawGit bool
		for _, p := range gotPaths {
			if strings.Contains(p, "/acme/widgets") {
				sawGit = true
			}
			if strings.Contains(p, pushSecret) {
				t.Fatalf("token in path %s", p)
			}
		}
		if !sawGit {
			t.Fatalf("paths %v", gotPaths)
		}
	})

	t.Run("bypass still asks", func(t *testing.T) {
		app, evals, auditPath := newPushApp(t)
		app.policy.PermissionMode = "bypassPermissions"
		out, err := runPush(t, app, auditPath, []string{"acme/widgets"}, feature("feature-bypass", "note-bypass", "git push https://github.com/acme/widgets.git feature-bypass"), true)
		if err != nil || !strings.Contains(out, "git push sent") || evals.Load() == 0 {
			t.Fatalf("bypass skipped the card: %v evals=%d\n%s", err, evals.Load(), out)
		}
	})

	t.Run("managed allow still asks", func(t *testing.T) {
		app, evals, auditPath := newPushApp(t)
		app.policy.ToolAllow = []string{"git_push"}
		out, err := runPush(t, app, auditPath, []string{"acme/widgets"}, feature("feature-allow", "note-allow", "git push https://github.com/acme/widgets.git feature-allow"), true)
		if err != nil || !strings.Contains(out, "git push sent") || evals.Load() == 0 {
			t.Fatalf("managed allow skipped the card: %v evals=%d\n%s", err, evals.Load(), out)
		}
	})

	t.Run("durable allow still asks", func(t *testing.T) {
		app, evals, auditPath := newPushApp(t)
		srv := serve(t, app)
		bot := createGrantedBot(t, srv.URL, "Ada", []string{"git", "github"})
		res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"github_allow": []string{"acme/widgets"}}, "")
		if res.StatusCode != 200 {
			t.Fatalf("allow %d %s", res.StatusCode, b)
		}
		if _, err := app.st.InsertUserPermRule(store.UserPermRule{BotID: bot.ID, Effect: "allow", Pattern: "git_push"}); err != nil {
			t.Fatal(err)
		}
		done := approveGitPush(app, bot.ID)
		out, err := app.dispatchTool(t.Context(), bot, "run_shell", map[string]any{"command": feature("feature-user", "note-user", "git push https://github.com/acme/widgets.git feature-user")})
		if aerr := <-done; aerr != nil {
			t.Error(aerr)
		}
		assertNoPushSecret(t, app, auditPath, out, logBody(t, srv.URL))
		if err != nil || !strings.Contains(out, "git push sent") || evals.Load() == 0 {
			t.Fatalf("durable allow skipped the card: %v evals=%d\n%s", err, evals.Load(), out)
		}
	})

	deny := func(t *testing.T, command, reason string) {
		t.Helper()
		app, evals, auditPath := newPushApp(t)
		before := packs.Load()
		out, err := runPush(t, app, auditPath, []string{"acme/widgets"}, command, false)
		if err == nil || strings.Contains(out, "PUSH_DONE") || strings.Contains(out, "git push sent") {
			t.Fatalf("push was sent: %v\n%s", err, out)
		}
		if !strings.Contains(out, reason) {
			t.Fatalf("reason %s missing:\n%s", reason, out)
		}
		if evals.Load() != 0 {
			t.Fatalf("Evaluate ran for %s (%d)", reason, evals.Load())
		}
		if packs.Load() != before {
			t.Fatalf("receive-pack ran for %s", reason)
		}
		if !strings.Contains(readAudit(t, auditPath), "github_push_denied") {
			t.Fatalf("audit missing denial for %s", reason)
		}
	}

	t.Run("force", func(t *testing.T) {
		deny(t, feature("feature", "note-force", "git push --force https://github.com/acme/widgets.git feature"), "force")
		deny(t, feature("feature", "note-lease", "git push --force-with-lease https://github.com/acme/widgets.git feature"), "force")
		deny(t, feature("feature", "note-plus", "git push https://github.com/acme/widgets.git +feature"), "force")
		deny(t, feature("feature", "note-f", "git push -f https://github.com/acme/widgets.git feature"), "force")
	})
	t.Run("durable allow does not bypass force", func(t *testing.T) {
		app, evals, auditPath := newPushApp(t)
		srv := serve(t, app)
		bot := createGrantedBot(t, srv.URL, "Ada", []string{"git", "github"})
		res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"github_allow": []string{"acme/widgets"}}, "")
		if res.StatusCode != 200 {
			t.Fatalf("allow %d %s", res.StatusCode, b)
		}
		if _, err := app.st.InsertUserPermRule(store.UserPermRule{BotID: bot.ID, Effect: "allow", Pattern: "git_push"}); err != nil {
			t.Fatal(err)
		}
		before := packs.Load()
		out, err := app.dispatchTool(t.Context(), bot, "run_shell", map[string]any{"command": feature("feature", "note-force-user", "git push --force https://github.com/acme/widgets.git feature")})
		assertNoPushSecret(t, app, auditPath, out, logBody(t, srv.URL))
		if err == nil || !strings.Contains(out, "force") || evals.Load() != 0 || packs.Load() != before || strings.Contains(out, "PUSH_DONE") {
			t.Fatalf("force with a durable allow: %v evals=%d\n%s", err, evals.Load(), out)
		}
	})
	t.Run("delete and tag", func(t *testing.T) {
		deny(t, feature("feature", "note-del", "git push https://github.com/acme/widgets.git :feature"), "delete")
		deny(t, feature("feature", "note-tag", "git tag v1\ngit push https://github.com/acme/widgets.git refs/tags/v1"), "tag")
		deny(t, feature("feature", "note-tag-src", "git tag v2\ngit push https://github.com/acme/widgets.git v2"), "tag")
	})
	t.Run("default branch", func(t *testing.T) {
		cmd := `set -e
git init
git checkout -b main
echo hello > readme.txt
git add readme.txt
git commit -m note-main
git push https://github.com/acme/widgets.git main
echo PUSH_DONE
`
		deny(t, cmd, "default branch")
	})
	t.Run("empty allowlist", func(t *testing.T) {
		app, evals, auditPath := newPushApp(t)
		before := packs.Load()
		out, err := runPush(t, app, auditPath, nil, feature("feature", "note-empty", "git push https://github.com/acme/widgets.git feature"), false)
		if err == nil || !strings.Contains(out, "allowlist") || evals.Load() != 0 || packs.Load() != before {
			t.Fatalf("empty allowlist: %v evals=%d\n%s", err, evals.Load(), out)
		}
	})
	t.Run("prompts off", func(t *testing.T) {
		app, evals, auditPath := newPushApp(t)
		app.policy.UIPrompts = false
		before := packs.Load()
		out, err := runPush(t, app, auditPath, []string{"acme/widgets"}, feature("feature-ui", "note-ui", "git push https://github.com/acme/widgets.git feature-ui"), false)
		if err == nil || strings.Contains(out, "PUSH_DONE") || !strings.Contains(out, "denied") {
			t.Fatalf("prompts off: %v\n%s", err, out)
		}
		if evals.Load() == 0 {
			t.Fatal("prompts off did not call Evaluate")
		}
		if packs.Load() != before {
			t.Fatal("prompts off pushed")
		}
	})
}

func approveGitPush(app *App, botID string) <-chan error {
	errc := make(chan error, 1)
	go func() {
		defer close(errc)
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			list := app.perm.Pending(botID)
			if len(list) > 0 {
				id, _ := list[0]["id"].(string)
				runID, _ := list[0]["run_id"].(string)
				if list[0]["tool"] != "git_push" {
					errc <- fmt.Errorf("card tool %#v", list[0]["tool"])
					return
				}
				if err := app.perm.DecideFor(botID, runID, id, permission.AllowOnce); err != nil {
					errc <- err
				}
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
		errc <- errors.New("approval card did not appear")
	}()
	return errc
}

func assertNoPushSecret(t *testing.T, app *App, auditPath, toolOut, logs string) {
	t.Helper()
	if strings.Contains(toolOut, pushSecret) {
		t.Fatalf("token in tool output:\n%s", toolOut)
	}
	if strings.Contains(logs, pushSecret) {
		t.Fatal("token in the event log")
	}
	raw := readAudit(t, auditPath)
	if strings.Contains(raw, pushSecret) || strings.Contains(raw, "Bearer") {
		t.Fatalf("token in audit:\n%s", raw)
	}
	cmd := exec.Command("grep", "-R", "-F", "-q", pushSecret, app.ws)
	if err := cmd.Run(); err == nil {
		t.Fatal("token in the workspace mount")
	}
}

func readAudit(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func gitOK(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v %s", strings.Join(args, " "), err, b)
	}
	return string(b)
}

func logBody(t *testing.T, base string) string {
	t.Helper()
	_, b := do(t, "GET", base+"/api/logs", nil, "")
	return string(b)
}
