package daemon

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"io"
	"net"
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
		app.editPol(func(p *policy.Policy) { p.GitHub.Repos = []string{"acme/widgets"} })
		app.editPol(func(p *policy.Policy) { p.GitHub.TokenFile = "/etc/local-grok-bots/github.token" })
		app.editPol(func(p *policy.Policy) { p.UIPrompts = true })
		app.editPol(func(p *policy.Policy) { p.PromptTimeout = 20 * time.Second })
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
		rawAudit := readAudit(t, auditPath)
		if !strings.Contains(rawAudit, "github_push_allowed") {
			t.Fatal("audit missing github_push_allowed")
		}
		if !strings.Contains(rawAudit, `"method":"GET"`) || !strings.Contains(rawAudit, `"method":"POST"`) {
			t.Fatalf("audit missing method:\n%s", rawAudit)
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
		for i, h := range gotAuth {
			pth := ""
			if i < len(gotPaths) {
				pth = gotPaths[i]
			}
			if strings.Contains(pth, "/repos/") {
				if h != "Bearer "+pushSecret {
					t.Fatalf("api auth %q path %s", h, pth)
				}
				continue
			}
			want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+pushSecret))
			if h != want {
				t.Fatalf("git auth %q path %s", h, pth)
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
		app.editPol(func(p *policy.Policy) { p.PermissionMode = "bypassPermissions" })
		out, err := runPush(t, app, auditPath, []string{"acme/widgets"}, feature("feature-bypass", "note-bypass", "git push https://github.com/acme/widgets.git feature-bypass"), true)
		if err != nil || !strings.Contains(out, "git push sent") || evals.Load() == 0 {
			t.Fatalf("bypass skipped the card: %v evals=%d\n%s", err, evals.Load(), out)
		}
	})

	t.Run("managed allow still asks", func(t *testing.T) {
		app, evals, auditPath := newPushApp(t)
		app.editPol(func(p *policy.Policy) { p.ToolAllow = []string{"git_push"} })
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

	t.Run("foreign author", func(t *testing.T) {
		app, evals, auditPath := newPushApp(t)
		before := packs.Load()
		command := `set -e
git init
git checkout -b feature-evil
echo hello > readme.txt
git add readme.txt
GIT_AUTHOR_NAME=Evil GIT_AUTHOR_EMAIL=evil@evil.example GIT_COMMITTER_NAME=Evil GIT_COMMITTER_EMAIL=evil@evil.example git commit -m evil
git push https://github.com/acme/widgets.git feature-evil
echo PUSH_DONE
`
		out, err := runPush(t, app, auditPath, []string{"acme/widgets"}, command, false)
		if err == nil || strings.Contains(out, "PUSH_DONE") || strings.Contains(out, "git push sent") {
			t.Fatalf("push was sent: %v\n%s", err, out)
		}
		if !strings.Contains(out, "author") {
			t.Fatalf("reason author missing:\n%s", out)
		}
		if evals.Load() != 0 {
			t.Fatalf("Evaluate ran (%d)", evals.Load())
		}
		if packs.Load() != before {
			t.Fatal("receive-pack ran")
		}
		raw := readAudit(t, auditPath)
		if !strings.Contains(raw, "github_push_denied") || !strings.Contains(raw, `"reason":"author"`) {
			t.Fatalf("audit:\n%s", raw)
		}
	})

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
	t.Run("default branch case", func(t *testing.T) {
		cmd := `set -e
git init
git checkout -b Main
echo hello > readme.txt
git add readme.txt
git commit -m note-Main
git push https://github.com/acme/widgets.git Main
echo PUSH_DONE
`
		deny(t, cmd, "default branch")
	})
	t.Run("hostile config", func(t *testing.T) {
		var hits atomic.Int32
		attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Error(w, "no", http.StatusForbidden)
		}))
		t.Cleanup(attacker.Close)
		app, evals, auditPath := newPushApp(t)
		before := packs.Load()
		extra := fmt.Sprintf("printf '%%s\\n' '[url \"%s/\"]' '\tinsteadOf = https://github.com/' >> .git/config\ngit push https://github.com/acme/widgets.git feature-cfg\n", attacker.URL)
		out, err := runPush(t, app, auditPath, []string{"acme/widgets"}, feature("feature-cfg", "note-cfg", extra), false)
		if err == nil || !strings.Contains(out, "config") || strings.Contains(out, "PUSH_DONE") || strings.Contains(out, "git push sent") {
			t.Fatalf("config: %v\n%s", err, out)
		}
		if evals.Load() != 0 || packs.Load() != before || hits.Load() != 0 {
			t.Fatalf("config reached a push evals=%d packs=%d hits=%d", evals.Load(), packs.Load()-before, hits.Load())
		}
	})
	t.Run("empty allowlist", func(t *testing.T) {
		app, evals, auditPath := newPushApp(t)
		before := packs.Load()
		out, err := runPush(t, app, auditPath, nil, feature("feature", "note-empty", "git push https://github.com/acme/widgets.git feature"), false)
		if err == nil || !strings.Contains(out, "allowlist") || evals.Load() != 0 || packs.Load() != before {
			t.Fatalf("empty allowlist: %v evals=%d\n%s", err, evals.Load(), out)
		}
	})
	t.Run("subdirectory", func(t *testing.T) {
		app, evals, auditPath := newPushApp(t)
		packsBefore := packs.Load()
		cmd := `set -e
mkdir -p scratch
cd scratch
git init
git checkout -b feature-sub
echo hello > readme.txt
git add readme.txt
git commit -m note-sub
git push https://github.com/acme/widgets.git feature-sub
echo PUSH_DONE
`
		out, err := runPush(t, app, auditPath, []string{"acme/widgets"}, cmd, true)
		if err != nil || !strings.Contains(out, "git push sent") || !strings.Contains(out, "PUSH_DONE") || evals.Load() == 0 {
			t.Fatalf("subdir: %v evals=%d\n%s", err, evals.Load(), out)
		}
		if packs.Load() <= packsBefore {
			t.Fatal("subdir receive-pack was not called")
		}
		log := gitOK(t, "--git-dir", bare, "log", "--all", "--format=%s")
		if !strings.Contains(log, "note-sub") {
			t.Fatalf("bare repo log:\n%s", log)
		}
	})

	t.Run("symlinked subdirectory", func(t *testing.T) {
		app, _, auditPath := newPushApp(t)
		before := packs.Load()
		cmd := `set -e
mkdir -p real
ln -s real link
cd link
git init
git checkout -b feature-link
echo hello > readme.txt
git add readme.txt
git commit -m note-link
git push https://github.com/acme/widgets.git feature-link
echo PUSH_DONE
`
		out, err := runPush(t, app, auditPath, []string{"acme/widgets"}, cmd, false)
		if err == nil || !strings.Contains(out, "symlink") || strings.Contains(out, "PUSH_DONE") || packs.Load() != before {
			t.Fatalf("symlink: %v\n%s", err, out)
		}
	})

	t.Run("prompts off", func(t *testing.T) {
		app, evals, auditPath := newPushApp(t)
		app.editPol(func(p *policy.Policy) { p.UIPrompts = false })
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

	t.Run("replace", func(t *testing.T) {
		deny(t, `set -e
git init
git checkout -b feature-repl
echo hello > readme.txt
git add readme.txt
GIT_AUTHOR_NAME=Evil GIT_AUTHOR_EMAIL=evil@evil.example GIT_COMMITTER_NAME=Evil GIT_COMMITTER_EMAIL=evil@evil.example git commit -m evil
evil=$(git rev-parse HEAD)
git checkout --orphan goodtmp
echo good > readme.txt
git add readme.txt
git commit -m good
good=$(git rev-parse HEAD)
git replace "$evil" "$good"
git checkout feature-repl
git push https://github.com/acme/widgets.git feature-repl
echo PUSH_DONE
`, "replace")
	})
	t.Run("shallow", func(t *testing.T) {
		deny(t, `set -e
git init
git checkout -b feature-shallow
echo hello > readme.txt
git add readme.txt
git commit -m note-shallow
printf '%s\n' "$(git rev-parse HEAD)" > .git/shallow
git push https://github.com/acme/widgets.git feature-shallow
echo PUSH_DONE
`, "shallow")
	})
	t.Run("grafts", func(t *testing.T) {
		deny(t, `set -e
git init
git checkout -b feature-graft
echo hello > readme.txt
git add readme.txt
git commit -m note-graft
mkdir -p .git/info
printf '%s\n' "$(git rev-parse HEAD)" > .git/info/grafts
git push https://github.com/acme/widgets.git feature-graft
echo PUSH_DONE
`, "shallow")
	})
	t.Run("packed replace", func(t *testing.T) {
		deny(t, `set -e
git init
git checkout -b feature-packed
echo hello > readme.txt
git add readme.txt
git commit -m note-packed
oid=$(git rev-parse HEAD)
git pack-refs --all
printf '%s refs/replace/%s\n' "$oid" "$oid" >> .git/packed-refs
git push https://github.com/acme/widgets.git feature-packed
echo PUSH_DONE
`, "replace")
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
				if app.writeProxyUp() {
					errc <- errors.New("write proxy reachable before approval")
					return
				}
				sock := app.gitHubReadSock(botID)
				if sock == "" {
					errc <- errors.New("read socket missing before approval")
					return
				}
				client := &http.Client{Transport: &http.Transport{
					Dial: func(network, addr string) (net.Conn, error) {
						return net.Dial("unix", sock)
					},
				}}
				req, rerr := http.NewRequest(http.MethodPost, "http://proxy/github/acme/widgets.git/git-receive-pack", strings.NewReader("0000"))
				if rerr != nil {
					errc <- rerr
					return
				}
				res, rerr := client.Do(req)
				if rerr != nil {
					errc <- rerr
					return
				}
				body, _ := io.ReadAll(res.Body)
				res.Body.Close()
				if res.StatusCode != http.StatusForbidden || strings.Contains(string(body), pushSecret) {
					errc <- fmt.Errorf("jail receive-pack status %d body %q", res.StatusCode, body)
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

func TestGitPushAuthorRange(t *testing.T) {
	for _, bin := range []string{"git", "bwrap", "gcc"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Fatalf("%s is required", bin)
		}
	}
	bare := t.TempDir()
	gitOK(t, "init", "--bare", bare)
	gitOK(t, "-C", bare, "symbolic-ref", "HEAD", "refs/heads/main")
	seed := t.TempDir()
	gitOK(t, "-C", seed, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(seed, "readme.txt"), []byte("human\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitEnv(t, seed, []string{
		"GIT_AUTHOR_NAME=Human", "GIT_AUTHOR_EMAIL=human@example.com",
		"GIT_COMMITTER_NAME=Human", "GIT_COMMITTER_EMAIL=human@example.com",
	}, "add", "readme.txt")
	gitEnv(t, seed, []string{
		"GIT_AUTHOR_NAME=Human", "GIT_AUTHOR_EMAIL=human@example.com",
		"GIT_COMMITTER_NAME=Human", "GIT_COMMITTER_EMAIL=human@example.com",
	}, "commit", "-m", "human-main")
	gitOK(t, "-C", seed, "remote", "add", "origin", bare)
	gitOK(t, "-C", seed, "push", "origin", "HEAD:refs/heads/main")

	var packs atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	app.githubGitBase = upstream.URL
	app.githubAPIBase = upstream.URL
	app.editPol(func(p *policy.Policy) { p.GitHub.Repos = []string{"acme/widgets"} })
	app.editPol(func(p *policy.Policy) { p.GitHub.TokenFile = filepath.Join(t.TempDir(), "github.token") })
	if err := os.WriteFile(app.pol().GitHub.TokenFile, []byte(pushSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	app.editPol(func(p *policy.Policy) { p.UIPrompts = true })
	app.editPol(func(p *policy.Policy) { p.PromptTimeout = 20 * time.Second })
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lg.Close() })
	app.audit = lg
	var evals atomic.Int32
	app.perm.AddHook(func(req permission.Request) permission.HookResult {
		if req.Tool == "git_push" {
			evals.Add(1)
		}
		return permission.HookResult{}
	})
	srv := serve(t, app)
	bot := createGrantedBot(t, srv.URL, "Ada", []string{"git", "github"})
	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"github_allow": []string{"acme/widgets"}}, "")
	if res.StatusCode != 200 {
		t.Fatalf("allow %d %s", res.StatusCode, b)
	}
	root := app.botWorkspace(bot.ID)
	if err := os.MkdirAll(filepath.Join(root, "runs"), 0o755); err != nil {
		t.Fatal(err)
	}
	ada := []string{
		"GIT_AUTHOR_NAME=Ada", "GIT_AUTHOR_EMAIL=Ada@users.noreply",
		"GIT_COMMITTER_NAME=Ada", "GIT_COMMITTER_EMAIL=Ada@users.noreply",
	}
	human := []string{
		"GIT_AUTHOR_NAME=Human", "GIT_AUTHOR_EMAIL=human@example.com",
		"GIT_COMMITTER_NAME=Human", "GIT_COMMITTER_EMAIL=human@example.com",
	}
	run := func(t *testing.T, command string, approve bool) (string, error) {
		t.Helper()
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
		return out, err
	}

	t.Run("new branch over human history", func(t *testing.T) {
		sub := filepath.Join(root, "runs", "a")
		gitOK(t, "clone", bare, sub)
		beforeE, beforeP := evals.Load(), packs.Load()
		out, err := run(t, `set -e
cd runs/a
git checkout -b feature-a
echo bot >> readme.txt
git add readme.txt
git commit -m bot-a
git push https://github.com/acme/widgets.git feature-a
echo PUSH_DONE
`, true)
		if err != nil || !strings.Contains(out, "git push sent") || !strings.Contains(out, "PUSH_DONE") {
			t.Fatalf("send: %v\n%s", err, out)
		}
		if evals.Load() <= beforeE || packs.Load() <= beforeP {
			t.Fatalf("evals %d packs %d", evals.Load(), packs.Load())
		}
		if strings.Contains(out, "proxy unavailable") {
			t.Fatalf("proxy unavailable:\n%s", out)
		}
	})
	t.Run("foreign commit on new branch", func(t *testing.T) {
		sub := filepath.Join(root, "runs", "b")
		gitOK(t, "clone", bare, sub)
		beforeE, beforeP := evals.Load(), packs.Load()
		out, err := run(t, `set -e
cd runs/b
git checkout -b feature-b
echo bot >> readme.txt
git add readme.txt
GIT_AUTHOR_NAME=Evil GIT_AUTHOR_EMAIL=evil@evil.example GIT_COMMITTER_NAME=Evil GIT_COMMITTER_EMAIL=evil@evil.example git commit -m evil-b
git push https://github.com/acme/widgets.git feature-b
echo PUSH_DONE
`, false)
		if err == nil || strings.Contains(out, "PUSH_DONE") || strings.Contains(out, "git push sent") {
			t.Fatalf("sent: %v\n%s", err, out)
		}
		if strings.Contains(out, "proxy unavailable") || !strings.Contains(out, "author") {
			t.Fatalf("reason:\n%s", out)
		}
		if evals.Load() != beforeE || packs.Load() != beforeP {
			t.Fatalf("evals %d->%d packs %d->%d", beforeE, evals.Load(), beforeP, packs.Load())
		}
	})
	t.Run("merge newer upstream", func(t *testing.T) {
		sub := filepath.Join(root, "runs", "c")
		gitOK(t, "clone", bare, sub)
		gitOK(t, "-C", sub, "checkout", "-b", "feature-c")
		if err := os.WriteFile(filepath.Join(sub, "bot.txt"), []byte("bot\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		gitEnv(t, sub, ada, "add", "bot.txt")
		gitEnv(t, sub, ada, "commit", "-m", "bot-c")
		gitOK(t, "-C", sub, "push", "origin", "HEAD:refs/heads/feature-c")
		gitOK(t, "-C", sub, "checkout", "main")
		if err := os.WriteFile(filepath.Join(sub, "readme.txt"), []byte("human-2\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		gitEnv(t, sub, human, "add", "readme.txt")
		gitEnv(t, sub, human, "commit", "-m", "human-2")
		gitOK(t, "-C", sub, "push", "origin", "HEAD:refs/heads/main")
		gitOK(t, "-C", sub, "checkout", "feature-c")
		gitEnv(t, sub, ada, "merge", "--no-ff", "main", "-m", "merge-main")
		beforeE, beforeP := evals.Load(), packs.Load()
		out, err := run(t, `set -e
cd runs/c
git push https://github.com/acme/widgets.git feature-c
echo PUSH_DONE
`, true)
		if err != nil || !strings.Contains(out, "git push sent") || !strings.Contains(out, "PUSH_DONE") {
			t.Fatalf("merge push: %v\n%s", err, out)
		}
		if strings.Contains(out, "proxy unavailable") || evals.Load() <= beforeE || packs.Load() <= beforeP {
			t.Fatalf("evals %d packs %d\n%s", evals.Load(), packs.Load(), out)
		}
	})
	t.Run("local remote ref is not upstream", func(t *testing.T) {
		beforeE, beforeP := evals.Load(), packs.Load()
		out, err := run(t, `set -e
mkdir -p runs/d
cd runs/d
git init
git checkout -b feature-d
echo bad > readme.txt
git add readme.txt
GIT_AUTHOR_NAME=Evil GIT_AUTHOR_EMAIL=evil@evil.example GIT_COMMITTER_NAME=Evil GIT_COMMITTER_EMAIL=evil@evil.example git commit -m evil-d
git update-ref refs/remotes/origin/main HEAD
git push https://github.com/acme/widgets.git feature-d
echo PUSH_DONE
`, false)
		if err == nil || strings.Contains(out, "PUSH_DONE") || strings.Contains(out, "git push sent") {
			t.Fatalf("sent: %v\n%s", err, out)
		}
		if strings.Contains(out, "proxy unavailable") || !strings.Contains(out, "author") {
			t.Fatalf("reason:\n%s", out)
		}
		if evals.Load() != beforeE || packs.Load() != beforeP {
			t.Fatalf("evals %d->%d packs %d->%d", beforeE, evals.Load(), beforeP, packs.Load())
		}
	})
}

func gitEnv(t *testing.T, dir string, env []string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
	)
	cmd.Env = append(cmd.Env, env...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v %s", strings.Join(args, " "), err, b)
	}
}
