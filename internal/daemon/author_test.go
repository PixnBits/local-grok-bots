package daemon

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestGitAuthorFromPolicy(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()

	t.Run("unsafe name refuses without embedding", func(t *testing.T) {
		app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
			return model.ChatResponse{Content: "no"}, nil
		}})
		srv := serve(t, app)
		const bad = "Ada;echo PWNED > pwned.txt"
		bot := createGrantedBot(t, srv.URL, bad, []string{"git"})
		out, err := app.dispatchTool(ctx, bot, "run_shell", map[string]any{"command": "git init"})
		if err == nil || !strings.Contains(out, "invalid author") {
			t.Fatalf("unsafe author ran: %v\n%s", err, out)
		}
		if strings.Contains(out, "PWNED") || strings.Contains(out, bad) || strings.Contains(out, "pwned") {
			t.Fatalf("author leaked into output:\n%s", out)
		}
		if _, statErr := os.Stat(filepath.Join(app.ws, "pwned.txt")); !os.IsNotExist(statErr) {
			t.Fatalf("injection created pwned.txt: %v", statErr)
		}
		raw, jerr := json.Marshal(logKind(t, srv.URL, "grant_denied"))
		if jerr != nil {
			t.Fatal(jerr)
		}
		if strings.Contains(string(raw), "PWNED") || strings.Contains(string(raw), bad) {
			t.Fatalf("author leaked into the log: %s", raw)
		}
		if !hasDetail(logDetails(t, srv.URL, "grant_denied"), "git", "") {
			t.Fatalf("denial not logged: %s", raw)
		}
	})

	t.Run("bot name is the author", func(t *testing.T) {
		app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
			return model.ChatResponse{Content: "no"}, nil
		}})
		srv := serve(t, app)
		bot := createGrantedBot(t, srv.URL, "Ada", []string{"git"})
		out, err := app.dispatchTool(ctx, bot, "run_shell", map[string]any{"command": gitAuthorScript})
		if err != nil || !strings.Contains(out, "Ada:Ada@users.noreply") {
			t.Fatalf("author: %v\n%s", err, out)
		}
	})

	t.Run("policy name and template override the bot", func(t *testing.T) {
		app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
			return model.ChatResponse{Content: "no"}, nil
		}})
		app.policy.GitHub.AuthorName = "ci-bot"
		app.policy.GitHub.AuthorEmail = "{name}@users.noreply.example.com"
		srv := serve(t, app)
		bot := createGrantedBot(t, srv.URL, "Ada", []string{"git"})
		out, err := app.dispatchTool(ctx, bot, "run_shell", map[string]any{"command": gitAuthorScript})
		if err != nil || !strings.Contains(out, "ci-bot:ci-bot@users.noreply.example.com") {
			t.Fatalf("policy author: %v\n%s", err, out)
		}
		if strings.Contains(out, "Ada:") {
			t.Fatalf("bot name used as author:\n%s", out)
		}
	})
}

func createGrantedBot(t *testing.T, base, name string, grants []string) store.Bot {
	t.Helper()
	_, b := do(t, "POST", base+"/api/bots", map[string]any{"name": name, "description": "stay"}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	if bot.Name != name {
		t.Fatalf("name stored as %q", bot.Name)
	}
	res, b := do(t, "PATCH", base+"/api/bots/"+bot.ID, map[string]any{"grants": grants}, "")
	if res.StatusCode != 200 {
		t.Fatalf("grant %d %s", res.StatusCode, b)
	}
	return bot
}

const gitAuthorScript = `set -e
git init
echo hello > readme.txt
git add readme.txt
git commit -m note
git log -1 --format=%an:%ae
`
