package daemon

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestGitWrapperUsesEffectiveRepos(t *testing.T) {
	for _, bin := range []string{"bwrap", "git", "gcc"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " is required")
		}
	}
	app := newApp(t, "", fakeModel{})
	app.editPol(func(p *policy.Policy) {
		p.GitHub.Repos = []string{"acme/widgets", "acme/ceiling-only-2027"}
	})
	srv := serve(t, app)
	bot := createGrantedBot(t, srv.URL, "Ada", []string{"git", "github"})
	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{
		"github_allow": []string{"acme/widgets", "zzbot/only-2027"},
	}, "")
	if res.StatusCode != 200 {
		t.Fatalf("patch %d %s", res.StatusCode, b)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	out, err := app.dispatchTool(ctx, bot, "run_shell", map[string]any{
		"command": "echo WRAP_BEGIN; grep -E 'acme|2027' /usr/bin/git; echo WRAP_END; env",
	})
	if err != nil {
		t.Fatalf("err %v\n%s", err, out)
	}
	if !strings.Contains(out, "acme/widgets") {
		t.Fatalf("shared repo missing\n%s", out)
	}
	if strings.Contains(out, "ceiling-only-2027") || strings.Contains(out, "zzbot/only-2027") || strings.Contains(out, "only-2027") {
		t.Fatalf("repo outside the effective list\n%s", out)
	}
}
