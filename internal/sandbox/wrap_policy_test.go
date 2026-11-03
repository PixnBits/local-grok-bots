package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestGitWrapNoPolicyOnlyRepos(t *testing.T) {
	const secret = "acme/secret-merger-2027"
	ceiling := []string{"acme/widgets", secret}
	bot := []string{"acme/widgets", "onlybot/repo"}
	eff := (policy.Policy{GitHub: policy.GitHub{Repos: ceiling}}).EffectiveGitHubRepos(bot)
	if len(eff) != 1 || eff[0] != "acme/widgets" {
		t.Fatalf("effective %v", eff)
	}
	script := gitWrap(gitWrapOpts{
		Grant: true, Hub: true, Bridge: false,
		Repos: eff, Name: "Ada", Email: "bot@localhost",
	})
	for _, leaked := range []string{secret, "secret-merger-2027", "onlybot/repo", gitHubListCeiling, gitHubListBot, "@@POLICY@@", "@@BOT@@"} {
		if strings.Contains(script, leaked) {
			t.Fatalf("rendered script contains %q", leaked)
		}
	}
	if !strings.Contains(script, "acme/widgets") {
		t.Fatal("effective repo missing from wrapper")
	}
	text := runGitWrap(t, script, "clone", "https://github.com/"+secret+".git", "dest")
	if strings.Contains(text, secret) || strings.Contains(text, "secret-merger") || !strings.Contains(text, RepoNotAvailable) {
		t.Fatalf("denial output: %s", text)
	}

	ws := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	prep, err := prepare(ctx, Request{
		Workspace:      ws,
		Command:        "true",
		Grants:         []string{"git"},
		GitHubRepos:    eff,
		GitAuthor:      "Ada",
		GitAuthorEmail: "bot@localhost",
	}, ws)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer prep.close()
	for _, env := range prep.env {
		if strings.Contains(env, secret) || strings.Contains(env, "secret-merger") {
			t.Fatalf("env %s", env)
		}
	}
	err = filepath.Walk(prep.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if strings.Contains(path, secret) || strings.Contains(info.Name(), "secret-merger") {
			t.Fatalf("path %s", path)
		}
		if !info.Mode().IsRegular() || info.Size() > 8<<20 {
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		if bytes.Contains(body, []byte(secret)) || bytes.Contains(body, []byte("secret-merger-2027")) {
			t.Fatalf("found policy-only repo in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if runtime.GOOS != "linux" {
		return
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap unavailable")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	runCtx, runCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer runCancel()
	res, runErr := Run(runCtx, Request{
		Workspace:      ws,
		Command:        "grep -F secret-merger-2027 /usr/bin/git && echo LEAKED || echo CLEAN; git clone https://github.com/" + secret + ".git dest; echo DONE",
		Grants:         []string{"git", "github"},
		GitHubRepos:    eff,
		GitAuthor:      "Ada",
		GitAuthorEmail: "bot@localhost",
	})
	out := res.Stdout + res.Stderr
	if strings.Contains(out, "LEAKED") || strings.Contains(out, secret) || !strings.Contains(out, "CLEAN") || !strings.Contains(out, RepoNotAvailable) {
		t.Fatalf("jail err=%v\n%s", runErr, out)
	}
}
