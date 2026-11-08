package permbroker

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

func evalWrite(e *Engine, ceiling Level, cwd, ws, tool, path string) Decision {
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: ceiling})
	raw, _ := json.Marshal(map[string]string{"file_path": path})
	return e.Evaluate(context.Background(), Request{
		BotID: ceilingBot, SessionID: "sess", RunID: "run", TaskID: "task",
		Cwd: cwd, Workspace: ws, ToolName: tool, ToolInput: raw,
	})
}

func TestCeilingDanglingLinkAsks(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()
	missing := filepath.Join(outside, "missing-target")
	link := filepath.Join(ws, "l")
	if err := os.Symlink(missing, link); err != nil {
		t.Fatal(err)
	}
	dirlink := filepath.Join(ws, "dl2")
	if err := os.Symlink(filepath.Join(outside, "no-such-dir"), dirlink); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(ws, "ok.txt")
	if err := os.WriteFile(inside, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	insideLink := filepath.Join(ws, "inside-l")
	if err := os.Symlink(filepath.Join(ws, "new-inside.txt"), insideLink); err != nil {
		t.Fatal(err)
	}
	for _, ceiling := range []Level{LevelMedium, LevelHigh, LevelCritical} {
		e := testEngine(t)
		wantAsk(t, evalWrite(e, ceiling, ws, ws, "Write", link))
		wantAsk(t, evalWrite(e, ceiling, ws, ws, "Edit", link))
		wantAsk(t, evalWrite(e, ceiling, ws, ws, "Write", filepath.Join(dirlink, "f")))
		wantCeilingAllow(t, evalWrite(e, ceiling, ws, ws, "Write", inside))
		wantAsk(t, evalWrite(e, ceiling, ws, ws, "Write", insideLink))
	}
}

func TestCeilingDanglingLinkLoopAndCap(t *testing.T) {
	ws := t.TempDir()
	a := filepath.Join(ws, "a")
	b := filepath.Join(ws, "b")
	if err := os.Symlink(b, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	e := testEngine(t)
	wantAsk(t, evalWrite(e, LevelMedium, ws, ws, "Write", a))
	wantAsk(t, evalWrite(e, LevelCritical, ws, ws, "Write", b))

	chain := filepath.Join(ws, "s0")
	prev := filepath.Join(ws, "end.txt")
	if err := os.WriteFile(prev, []byte("e"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 41; i >= 0; i-- {
		name := filepath.Join(ws, "s"+strconv.Itoa(i))
		if err := os.Symlink(prev, name); err != nil {
			t.Fatal(err)
		}
		prev = name
	}
	wantAsk(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", chain))
}

func TestCeilingDanglingPolicyPathAsks(t *testing.T) {
	ws := t.TempDir()
	pol := filepath.Join(ws, "real-policy.toml")
	link := filepath.Join(ws, "p.toml")
	if err := os.Symlink(pol, link); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(ws, "a.txt")
	if err := os.WriteFile(kept, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := testEngine(t)
	e.SetPolicyPaths(pol)
	for _, ceiling := range []Level{LevelMedium, LevelHigh, LevelCritical} {
		wantAsk(t, evalWrite(e, ceiling, ws, ws, "Write", link))
	}
	wantCeilingAllow(t, evalWrite(e, LevelMedium, ws, ws, "Write", kept))
}

func TestCeilingGitApplyDanglingChain(t *testing.T) {
	requireGit(t)
	ws := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside-target")
	runGit(t, ws, "init")
	link := filepath.Join(ws, "l")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	runGit(t, ws, "add", "l")
	patch := runGitOut(t, ws, "diff", "--cached")
	runGit(t, ws, "rm", "--cached", "l")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	patchPath := filepath.Join(ws, "x.patch")
	if err := os.WriteFile(patchPath, patch, 0o644); err != nil {
		t.Fatal(err)
	}
	e := testEngine(t)
	wantCeilingAllow(t, evalWrite(e, LevelMedium, ws, ws, "Write", patchPath))
	wantAsk(t, evalShell(e, LevelMedium, ws, ws, "git apply x.patch"))
	runGit(t, ws, "apply", "x.patch")
	for _, ceiling := range []Level{LevelMedium, LevelHigh, LevelCritical} {
		wantAsk(t, evalWrite(testEngine(t), ceiling, ws, ws, "Write", link))
	}
}

func TestCeilingGitDirWriteAsks(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, ".git", "objects", "info"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := testEngine(t)
	asks := []string{
		filepath.Join(ws, ".git", "HEAD"),
		filepath.Join(ws, ".git", "packed-refs"),
		filepath.Join(ws, ".git", "objects", "info", "alternates"),
		filepath.Join(ws, ".git", "modules", "s", "config"),
		filepath.Join(ws, "s", ".git"),
	}
	for _, p := range asks {
		t.Run(p, func(t *testing.T) {
			wantAsk(t, evalWrite(e, LevelMedium, ws, ws, "Write", p))
			wantAsk(t, evalWrite(e, LevelCritical, ws, ws, "Write", p))
		})
	}
	wantAsk(t, evalShell(e, LevelMedium, ws, ws, "git add .git/HEAD"))
	wantAsk(t, evalShell(e, LevelCritical, ws, ws, "git add .git/HEAD"))
	wantNeverDeny(t, evalShell(testEngine(t), LevelCritical, ws, ws, "git add .git/hooks/pre-commit"))
}

func TestCeilingGitdirLookalikeWriteAsks(t *testing.T) {
	ws := t.TempDir()
	evil := filepath.Join(ws, "evil")
	if err := os.MkdirAll(evil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evil, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := testEngine(t)
	wantAsk(t, evalWrite(e, LevelMedium, ws, ws, "Write", filepath.Join(evil, "config")))
	wantAsk(t, evalWrite(e, LevelCritical, ws, ws, "Write", filepath.Join(evil, "HEAD")))
	gitfile := filepath.Join(ws, "z", ".git")
	wantAsk(t, evalWrite(e, LevelMedium, ws, ws, "Write", gitfile))
}

func TestCeilingClientConfigWriteAsks(t *testing.T) {
	ws := t.TempDir()
	e := testEngine(t)
	paths := []struct {
		name string
		rel  string
	}{
		{name: "grok", rel: filepath.Join(".grok", "settings.json")},
		{name: "vscode", rel: filepath.Join(".vscode", "tasks.json")},
		{name: "vscode-settings", rel: filepath.Join(".vscode", "settings.json")},
		{name: "vscode-launch", rel: filepath.Join(".vscode", "launch.json")},
		{name: "envrc", rel: ".envrc"},
		{name: "claude", rel: filepath.Join(".claude", "settings.json")},
		{name: "idea", rel: filepath.Join(".idea", "workspace.xml")},
		{name: "idea-run", rel: filepath.Join(".idea", "runConfigurations", "a.xml")},
		{name: "devcontainer", rel: filepath.Join(".devcontainer", "devcontainer.json")},
	}
	for _, tc := range paths {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(ws, tc.rel)
			wantAsk(t, evalWrite(e, LevelMedium, ws, ws, "Write", p))
			wantAsk(t, evalWrite(e, LevelCritical, ws, ws, "Write", p))
			wantAsk(t, evalShell(e, LevelMedium, ws, ws, "git add "+tc.rel))
			wantAsk(t, evalShell(e, LevelCritical, ws, ws, "git add "+tc.rel))
		})
	}
	kept := filepath.Join(ws, "a.txt")
	if err := os.WriteFile(kept, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantCeilingAllow(t, evalWrite(e, LevelMedium, ws, ws, "Write", kept))
}

func TestCeilingGitRiskNested(t *testing.T) {
	ctx := context.Background()
	evalStatus := func(e *Engine, ws, cmd string) Decision {
		e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelLow})
		req := bashReq(ceilingBot, "sess", "task", ws, cmd)
		req.Workspace = ws
		return e.Evaluate(ctx, req)
	}
	t.Run("submodule-modules", func(t *testing.T) {
		e := testEngine(t)
		ws, home, userHome := cleanRepo(t)
		mustWrite(t, filepath.Join(ws, ".git", "modules", "s", "config"), "[core]\n\tfsmonitor = x\n")
		e.SetBotContext(ceilingBot, ws, nil)
		e.SetBotRuntime(ceilingBot, home, userHome, nil)
		e.SnapshotBot(ceilingBot)
		wantAsk(t, evalStatus(e, ws, "git status"))
	})
	t.Run("gitdir-file", func(t *testing.T) {
		e := testEngine(t)
		ws, home, userHome := cleanRepo(t)
		evil := filepath.Join(ws, "evil")
		mustWrite(t, filepath.Join(evil, "config"), "[core]\n\trepositoryformatversion = 0\n\tpager = less\n")
		z := filepath.Join(ws, "z")
		if err := os.Mkdir(z, 0o755); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(z, ".git"), "gitdir: "+evil+"\n")
		e.SetBotContext(ceilingBot, ws, nil)
		e.SetBotRuntime(ceilingBot, home, userHome, nil)
		e.SnapshotBot(ceilingBot)
		wantAsk(t, evalStatus(e, ws, "git -C z status"))
	})
	t.Run("dash-C", func(t *testing.T) {
		e := testEngine(t)
		ws, home, userHome := cleanRepo(t)
		n := filepath.Join(ws, "n")
		if err := os.MkdirAll(filepath.Join(n, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(n, ".git", "config"), "[core]\n\trepositoryformatversion = 0\n\thooksPath = ./h\n")
		e.SetBotContext(ceilingBot, ws, nil)
		e.SetBotRuntime(ceilingBot, home, userHome, nil)
		e.SnapshotBot(ceilingBot)
		wantAsk(t, evalStatus(e, ws, "git -C n status"))
	})
}

func TestCeilingRealSubmoduleGitRisk(t *testing.T) {
	requireGit(t)
	sub := t.TempDir()
	runGit(t, sub, "init")
	if err := os.WriteFile(filepath.Join(sub, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, sub, "add", "f")
	runGit(t, sub, "commit", "-m", "i")
	ws := t.TempDir()
	runGit(t, ws, "init")
	runGit(t, ws, "commit", "--allow-empty", "-m", "root")
	runGit(t, ws, "-c", "protocol.file.allow=always", "submodule", "add", "file://"+sub, "s")
	mod := filepath.Join(ws, ".git", "modules", "s", "config")
	b, err := os.ReadFile(mod)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mod, append(b, []byte("\n[core]\n\tfsmonitor = x\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	e := testEngine(t)
	home := t.TempDir()
	e.SetBotContext(ceilingBot, ws, nil)
	e.SetBotRuntime(ceilingBot, home, home, nil)
	e.SnapshotBot(ceilingBot)
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelLow})
	req := bashReq(ceilingBot, "sess", "task", ws, "git status")
	req.Workspace = ws
	wantAsk(t, e.Evaluate(context.Background(), req))
}

func TestCeilingN14N3(t *testing.T) {
	ws := t.TempDir()
	wantAsk(t, evalShell(testEngine(t), LevelCritical, ws, ws, "gh auth login --with-token"))
	wantAsk(t, evalShell(testEngine(t), LevelMedium, ws, ws, "git -C . submodule foreach id"))
	wantAsk(t, evalShell(testEngine(t), LevelCritical, ws, ws, "git -C . submodule foreach id"))
	e := testEngine(t)
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelMedium})
	req := bashReq(ceilingBot, "sess", "task", ws, "git -c x=y submodule foreach id")
	req.Workspace = ws
	in := inspected{
		Eligible: true, Literal: true, Level: LevelMedium,
		Argv: []string{"git", "-c", "x=y", "submodule", "foreach", "id"},
		Raw:  "git -c x=y submodule foreach id",
	}
	if _, ok := e.ceilingMatch(req, in); ok {
		t.Fatal("matched foreach after -c")
	}
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	_ = runGitOut(t, dir, args...)
}

func runGitOut(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t",
		"GIT_AUTHOR_EMAIL=t@t.example",
		"GIT_COMMITTER_NAME=t",
		"GIT_COMMITTER_EMAIL=t@t.example",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return out
}
