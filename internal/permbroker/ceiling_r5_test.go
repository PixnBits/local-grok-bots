package permbroker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func symlinkChain(t *testing.T, dir string, n int) string {
	t.Helper()
	end := filepath.Join(dir, "end.txt")
	if err := os.WriteFile(end, []byte("e"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := end
	first := end
	for i := 1; i <= n; i++ {
		name := filepath.Join(dir, "h"+strconv.Itoa(i))
		if err := os.Symlink(prev, name); err != nil {
			t.Fatal(err)
		}
		prev = name
		first = name
	}
	return first
}

func globCall(e *Engine, ceiling Level, ws, pattern string) Decision {
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: ceiling})
	raw, _ := json.Marshal(map[string]any{"path": ws, "pattern": pattern})
	return e.Evaluate(context.Background(), Request{
		BotID: ceilingBot, SessionID: "sess", RunID: "run", TaskID: "task",
		Cwd: ws, Workspace: ws, ToolName: "Glob", ToolInput: raw,
	})
}

func TestCeilingResolverErrors(t *testing.T) {
	ws := t.TempDir()
	a := filepath.Join(ws, "a")
	b := filepath.Join(ws, "b")
	mustSymlink(t, b, a)
	mustSymlink(t, a, b)
	if _, err := resolvePath(a); !errors.Is(err, errSymlinkLoop) {
		t.Fatalf("loop err %v", err)
	}

	outside := t.TempDir()
	dangling := filepath.Join(ws, "gone")
	mustSymlink(t, filepath.Join(outside, "missing"), dangling)
	if _, err := resolvePath(dangling); !errors.Is(err, errSymlinkDangling) {
		t.Fatalf("dangling err %v", err)
	}

	fresh := filepath.Join(ws, "brand-new.txt")
	got, err := resolvePath(fresh)
	if err != nil || got != fresh {
		t.Fatalf("new file %q %v", got, err)
	}

	inside := filepath.Join(ws, "ok.txt")
	if err := os.WriteFile(inside, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(ws, "via")
	mustSymlink(t, inside, link)
	got, err = resolvePath(link)
	if err != nil || got != inside {
		t.Fatalf("inside symlink %q %v", got, err)
	}

	okChain := symlinkChain(t, t.TempDir(), 40)
	if _, err := resolvePath(okChain); err != nil {
		t.Fatalf("40 hops %v", err)
	}
	over := symlinkChain(t, t.TempDir(), 41)
	if _, err := resolvePath(over); !errors.Is(err, errSymlinkHops) {
		t.Fatalf("41 hops %v", err)
	}
}

func TestCeilingHopBoundary(t *testing.T) {
	okDir := t.TempDir()
	ok := symlinkChain(t, okDir, 40)
	wantCeilingAllow(t, evalWrite(testEngine(t), LevelMedium, okDir, okDir, "Write", ok))

	overDir := t.TempDir()
	over := symlinkChain(t, overDir, 41)
	for _, ceiling := range []Level{LevelMedium, LevelCritical} {
		wantAsk(t, evalWrite(testEngine(t), ceiling, overDir, overDir, "Write", over))
	}
}

func TestCeilingMust6Layouts(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	if err := os.Mkdir(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(root, "fakehome")
	mustWrite(t, filepath.Join(fake, ".bash_profile"), "x\n")
	mustWrite(t, filepath.Join(fake, ".ssh", "authorized_keys"), "k\n")
	mustWrite(t, filepath.Join(fake, "note.txt"), "n\n")
	if err := os.MkdirAll(filepath.Join(ws, "x1", "x2", "x3"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, "../../..", filepath.Join(ws, "x1", "x2", "x3", "D"))
	mustSymlink(t, "../fakehome/.bash_profile", filepath.Join(ws, "l_up"))
	mustSymlink(t, "../../fakehome/.ssh/authorized_keys", filepath.Join(ws, "x1", "l_up2"))
	mustSymlink(t, "../fakehome/note.txt", filepath.Join(ws, "l_note"))

	rows := []string{
		filepath.Join(ws, "x1", "x2", "x3", "D", "l_up"),
		filepath.Join(ws, "x1", "x2", "x3", "D", "x1", "l_up2"),
		filepath.Join(ws, "x1", "x2", "x3", "D", "x1", "x2", "x3", "D", "l_up"),
		filepath.Join(ws, "x1", "x2", "x3", "D", "l_note"),
	}
	patch := filepath.Join(ws, "x.patch")
	if err := os.WriteFile(patch, []byte("diff\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, ceiling := range []Level{LevelMedium, LevelCritical} {
		e := testEngine(t)
		wantCeilingAllow(t, evalWrite(e, ceiling, ws, ws, "Write", patch))
		wantCeilingAllow(t, evalShell(e, ceiling, ws, ws, "git apply x.patch"))
		for _, path := range rows {
			wantAsk(t, evalWrite(e, ceiling, ws, ws, "Write", path))
			wantAsk(t, evalWrite(e, ceiling, ws, ws, "Edit", path))
		}
	}

	outside := t.TempDir()
	kept := filepath.Join(ws, "ok.txt")
	if err := os.WriteFile(kept, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(outside, "alias")
	mustSymlink(t, kept, alias)
	wantAsk(t, evalWrite(testEngine(t), LevelCritical, ws, ws, "Write", alias))
}

func TestCeilingMust7AndShould6Symlinks(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, ".git", "info"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, ".git", "modules", "s"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(ws, ".git", "config"), "[core]\n")
	mustWrite(t, filepath.Join(ws, ".git", "HEAD"), "ref: refs/heads/main\n")
	mustWrite(t, filepath.Join(ws, ".git", "hooks", "pre-commit"), "#!/bin/sh\n")
	mustWrite(t, filepath.Join(ws, ".git", "info", "attributes"), "\n")
	mustWrite(t, filepath.Join(ws, ".git", "modules", "s", "config"), "[core]\n")
	mustWrite(t, filepath.Join(ws, "s", ".git"), "gitdir: ../.git/modules/s\n")
	mustWrite(t, filepath.Join(ws, "bare", "config"), "[core]\n")
	mustWrite(t, filepath.Join(ws, ".claude", "settings.json"), "{}\n")
	mustWrite(t, filepath.Join(ws, ".vscode", "tasks.json"), "{}\n")
	mustWrite(t, filepath.Join(ws, ".vscode", "settings.json"), "{}\n")
	mustWrite(t, filepath.Join(ws, ".envrc"), "\n")
	if err := os.MkdirAll(filepath.Join(ws, ".grok"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(ws, ".mcp.json"), "{}\n")

	links := []struct {
		name   string
		link   string
		target string
		via    string
	}{
		{name: "g-cfg", link: "g_cfg", target: ".git/config"},
		{name: "g-hook", link: "g_hook", target: ".git/hooks/pre-commit"},
		{name: "g-attr", link: "g_attr", target: ".git/info/attributes"},
		{name: "c-tasks", link: "c_tasks", target: ".vscode/tasks.json"},
		{name: "c-claude", link: "c_claude", target: ".claude/settings.json"},
		{name: "c-envrc", link: "c_envrc", target: ".envrc"},
		{name: "inn", link: "inn", target: ".git/config"},
		{name: "innhead", link: "innhead", target: ".git/HEAD"},
		{name: "innhook", link: "innhook", target: ".git/hooks/pre-commit"},
		{name: "innmod", link: "innmod", target: ".git/modules/s/config"},
		{name: "innsubgf", link: "innsubgf", target: "s/.git"},
		{name: "innbare", link: "innbare", target: "bare/config"},
		{name: "innc", link: "innc", target: ".claude/settings.json"},
		{name: "innm", link: "innm", target: ".mcp.json"},
		{name: "gk", link: "gk", target: ".grok"},
	}
	for _, tc := range links {
		mustSymlink(t, tc.target, filepath.Join(ws, tc.link))
	}
	mustSymlink(t, ".vscode", filepath.Join(ws, "c_vs"))

	paths := []string{
		filepath.Join(ws, "g_cfg"),
		filepath.Join(ws, "g_hook"),
		filepath.Join(ws, "g_attr"),
		filepath.Join(ws, "c_tasks"),
		filepath.Join(ws, "c_vs", "tasks.json"),
		filepath.Join(ws, "c_vs", "settings.json"),
		filepath.Join(ws, "c_claude"),
		filepath.Join(ws, "c_envrc"),
		filepath.Join(ws, "inn"),
		filepath.Join(ws, "innhead"),
		filepath.Join(ws, "innhook"),
		filepath.Join(ws, "innmod"),
		filepath.Join(ws, "innsubgf"),
		filepath.Join(ws, "innbare"),
		filepath.Join(ws, "innc"),
		filepath.Join(ws, "gk", "settings.json"),
		filepath.Join(ws, "innm"),
	}
	for _, ceiling := range []Level{LevelMedium, LevelCritical} {
		e := testEngine(t)
		for _, path := range paths {
			t.Run(string(ceiling)+"/"+filepath.Base(path), func(t *testing.T) {
				want := wantAsk
				base := filepath.Base(path)
				if base == "g_hook" || base == "innhook" {
					want = wantNeverDeny
				}
				want(t, evalWrite(e, ceiling, ws, ws, "Write", path))
				want(t, evalWrite(e, ceiling, ws, ws, "Edit", path))
			})
		}
		wantAsk(t, evalShell(e, ceiling, ws, ws, "git add inn"))
		wantAsk(t, evalShell(e, ceiling, ws, ws, "git add g_cfg"))
	}
	kept := filepath.Join(ws, "a.txt")
	if err := os.WriteFile(kept, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	via := filepath.Join(ws, "via-ok")
	mustSymlink(t, kept, via)
	wantCeilingAllow(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", via))
	wantCeilingAllow(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", filepath.Join(ws, "new.txt")))
}

func TestCeilingClientCase(t *testing.T) {
	ws := t.TempDir()
	rels := []string{
		filepath.Join(".VSCODE", "tasks.json"),
		filepath.Join(".Claude", "settings.json"),
		filepath.Join(".GROK", "settings.json"),
		filepath.Join(".Grok", "hooks", "x"),
		filepath.Join(".VSCode", "tasks.json"),
		filepath.Join(".vscode", "Tasks.json"),
		filepath.Join(".vscode", "TASKS.JSON"),
		filepath.Join(".Idea", "workspace.xml"),
		".ENVRC",
		".Envrc",
		filepath.Join(".DevContainer", "devcontainer.json"),
		".MCP.json",
	}
	for _, rel := range rels {
		t.Run(rel, func(t *testing.T) {
			path := filepath.Join(ws, rel)
			for _, ceiling := range []Level{LevelMedium, LevelCritical} {
				wantAsk(t, evalWrite(testEngine(t), ceiling, ws, ws, "Write", path))
				wantAsk(t, evalShell(testEngine(t), ceiling, ws, ws, "git add "+rel))
			}
		})
	}
}

func TestCeilingGlobRefuse(t *testing.T) {
	ws := t.TempDir()
	asks := []struct {
		name    string
		pattern string
	}{
		{name: "dotdot", pattern: "../secret/*"},
		{name: "brace", pattern: "{a,b}/*"},
		{name: "brace-dotdot", pattern: "{..,x}/*"},
		{name: "tilde", pattern: "~/.ssh/*"},
		{name: "absolute", pattern: "/etc/passwd"},
	}
	for _, tc := range asks {
		t.Run(tc.name, func(t *testing.T) {
			wantAsk(t, globCall(testEngine(t), LevelLow, ws, tc.pattern))
			wantAsk(t, globCall(testEngine(t), LevelCritical, ws, tc.pattern))
		})
	}
	wantCeilingAllow(t, globCall(testEngine(t), LevelLow, ws, "**/*.go"))
}

func TestCeilingGitPlace(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(ws, ".git", "config"), "[core]\n\trepositoryformatversion = 0\n")
	sub := filepath.Join(ws, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	e := testEngine(t)
	wantCeilingAllow(t, evalShell(e, LevelLow, ws, ws, "git status"))
	wantCeilingAllow(t, evalShell(e, LevelLow, ws, ws, "git status >/dev/null"))
	wantCeilingAllow(t, evalShell(e, LevelLow, ws, ws, "git status >/dev/null 2>&1"))
	wantCeilingAllow(t, evalShell(e, LevelLow, ws, ws, "git diff HEAD --stat"))
	for _, ceiling := range []Level{LevelMedium, LevelCritical} {
		wantAsk(t, evalShell(testEngine(t), ceiling, ws, ws, "git -C . status"))
		wantAsk(t, evalShell(testEngine(t), ceiling, ws, ws, "git -C sub status"))
		wantAsk(t, evalShell(testEngine(t), ceiling, ws, ws, "git -Csub status"))
		wantAsk(t, evalShell(testEngine(t), ceiling, ws, ws, "git --git-dir=.git status"))
		wantAsk(t, evalShell(testEngine(t), ceiling, ws, ws, "git --git-dir .git status"))
		wantAsk(t, evalShell(testEngine(t), ceiling, sub, ws, "git status"))
	}
	// A symlink cwd has a different spelling, so the text compare falls
	// through to resolvePath. The root link is the workspace. The subdir
	// link is not.
	link := filepath.Join(t.TempDir(), "cwd-root")
	if err := os.Symlink(ws, link); err != nil {
		t.Fatal(err)
	}
	sublink := filepath.Join(t.TempDir(), "cwd-sub")
	if err := os.Symlink(sub, sublink); err != nil {
		t.Fatal(err)
	}
	wantCeilingAllow(t, evalShell(testEngine(t), LevelLow, link, ws, "git status"))
	wantCeilingAllow(t, evalShell(testEngine(t), LevelMedium, link, ws, "git status"))
	for _, ceiling := range []Level{LevelLow, LevelMedium, LevelCritical} {
		wantAsk(t, evalShell(testEngine(t), ceiling, sublink, ws, "git status"))
	}
}

func TestCeilingGitdirSignalOrder(t *testing.T) {
	ws := t.TempDir()
	rels := []string{
		filepath.Join("C", "config"),
		filepath.Join("C", "objects", "info", "k"),
		filepath.Join("C", "refs", "heads", "k"),
		filepath.Join("evil", "commondir"),
		filepath.Join("evil", "config.worktree"),
		filepath.Join("evil", "HEAD"),
		filepath.Join("evil", "gitdir"),
		filepath.Join("fresh", "hooks", "pre-commit"),
		filepath.Join("fresh", "objects", "info", "k"),
		filepath.Join("fresh", "commondir"),
		".GIT/plain",
		filepath.Join("s", ".GIT"),
	}
	for _, rel := range rels {
		t.Run(rel, func(t *testing.T) {
			path := filepath.Join(ws, rel)
			for _, ceiling := range []Level{LevelMedium, LevelCritical} {
				wantAsk(t, evalWrite(testEngine(t), ceiling, ws, ws, "Write", path))
				wantAsk(t, evalShell(testEngine(t), ceiling, ws, ws, "git add "+rel))
			}
		})
	}
}

func TestCeilingHookExceptionBounds(t *testing.T) {
	// A path with a hooks component that is not .git/hooks still asks.
	// A write of .git/hooks is a hard deny when a ceiling is set.
	clean := t.TempDir()
	wantAsk(t, evalShell(testEngine(t), LevelMedium, clean, clean, "git add evil/hooks/pre-commit"))
	wantAsk(t, evalShell(testEngine(t), LevelCritical, clean, clean, "git add evil/hooks/pre-commit"))

	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(ws, ".git", "config"), "[core]\n")
	mustWrite(t, filepath.Join(ws, ".git", "HEAD"), "ref: refs/heads/main\n")
	mustSymlink(t, "../config", filepath.Join(ws, ".git", "hooks", "pre-commit"))
	wantAsk(t, evalShell(testEngine(t), LevelMedium, ws, ws, "git add evil/hooks/pre-commit"))
	wantNeverDeny(t, evalShell(testEngine(t), LevelCritical, ws, ws, "git add .git/hooks/pre-commit"))
	wantAsk(t, evalShell(testEngine(t), LevelCritical, ws, ws, "git diff .git/hooks/pre-commit"))
	wantNeverDeny(t, evalWrite(testEngine(t), LevelCritical, ws, ws, "Write", filepath.Join(ws, ".git", "hooks", "pre-commit")))
	wantNeverDeny(t, evalShell(testEngine(t), LevelMedium, ws, ws, "git add .GIT/hooks/pre-commit"))
	wantAsk(t, evalShell(testEngine(t), LevelCritical, ws, ws, "git add .gitmodules"))

	plain := t.TempDir()
	if err := os.MkdirAll(filepath.Join(plain, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(plain, ".git", "hooks", "pre-commit"), "#!/bin/sh\n")
	wantNeverDeny(t, evalShell(testEngine(t), LevelCritical, plain, plain, "git add .git/hooks/pre-commit"))
}

func TestCeilingSpelledAndResolvedSides(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(ws, ".git", "config"), "[core]\n")
	mustSymlink(t, ".git/config", filepath.Join(ws, "inn"))
	wantAsk(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", filepath.Join(ws, "inn")))

	mustSymlink(t, ws, filepath.Join(ws, "D"))
	// Join would clean .git/.. away. The spelled string has to keep it.
	spelled := filepath.Join(ws, "D") + "/.git/../ok.txt"
	wantAsk(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", spelled))

	marked := filepath.Join(ws, "marked.txt")
	if err := os.WriteFile(marked, []byte("m"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, marked, filepath.Join(ws, "inn-crit"))
	e := testEngine(t)
	e.SetCriticalPaths([]string{marked})
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelCritical})
	raw, _ := json.Marshal(map[string]string{"file_path": filepath.Join(ws, "inn-crit")})
	req := Request{
		BotID: ceilingBot, SessionID: "sess", RunID: "run", TaskID: "task",
		Cwd: ws, Workspace: ws, ToolName: "Write", ToolInput: raw,
	}
	if !e.ceilingPathsRefuse(req, inspected{Level: LevelMedium, Eligible: true, Literal: true}) {
		t.Fatal("critical class missed the resolved target")
	}
}

func TestCeilingNestedGitRisk(t *testing.T) {
	status := func(t *testing.T, ws, home, userHome string) Decision {
		t.Helper()
		e := testEngine(t)
		e.SetBotContext(ceilingBot, ws, nil)
		e.SetBotRuntime(ceilingBot, home, userHome, nil)
		e.SnapshotBot(ceilingBot)
		e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelLow})
		req := bashReq(ceilingBot, "sess", "task", ws, "git status")
		req.Workspace = ws
		return e.Evaluate(context.Background(), req)
	}
	t.Run("gitmodules-lookalike", func(t *testing.T) {
		ws, home, userHome := cleanRepo(t)
		mustWrite(t, filepath.Join(ws, ".gitmodules"), "[submodule \"s\"]\n\tpath = s\n")
		mustWrite(t, filepath.Join(ws, "s", "HEAD"), "ref: refs/heads/main\n")
		mustWrite(t, filepath.Join(ws, "s", "objects", "info", "k"), "x\n")
		mustWrite(t, filepath.Join(ws, "s", "config"), "[core]\n\tfsmonitor = x\n")
		wantAsk(t, status(t, ws, home, userHome))
	})
	t.Run("gitmodules-refs-only", func(t *testing.T) {
		ws, home, userHome := cleanRepo(t)
		mustWrite(t, filepath.Join(ws, ".gitmodules"), "[submodule \"look\"]\n\tpath = look\n")
		mustWrite(t, filepath.Join(ws, "look", "refs", "heads", "k"), "x\n")
		mustWrite(t, filepath.Join(ws, "look", "config"), "[core]\n\tfsmonitor = x\n")
		wantAsk(t, status(t, ws, home, userHome))
	})
	t.Run("modules-hook", func(t *testing.T) {
		ws, home, userHome := cleanRepo(t)
		hook := filepath.Join(ws, ".git", "modules", "s", "hooks", "post-checkout")
		mustWrite(t, hook, "#!/bin/sh\n")
		if err := os.Chmod(hook, 0o755); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(ws, ".git", "modules", "s", "config"), "[core]\n\trepositoryformatversion = 0\n")
		wantAsk(t, status(t, ws, home, userHome))
	})
	t.Run("loose-git-dir", func(t *testing.T) {
		ws, home, userHome := cleanRepo(t)
		mustWrite(t, filepath.Join(ws, "n", ".git", "HEAD"), "ref: refs/heads/main\n")
		mustWrite(t, filepath.Join(ws, "n", ".git", "config"), "[core]\n\tfsmonitor = x\n")
		wantAsk(t, status(t, ws, home, userHome))
	})
	t.Run("separate-gitdir", func(t *testing.T) {
		ws, home, userHome := cleanRepo(t)
		elseDir := t.TempDir()
		mustWrite(t, filepath.Join(elseDir, "HEAD"), "ref: refs/heads/main\n")
		mustWrite(t, filepath.Join(elseDir, "config"), "[core]\n\tfsmonitor = x\n")
		mustWrite(t, filepath.Join(ws, "n", ".git"), "gitdir: "+elseDir+"\n")
		wantAsk(t, status(t, ws, home, userHome))
	})
}

func TestCeilingLiveFsmonitor(t *testing.T) {
	requireGit(t)
	ws := t.TempDir()
	runGit(t, ws, "init")
	mustSymlink(t, ".git/config", filepath.Join(ws, "g_cfg"))
	for _, ceiling := range []Level{LevelMedium, LevelCritical} {
		wantAsk(t, evalWrite(testEngine(t), ceiling, ws, ws, "Write", filepath.Join(ws, "g_cfg")))
	}
	e := testEngine(t)
	home := t.TempDir()
	e.SetBotContext(ceilingBot, ws, nil)
	e.SetBotRuntime(ceilingBot, home, home, nil)
	e.SnapshotBot(ceilingBot)
	cfg := filepath.Join(ws, ".git", "config")
	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, append(b, []byte("\n[core]\n\tfsmonitor = true\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelLow})
	req := bashReq(ceilingBot, "sess", "task", ws, "git status")
	req.Workspace = ws
	wantAsk(t, e.Evaluate(context.Background(), req))
}
