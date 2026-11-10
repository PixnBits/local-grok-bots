package permbroker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCeilingGitAllowlist(t *testing.T) {
	ws := t.TempDir()
	mustWrite(t, filepath.Join(ws, "README"), "hi\n")
	mustWrite(t, filepath.Join(ws, ".env"), "S=1\n")
	allows := []struct {
		ceiling Level
		cmd     string
	}{
		{LevelLow, "git status"},
		{LevelLow, "git status -sb"},
		{LevelLow, "git log --oneline"},
		{LevelLow, "git log -- .env"},
		{LevelLow, "git diff HEAD --stat"},
		{LevelLow, "git diff --stat -- README"},
		{LevelLow, "git show --stat"},
		{LevelLow, "git show --stat HEAD"},
		{LevelLow, "git rev-parse --abbrev-ref HEAD"},
		{LevelLow, "git ls-files"},
		{LevelLow, "git branch"},
		{LevelLow, "git branch --list"},
		{LevelLow, "git branch -a"},
		{LevelLow, "git tag --list"},
		{LevelLow, "git remote"},
		// r9 SHOULD-5: `git remote -v` prints remote URLs, so it asks.
		{LevelLow, "git describe --tags"},
		{LevelLow, "git blame README"},
		{LevelMedium, "git add README"},
		{LevelMedium, `git commit -m "core.hooksPath"`},
		{LevelCritical, `git commit -m "core.hooksPath"`},
		{LevelMedium, `git commit -m "note" README`},
	}
	for _, tc := range allows {
		t.Run(tc.cmd, func(t *testing.T) {
			wantCeilingAllow(t, evalShell(testEngine(t), tc.ceiling, ws, ws, tc.cmd))
		})
	}
	asks := []string{
		"git version",
		"git help",
		"git fetch origin",
		"git push",
		"git archive HEAD",
		"git init",
		"git diff",
		"git show HEAD",
		"git log -p",
		"git log -p -- README",
		"git log -p -- .env",
		"git branch -d side",
		"git tag -d v1",
		"git commit --amend -m x",
		"git commit -F msg",
		"git commit -m x --no-verify",
		"git commit -am x",
		"git add .",
		"git add -A",
		"git stash",
		"git stash list",
		"git checkout main",
		"git remote add origin https://example.invalid/x.git",
		// r9 SHOULD-5: verbose remote output is no longer low-allowed.
		"git remote -v",
		"git diff --stat -- .env",
		"git show HEAD:.env",
		"git show --stat HEAD:.env",
		"git cat-file -p HEAD:.env",
		"git grep TOKEN",
		"git grep TOKEN -- README",
		"git blame .env",
		"git diff -- .env",
	}
	for _, cmd := range asks {
		t.Run(cmd, func(t *testing.T) {
			for _, ceiling := range []Level{LevelLow, LevelCritical} {
				d := evalShell(testEngine(t), ceiling, ws, ws, cmd)
				wantAsk(t, d)
				if d.Actor == neverAllowActor {
					t.Fatalf("hard deny %+v", d)
				}
			}
		})
	}
}

func TestCeilingGitAllowlistUnits(t *testing.T) {
	for _, sub := range []string{
		"apply", "am", "checkout", "switch", "restore", "merge", "pull",
		"rebase", "cherry-pick", "revert", "reset", "stash", "mv",
		"read-tree", "worktree", "clone", "submodule", "checkout-index",
		"sparse-checkout",
	} {
		if !ceilingGitAlwaysAsk(sub) {
			t.Fatalf("%s is not always-ask", sub)
		}
	}
	if ceilingGitPermit([]string{"git", "version"}) {
		t.Fatal("version permitted")
	}
	if ceilingGitPermit([]string{"git", "apply", "p.patch"}) {
		t.Fatal("apply permitted")
	}
	if !ceilingGitPermit([]string{"git", "status"}) {
		t.Fatal("status refused")
	}
	if !gitSecretRead([]string{"git", "cat-file", "-p", "HEAD:.env"}) {
		t.Fatal("cat-file")
	}
	if !gitSecretRead([]string{"git", "grep", "TOKEN"}) {
		t.Fatal("grep no path")
	}
	if gitSecretRead([]string{"git", "grep", "TOKEN", "--", "README"}) {
		t.Fatal("grep with a safe pathspec")
	}
	if !gitSecretRead([]string{"git", "grep", "TOKEN", "--", ".env"}) {
		t.Fatal("grep secret path")
	}
	if !gitSecretRead([]string{"git", "show", "HEAD:.env"}) {
		t.Fatal("show rev:path")
	}
	if !gitSecretRead([]string{"git", "log", "-p", "--", "README"}) {
		t.Fatal("log -p")
	}
	if gitSecretRead([]string{"git", "log", "--", ".env"}) {
		t.Fatal("log subjects")
	}
	if !gitSecretRead([]string{"git", "diff", "--stat", "--", ".env"}) {
		t.Fatal("diff stat secret")
	}
	if gitSecretRead([]string{"git", "diff", "HEAD", "--stat"}) {
		t.Fatal("diff stat safe")
	}
	for _, argv := range [][]string{
		{"git", "clone", "--separate-git-dir=.git/hooks/x", "sub"},
		{"git", "clone", "--separate-git-dir", ".git/hooks/x", "sub"},
		{"git", "clone", "--template=.git/hooks", "sub"},
		{"git", "clone", "--git-dir=.git/hooks/x", "sub"},
		{"git", "clone", "--work-tree=.git/hooks", "sub"},
		{"git", "--output=.claude/settings.json", "diff", "--stat"},
	} {
		got := gitPathFlagPaths(argv)
		if len(got) == 0 || got[0].value == "" {
			t.Fatalf("no flag path in %q", argv)
		}
	}
	mv := createdDirIndexes([]string{"git", "mv", "d", ".VSCode"})
	if !mv[3] {
		t.Fatalf("git mv dest %#v", mv)
	}
	if !createdDirRefused(".VSCode", ".VSCode") || !createdDirRefused(".IDEA", ".IDEA") {
		t.Fatal("case class")
	}
	cp := createdDirIndexes([]string{"cp", "a", ".husky"})
	if !cp[2] {
		t.Fatalf("cp dest %#v", cp)
	}
	shell := createdDirIndexes([]string{"mv", "d", ".idea"})
	if !shell[2] {
		t.Fatalf("mv dest %#v", shell)
	}
	ln := createdDirIndexes([]string{"ln", "-s", "d", ".vscode"})
	if !ln[3] {
		t.Fatalf("ln dest %#v", ln)
	}
	rs := createdDirIndexes([]string{"rsync", "-a", "d", ".vscode"})
	if !rs[3] {
		t.Fatalf("rsync dest %#v", rs)
	}
	inst := createdDirIndexes([]string{"install", "d", ".idea"})
	if !inst[2] {
		t.Fatalf("install dest %#v", inst)
	}
}

func TestCeilingExactHardDeny(t *testing.T) {
	ws := t.TempDir()
	key := filepath.Join(ws, "id_ed25519")
	mustWrite(t, key, "k\n")
	mustWrite(t, filepath.Join(ws, ".netrc"), "m\n")
	mustWrite(t, filepath.Join(ws, ".git-credentials"), "c\n")
	mustWrite(t, filepath.Join(ws, "admin-token"), "t\n")
	mustWrite(t, filepath.Join(ws, "github.token"), "g\n")
	mustWrite(t, filepath.Join(ws, ".config", "gh", "hosts.yml"), "h\n")
	mustWrite(t, filepath.Join(ws, ".config", "git", "credentials"), "c\n")
	mustWrite(t, filepath.Join(ws, ".env"), "S=1\n")
	mustWrite(t, filepath.Join(ws, ".env.local"), "S=1\n")
	mustWrite(t, filepath.Join(ws, ".env.example"), "A=1\n")
	mustWrite(t, filepath.Join(ws, "ca.pem"), "cert\n")
	mustWrite(t, filepath.Join(ws, "public.key"), "k\n")
	mustWrite(t, filepath.Join(ws, "README"), "hi\n")
	mustWrite(t, filepath.Join(ws, ".git", "config"), "[core]\n")
	hook := filepath.Join(ws, ".git", "hooks", "pre-commit")
	mustWrite(t, hook, "#!/bin/sh\n")

	denies := []struct {
		cmd, why string
	}{
		{"gh auth token", neverAllowCredential},
		{"gh auth token --hostname example.com", neverAllowCredential},
		{"gh --hostname example.com auth token", neverAllowCredential},
		{"gh auth --hostname example.com token", neverAllowCredential},
		{"git credential fill", neverAllowCredential},
		{"git credential approve", neverAllowCredential},
		{"git credential reject", neverAllowCredential},
		{"git -c user.name=a credential fill", neverAllowCredential},
		{"head " + key, neverAllowCredential},
		{"cat " + key, neverAllowCredential},
		{"tail " + key, neverAllowCredential},
		{"less " + filepath.Join(ws, ".netrc"), neverAllowCredential},
		{"cat " + filepath.Join(ws, ".git-credentials"), neverAllowCredential},
		{"cat " + filepath.Join(ws, "admin-token"), neverAllowCredential},
		{"cat " + filepath.Join(ws, "github.token"), neverAllowCredential},
		{"cat " + filepath.Join(ws, ".config", "gh", "hosts.yml"), neverAllowCredential},
		{"cat " + filepath.Join(ws, ".config", "git", "credentials"), neverAllowCredential},
		{"cat " + filepath.Join(ws, ".env"), neverAllowCredential},
		{"head " + filepath.Join(ws, ".env.local"), neverAllowCredential},
		{"git config core.hooksPath ./h", neverAllowHook},
		{"git config core.hooksPath", neverAllowHook},
		{"git config --file .gitconfig core.hooksPath ./h", neverAllowHook},
		{"git -c core.hooksPath=/tmp/h status", neverAllowHook},
		{"git -c core.hooksPath=/tmp/h status", neverAllowHook},
		{"git --config core.hooksPath=/tmp/h status", neverAllowHook},
		{"git -ccore.hooksPath=/tmp/h status", neverAllowHook},
		{"git add .git/hooks/pre-commit", neverAllowHook},
		{"git mv a.txt .git/hooks/pre-commit", neverAllowHook},
		{"echo x > .git/hooks/pre-commit", neverAllowHook},
		{"git status > .git/hooks/pre-commit", neverAllowHook},
		{"git clone --separate-git-dir=.git/hooks/x sub", neverAllowHook},
		{"git clone --separate-git-dir .git/hooks/x sub", neverAllowHook},
		{"git clone --template=.git/hooks sub", neverAllowHook},
		{"git clone --template .git/hooks sub", neverAllowHook},
		{"git clone --git-dir=.git/hooks/x sub", neverAllowHook},
		{"git clone --git-dir .git/hooks/x sub", neverAllowHook},
		{"git clone --work-tree=.git/hooks sub", neverAllowHook},
		{"git clone --work-tree .git/hooks sub", neverAllowHook},
	}
	for _, tc := range denies {
		t.Run(tc.cmd, func(t *testing.T) {
			for _, ceiling := range []Level{LevelLow, LevelCritical} {
				e := testEngine(t)
				d := evalShell(e, ceiling, ws, ws, tc.cmd)
				wantNeverDeny(t, d)
				if !strings.Contains(d.Reason, tc.why) {
					t.Fatalf("%+v", d)
				}
			}
		})
	}

	asks := []string{
		"cat " + filepath.Join(ws, ".env.example"),
		"head " + filepath.Join(ws, "ca.pem"),
		"cat " + filepath.Join(ws, "public.key"),
		"gh auth status",
		"gh auth status -t",
		"gh auth status --show-token",
		"gh secret list",
		"gh ssh-key list",
		"gh auth login --with-token",
		"git credential-store",
		"git credential-store store",
		"printenv",
		"command git status",
		"env git status",
		"timeout 1 git status",
		"sh -c 'git status'",
		"git status < " + filepath.Join(ws, ".netrc"),
		"cp README .git/hooks/pre-commit",
		"mv README .git/hooks/pre-commit",
		"ln -s README .git/hooks/pre-commit",
		"tee .git/hooks/pre-commit",
		"grep TOKEN " + key,
		"git config user.name core.hooksPath",
		"git -c include.path=core.hooksPath status",
		"git clone --separate-git-dir=.vscode sub",
		"git clone --template=.claude sub",
		"git clone --work-tree=.vscode status",
		"mv d .vscode",
		"cp d .idea",
		"install d .husky/pre-commit",
		"ln -s d .VSCode",
		"rsync -a d .IDEA",
		"git mv d .vscode",
		"git mv d .idea",
		"git mv d .VSCode",
		"git mv d .IDEA",
	}
	for _, cmd := range asks {
		t.Run(cmd, func(t *testing.T) {
			d := evalShell(testEngine(t), LevelCritical, ws, ws, cmd)
			wantAsk(t, d)
			if d.Actor == neverAllowActor {
				t.Fatalf("hard deny %+v", d)
			}
		})
	}

	raw := readReq(ceilingBot, ws, ws, key)
	e := testEngine(t)
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelCritical})
	wantNeverDeny(t, e.Evaluate(t.Context(), raw))
	pem := readReq(ceilingBot, ws, ws, filepath.Join(ws, "ca.pem"))
	d := e.Evaluate(t.Context(), pem)
	wantAsk(t, d)
	if d.Actor == neverAllowActor {
		t.Fatalf("pem deny %+v", d)
	}
}

func TestCeilingContentWritersAsk(t *testing.T) {
	requireGit(t)
	root := t.TempDir()
	origin := filepath.Join(root, "origin")
	if err := os.MkdirAll(origin, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, origin, "init", "-q", "-b", "main")
	mustWrite(t, filepath.Join(origin, "README"), "hi\n")
	runGit(t, origin, "add", "README")
	runGit(t, origin, "commit", "-q", "-m", "init")
	runGit(t, origin, "checkout", "-q", "-b", "side")
	mustWrite(t, filepath.Join(origin, ".claude", "settings.json"), "{}\n")
	mustWrite(t, filepath.Join(origin, ".vscode", "settings.json"), "{}\n")
	mustWrite(t, filepath.Join(origin, ".husky", "pre-commit"), "#!/bin/sh\n")
	runGit(t, origin, "add", "-A")
	runGit(t, origin, "commit", "-q", "-m", "class")
	side := strings.TrimSpace(string(runGitOut(t, origin, "rev-parse", "HEAD")))
	runGit(t, origin, "checkout", "-q", "main")
	patch := runGitOut(t, origin, "diff", "main..side")
	ws := filepath.Join(root, "ws")
	runGit(t, root, "clone", "-q", origin, ws)
	mustWrite(t, filepath.Join(ws, "class.patch"), string(patch))
	mustWrite(t, filepath.Join(ws, "d", "f"), "f\n")

	cmds := []string{
		"git apply class.patch",
		"git apply --cached class.patch",
		"git apply --index class.patch",
		"git am class.patch",
		"git checkout side",
		"git switch side",
		"git restore --source side -- .claude/settings.json",
		"git merge side",
		"git pull origin side",
		"git rebase side",
		"git cherry-pick " + side,
		"git revert " + side,
		"git reset --hard side",
		"git reset side",
		"git stash pop",
		"git stash apply",
		"git mv d .vscode",
		"git mv d .idea",
		"git mv d .VSCode",
		"git mv d .IDEA",
		"git read-tree " + side,
		"git read-tree -u " + side,
		"git worktree add ../wt side",
		"git clone " + origin + " dest",
		"git submodule update",
		"git checkout-index -a",
		"git sparse-checkout set .claude",
		"mv d .vscode",
		"cp -r d .vscode",
		"install d .idea/x",
		"ln -s d .husky/pre-commit",
		"rsync -a d .vscode",
	}
	for _, cmd := range cmds {
		t.Run(cmd, func(t *testing.T) {
			for _, ceiling := range []Level{LevelLow, LevelCritical} {
				d := evalShell(testEngine(t), ceiling, ws, ws, cmd)
				wantAsk(t, d)
				if d.Actor == neverAllowActor {
					t.Fatalf("hard deny %+v", d)
				}
			}
		})
	}

	applyRepo := filepath.Join(root, "apply")
	runGit(t, root, "clone", "-q", origin, applyRepo)
	mustWrite(t, filepath.Join(applyRepo, "class.patch"), string(patch))
	runGit(t, applyRepo, "apply", "class.patch")
	for _, rel := range []string{".claude/settings.json", ".vscode/settings.json", ".husky/pre-commit"} {
		if _, err := os.Stat(filepath.Join(applyRepo, rel)); err != nil {
			t.Fatalf("apply %s: %v", rel, err)
		}
	}
	checkoutRepo := filepath.Join(root, "checkout")
	runGit(t, root, "clone", "-q", origin, checkoutRepo)
	runGit(t, checkoutRepo, "checkout", "-q", "side")
	if _, err := os.Stat(filepath.Join(checkoutRepo, ".claude", "settings.json")); err != nil {
		t.Fatal(err)
	}
	mergeRepo := filepath.Join(root, "merge")
	runGit(t, root, "clone", "-q", origin, mergeRepo)
	mainSHA := strings.TrimSpace(string(runGitOut(t, mergeRepo, "rev-parse", "HEAD")))
	runGit(t, mergeRepo, "merge", "-q", "--no-edit", "origin/side")
	if _, err := os.Stat(filepath.Join(mergeRepo, ".husky", "pre-commit")); err != nil {
		t.Fatal(err)
	}
	runGit(t, mergeRepo, "reset", "-q", "--hard", mainSHA)
	if _, err := os.Stat(filepath.Join(mergeRepo, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("reset left class files: %v", err)
	}
	treeRepo := filepath.Join(root, "tree")
	runGit(t, root, "clone", "-q", origin, treeRepo)
	runGit(t, treeRepo, "read-tree", "--reset", "-u", side)
	if _, err := os.Stat(filepath.Join(treeRepo, ".vscode", "settings.json")); err != nil {
		t.Fatalf("read-tree: %v", err)
	}

	mvRepo := filepath.Join(root, "mv")
	runGit(t, root, "clone", "-q", origin, mvRepo)
	mustWrite(t, filepath.Join(mvRepo, "d", "f"), "f\n")
	runGit(t, mvRepo, "add", "d")
	runGit(t, mvRepo, "commit", "-q", "-m", "d")
	runGit(t, mvRepo, "mv", "d", ".vscode")
	if _, err := os.Stat(filepath.Join(mvRepo, ".vscode", "f")); err != nil {
		t.Fatal(err)
	}
	runGit(t, mvRepo, "mv", ".vscode", ".VSCode")
	if _, err := os.Stat(filepath.Join(mvRepo, ".VSCode", "f")); err != nil {
		t.Fatal(err)
	}
	runGit(t, mvRepo, "mv", ".VSCode", ".IDEA")
	if _, err := os.Stat(filepath.Join(mvRepo, ".IDEA", "f")); err != nil {
		t.Fatal(err)
	}
}

func TestCeilingWrapperNames(t *testing.T) {
	for _, name := range []string{"command", "env", "timeout", "sh", "bash", "tee"} {
		if !wrapperArgv([]string{name, "git", "status"}) {
			t.Fatalf("%s is not a wrapper", name)
		}
	}
}

func TestCeilingHooksPathEnvAsks(t *testing.T) {
	ws, home, userHome := cleanRepo(t)
	e := testEngine(t)
	e.SetBotContext(ceilingBot, ws, nil)
	e.SetBotRuntime(ceilingBot, home, userHome, []string{"GIT_CONFIG_KEY_0=core.hooksPath", "GIT_CONFIG_VALUE_0=/tmp/h", "GIT_CONFIG_COUNT=1"})
	e.SnapshotBot(ceilingBot)
	d := evalShell(e, LevelCritical, ws, ws, "git status")
	wantAsk(t, d)
	if d.Actor == neverAllowActor {
		t.Fatalf("hard deny %+v", d)
	}
}
