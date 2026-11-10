package permbroker

import (
	"path/filepath"
	"testing"
)

func r9Ask(t *testing.T, ws, cmd string) {
	t.Helper()
	for _, ceiling := range []Level{LevelLow, LevelMedium, LevelCritical} {
		d := evalShell(testEngine(t), ceiling, ws, ws, cmd)
		if d.Verdict == VerdictAllow {
			t.Fatalf("%s allowed at %s: %+v", cmd, ceiling, d)
		}
	}
}

func r9Allow(t *testing.T, ws string, ceiling Level, cmd string) {
	t.Helper()
	d := evalShell(testEngine(t), ceiling, ws, ws, cmd)
	if d.Verdict != VerdictAllow || d.PendingID != "" || d.Actor != AllowThroughSource {
		t.Fatalf("%s at %s: %+v", cmd, ceiling, d)
	}
}

func r9Repo(t *testing.T) string {
	t.Helper()
	ws := t.TempDir()
	mustWrite(t, filepath.Join(ws, "README.md"), "hi\n")
	mustWrite(t, filepath.Join(ws, ".env"), "S=1\n")
	return ws
}

// TestR9Fix1_OptionalValue pins git's optional-argument rule.
// A bare --pretty does not swallow the next word. Reverting that
// consumption lets `git show --pretty HEAD:.env --stat` auto-approve.
func TestR9Fix1_OptionalValue(t *testing.T) {
	ws := r9Repo(t)
	if !gitSecretRead([]string{"git", "show", "--pretty", "HEAD:.env", "--stat"}) {
		t.Fatal("gitSecretRead hid HEAD:.env")
	}
	pos := positionalsOf([]string{"--pretty", "HEAD:.env", "--stat"})
	if len(pos) != 1 || pos[0] != "HEAD:.env" {
		t.Fatalf("positionals %#v", pos)
	}
	if ceilingGitPermit([]string{"git", "show", "--pretty", "HEAD:.env", "--stat"}) {
		t.Fatal("show shape swallowed HEAD:.env")
	}
	if ceilingGitPermit([]string{"git", "describe", "--abbrev", "HEAD:.env"}) {
		t.Fatal("describe swallowed HEAD:.env")
	}
	asks := []string{
		"git show --pretty HEAD:.env --stat",
		"git show --format HEAD:.env --stat",
		"git show --pretty :.env --stat",
		"git show --format :.env --name-only",
		"git show --pretty :.env --name-status",
		"git add :/",
		"git describe --abbrev HEAD:.env",
		"git status --untracked-files :/",
		"git status -u :/",
		"git status --ignored '*'",
		"git status --find-renames '*'",
		"git log --pretty '*'",
		"git log --format HEAD:.env",
		"git log --decorate '*'",
		"git diff --stat --find-renames=50",
	}
	for _, cmd := range asks {
		r9Ask(t, ws, cmd)
	}
	r9Allow(t, ws, LevelLow, "git show --pretty=oneline --stat HEAD")
	r9Allow(t, ws, LevelLow, "git show --pretty --stat HEAD")
	r9Allow(t, ws, LevelLow, "git show --format=%s --stat HEAD")
	r9Allow(t, ws, LevelLow, "git log --pretty=format:%s")
	r9Allow(t, ws, LevelLow, "git log --pretty HEAD --stat")
	r9Allow(t, ws, LevelLow, "git status -uall")
	r9Allow(t, ws, LevelLow, "git status --untracked-files=all")
	r9Allow(t, ws, LevelLow, "git status --ignored=traditional")
	r9Allow(t, ws, LevelLow, "git status --find-renames=50")
	r9Allow(t, ws, LevelLow, "git describe --abbrev=4 --always")
	r9Allow(t, ws, LevelLow, "git describe --match 'v*' --always")
}

// TestR9Fix2_ShowCommitish pins show to plain commit-ish objects.
// A hex id is not checked with git cat-file. The broker does not run git.
// Bare `git show HEAD` stays an ask because it prints the patch.
func TestR9Fix2_ShowCommitish(t *testing.T) {
	ws := r9Repo(t)
	blob := "e9aaabc9e1bc61bd99aa4617cf6ac4d72dd64915"
	if plainCommitish(blob) || plainCommitish("e9aaabc") || plainCommitish("ABCD") {
		t.Fatal("hex id treated as a commit")
	}
	if !plainCommitish("HEAD") || !plainCommitish("HEAD^") || !plainCommitish("HEAD~1") || !plainCommitish("main") {
		t.Fatal("plain rev refused")
	}
	asks := []string{
		"git show --stat " + blob,
		"git show --name-only " + blob,
		"git show --name-status e9aaabc",
		"git show --stat ABCD",
		"git show --stat HEAD:.env",
		"git show --stat :.env",
		"git show --stat 'HEAD^{tree}'",
		"git show HEAD",
		"git show --pretty=oneline HEAD",
	}
	for _, cmd := range asks {
		r9Ask(t, ws, cmd)
	}
	r9Allow(t, ws, LevelLow, "git show --stat HEAD")
	r9Allow(t, ws, LevelLow, "git show --stat")
	r9Allow(t, ws, LevelLow, "git show --name-only HEAD")
	r9Allow(t, ws, LevelLow, "git show --name-status HEAD")
	r9Allow(t, ws, LevelLow, "git show --stat 'HEAD^'")
	r9Allow(t, ws, LevelLow, "git show --stat 'HEAD~1'")
	r9Allow(t, ws, LevelLow, "git show --stat main")
	r9Allow(t, ws, LevelLow, "git show --stat HEAD -- README.md")
}

// TestR9Fix3_RemoteURL pins URL-printing remote forms.
// r8 allowed `git remote -v` at low. That row moved to an ask.
func TestR9Fix3_RemoteURL(t *testing.T) {
	ws := r9Repo(t)
	if remoteListOK([]string{"-v"}) || remoteListOK([]string{"--verbose"}) || remoteListOK([]string{"show"}) {
		t.Fatal("remote list accepted a URL form")
	}
	if !remoteListOK(nil) {
		t.Fatal("bare remote refused")
	}
	for _, cmd := range []string{
		"git remote -v",
		"git remote --verbose",
		"git remote -vv",
		"git remote show",
		"git remote show origin",
		"git remote get-url origin",
	} {
		r9Ask(t, ws, cmd)
	}
	r9Allow(t, ws, LevelLow, "git remote")
}

// TestR9Fix4_SharedSecrets pins the one credential list and the .env*
// rule. gitSecretRead is what fails if .env* is removed. blameShape is
// checked on its own so dropping that call is visible too.
func TestR9Fix4_SharedSecrets(t *testing.T) {
	ws := r9Repo(t)
	names := []string{
		".npmrc",
		".netrc",
		".pypirc",
		".git-credentials",
		".aws/credentials",
		".aws/config",
		".ssh/config",
		".docker/config.json",
		".kube/config",
		"credentials",
		"credentials.json",
		"credentials.txt",
		"auth.json",
		"cookies",
		"cookies.txt",
		".env.example",
		".env.sample",
		".env.local",
	}
	if !gitSecretRead([]string{"git", "blame", ".env.example"}) {
		t.Fatal("gitSecretRead missed .env.example")
	}
	if !gitSecretReadPath(".env.example") || ceilingCredentialPath(".env.example") {
		t.Fatal(".env.example must ask for git and must not hard-deny")
	}
	rule, ok := ceilingGitLookup("blame")
	if !ok || blameShape([]string{".env.example"}, rule) {
		t.Fatal("blameShape allowed .env.example")
	}
	for _, name := range names {
		if name != ".env.example" && name != ".env.sample" && !ceilingCredentialPath(name) {
			t.Fatalf("credential list missed %s", name)
		}
		if !gitSecretReadPath(name) {
			t.Fatalf("git secret list missed %s", name)
		}
		r9Ask(t, ws, "git blame "+name)
		r9Ask(t, ws, "git show --stat -- "+name)
		r9Ask(t, ws, "git diff --stat -- "+name)
	}
	r9Allow(t, ws, LevelLow, "git blame README.md")
	r9Allow(t, ws, LevelLow, "git diff --stat -- README.md")
	r9Allow(t, ws, LevelLow, "git log --stat -- README.md")
}

// TestR9Fix5_Pathspec pins magic, glob, and root pathspecs on the
// commands that accept them. Ordinary names stay allowed.
func TestR9Fix5_Pathspec(t *testing.T) {
	ws := r9Repo(t)
	mustWrite(t, filepath.Join(ws, "src", "a.txt"), "a\n")
	asks := []string{
		"git add :/",
		"git add ':(top)'",
		"git add '*'",
		"git add .",
		"git add ./.",
		"git add src/..",
		"git add a/b/../..",
		"git add 'a?b'",
		"git add 'a[b]'",
		"git commit -m x :/",
		"git commit -m x '*'",
		"git commit -m x .",
		"git commit -m x ./.",
		"git diff --stat -- '*'",
		"git diff --stat -- .",
		"git diff --stat -- :/",
		"git log -- '*'",
		"git log -- .",
		"git log -- :/",
		"git blame '*'",
		"git blame .",
		"git ls-files '*'",
		"git ls-files .",
		"git status '*'",
		"git status -- .",
		"git status -- :/",
		"git rev-parse '*'",
	}
	for _, cmd := range asks {
		r9Ask(t, ws, cmd)
	}
	r9Allow(t, ws, LevelMedium, "git add README.md")
	r9Allow(t, ws, LevelMedium, "git add src/a.txt")
	r9Allow(t, ws, LevelMedium, "git commit -m x README.md")
	r9Allow(t, ws, LevelMedium, "git commit -m x src/a.txt")
	r9Allow(t, ws, LevelLow, "git status")
	r9Allow(t, ws, LevelLow, "git status -- README.md")
	r9Allow(t, ws, LevelLow, "git log --stat")
	r9Allow(t, ws, LevelLow, "git log -- README.md")
	r9Allow(t, ws, LevelLow, "git diff --stat HEAD")
	r9Allow(t, ws, LevelLow, "git diff --stat -- README.md")
	r9Allow(t, ws, LevelLow, "git blame README.md")
	r9Allow(t, ws, LevelLow, "git ls-files")
	r9Allow(t, ws, LevelLow, "git ls-files README.md")
}

// TestR9Fix6a_BranchVerbose pins branch creation hidden behind -v.
// A pattern is allowed only with --list or -l.
func TestR9Fix6a_BranchVerbose(t *testing.T) {
	ws := r9Repo(t)
	rule, ok := ceilingGitLookup("branch")
	if !ok {
		t.Fatal("no branch row")
	}
	if branchListOK([]string{"-v", "newb"}, rule) || branchListOK([]string{"-vv", "--", "newb"}, rule) {
		t.Fatal("branch -v NAME listed")
	}
	if !branchListOK([]string{"-v"}, rule) || !branchListOK([]string{"--list", "newb"}, rule) {
		t.Fatal("branch list refused")
	}
	for _, cmd := range []string{
		"git branch -v newb",
		"git branch -vv newb",
		"git branch -v newb evil",
		"git branch -vv -- newb",
		"git branch -a newb",
		"git branch -r newb",
		"git branch --verbose newb",
	} {
		r9Ask(t, ws, cmd)
	}
	if !branchListOK([]string{"-l", "feat*"}, rule) || !branchListOK([]string{"-r"}, rule) {
		t.Fatal("list shape refused")
	}
	r9Allow(t, ws, LevelLow, "git branch")
	r9Allow(t, ws, LevelLow, "git branch --list")
	r9Allow(t, ws, LevelLow, "git branch -v")
	r9Allow(t, ws, LevelLow, "git branch -vv")
	r9Allow(t, ws, LevelLow, "git branch -a")
	r9Allow(t, ws, LevelLow, "git branch --list newb")
	r9Allow(t, ws, LevelLow, "git branch --list 'feat*'")
	r9Allow(t, ws, LevelLow, "git branch -a --list newb")
}

// TestR9Fix6b_FormatGPG pins %G pretty placeholders.
func TestR9Fix6b_FormatGPG(t *testing.T) {
	ws := r9Repo(t)
	rule, ok := ceilingGitLookup("log")
	if !ok || logShape([]string{"--pretty=format:%GG"}, rule) {
		t.Fatal("log allowed a G placeholder")
	}
	for _, cmd := range []string{
		"git log --pretty=format:%GG",
		"git log --format=%GS",
		"git log --pretty=format:%GK",
		"git log --pretty=%GF",
		"git log --pretty=tformat:%GP",
		"git log --format='%G?'",
		"git show --stat --pretty=format:%G HEAD",
		"git show --stat --format=%GG HEAD",
	} {
		r9Ask(t, ws, cmd)
	}
	r9Allow(t, ws, LevelLow, "git log --format=%s")
	r9Allow(t, ws, LevelLow, "git log --pretty=format:%h --stat")
	r9Allow(t, ws, LevelLow, "git show --stat --pretty=format:%s HEAD")
	r9Allow(t, ws, LevelMedium, "git commit -m '%G'")
}
