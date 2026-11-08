package permbroker

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// plantKernelDecoys builds the git-apply layouts from the r5 probe.
// Each outer name is an innocuous symlink. The bytes of the target are
// the kernel name. A trim or a backslash rewrite lands on a regular
// decoy file that is not sensitive.
func plantKernelDecoys(t *testing.T, ws string) {
	t.Helper()
	mustWrite(t, filepath.Join(ws, ".git", "config"), "[core]\n\trepositoryformatversion = 0\n")
	mustWrite(t, filepath.Join(ws, ".git", "hooks", "pre-commit"), "#!/bin/sh\n")
	mustWrite(t, filepath.Join(ws, ".claude", "settings.json"), "{}\n")
	mustWrite(t, filepath.Join(ws, ".grok", "settings.json"), "{}\n")
	mustWrite(t, filepath.Join(ws, "q", "r"), "decoy\n")
	mustWrite(t, filepath.Join(ws, "foo"), "decoy\n")
	mustWrite(t, filepath.Join(ws, "inn3"), "decoy\n")
	mustWrite(t, filepath.Join(ws, "bar"), "decoy\n")
	mustWrite(t, filepath.Join(ws, "baz"), "decoy\n")
	mustWrite(t, filepath.Join(ws, "hd", "pre-commit"), "decoy\n")
	links := []struct{ name, target string }{
		{"inn", `q\r`},
		{`q\r`, ".git/config"},
		{"inn2", "foo "},
		{"foo ", ".git/config"},
		{"inn3 ", ".git/config"},
		{"inn4", "\tbar"},
		{"\tbar", ".claude/settings.json"},
		{"inn5", " baz"},
		{" baz", ".grok/settings.json"},
		{"hk", `hd\pre-commit`},
		{`hd\pre-commit`, ".git/hooks/pre-commit"},
	}
	for _, l := range links {
		mustSymlink(t, l.target, filepath.Join(ws, l.name))
	}
}

func assertFaithful(t *testing.T, base, spelled, suffix string) {
	t.Helper()
	abs := spelled
	if !filepath.IsAbs(spelled) {
		abs = filepath.Join(base, spelled)
	}
	kernel, err := filepath.EvalSymlinks(abs)
	if err != nil {
		t.Fatalf("kernel %q: %v", spelled, err)
	}
	var got string
	if filepath.IsAbs(spelled) {
		got, err = resolvePath(spelled)
	} else {
		got, err = resolveFrom(base, spelled)
	}
	if err != nil {
		t.Fatalf("resolve %q: %v", spelled, err)
	}
	if got != kernel {
		t.Fatalf("resolve %q = %q, kernel %q", spelled, got, kernel)
	}
	if !strings.HasSuffix(got, suffix) {
		t.Fatalf("resolve %q = %q, want suffix %s", spelled, got, suffix)
	}
}

func TestCeilingKernelBytes(t *testing.T) {
	ws := t.TempDir()
	plantKernelDecoys(t, ws)
	cases := []struct {
		name, spelled, suffix string
	}{
		{"backslash-target", filepath.Join(ws, "inn"), "/.git/config"},
		{"space-target", filepath.Join(ws, "inn2"), "/.git/config"},
		{"space-spelled", filepath.Join(ws, "inn3 "), "/.git/config"},
		{"tab-target-claude", filepath.Join(ws, "inn4"), "/.claude/settings.json"},
		{"space-target-grok", filepath.Join(ws, "inn5"), "/.grok/settings.json"},
		{"backslash-hook", filepath.Join(ws, "hk"), "/.git/hooks/pre-commit"},
		{"rel-backslash", "inn", "/.git/config"},
		{"rel-space-spelled", "inn3 ", "/.git/config"},
		{"rel-tab-claude", "inn4", "/.claude/settings.json"},
		{"rel-grok", "inn5", "/.grok/settings.json"},
		{"rel-hook", "hk", "/.git/hooks/pre-commit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertFaithful(t, ws, tc.spelled, tc.suffix)
			for _, tool := range []string{"Write", "Edit"} {
				for _, ceiling := range []Level{LevelMedium, LevelCritical} {
					d := evalWrite(testEngine(t), ceiling, ws, ws, tool, tc.spelled)
					if strings.HasSuffix(tc.suffix, "/.git/hooks/pre-commit") {
						wantNeverDeny(t, d)
						continue
					}
					wantAsk(t, d)
				}
			}
		})
	}
	// The files a trim or a backslash rewrite would have chosen stay eligible.
	for _, p := range []string{
		filepath.Join(ws, "q", "r"),
		filepath.Join(ws, "foo"),
		filepath.Join(ws, "inn3"),
		filepath.Join(ws, "bar"),
		filepath.Join(ws, "baz"),
		filepath.Join(ws, "hd", "pre-commit"),
		filepath.Join(ws, "plain.txt"),
	} {
		if !strings.HasSuffix(p, "plain.txt") {
			if _, err := os.Stat(p); err != nil {
				t.Fatal(err)
			}
		}
		wantCeilingAllow(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", p))
	}
}

func TestCeilingUnrepresentablePath(t *testing.T) {
	_, err := resolvePath("/tmp/a\x00b")
	if !errors.Is(err, errPathUnrepresentable) {
		t.Fatalf("resolvePath NUL: %v", err)
	}
	_, err = resolveFrom("/tmp", "a\x00b")
	if !errors.Is(err, errPathUnrepresentable) {
		t.Fatalf("resolveFrom NUL: %v", err)
	}
	_, err = resolvePath("")
	if !errors.Is(err, errPathUnresolved) || errors.Is(err, errPathUnrepresentable) {
		t.Fatalf("empty path: %v", err)
	}
	_, err = resolvePath("rel")
	if !errors.Is(err, errPathUnresolved) || errors.Is(err, errPathUnrepresentable) {
		t.Fatalf("relative path: %v", err)
	}
}

func TestCeilingHardlinkRefuses(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()
	cfg := filepath.Join(ws, ".git", "config")
	hook := filepath.Join(ws, ".git", "hooks", "pre-commit")
	mustWrite(t, cfg, "[core]\n\trepositoryformatversion = 0\n")
	mustWrite(t, hook, "#!/bin/sh\n")
	secret := filepath.Join(outside, "secret.txt")
	mustWrite(t, secret, "secret\n")
	notes := filepath.Join(ws, "notes.txt")
	runHook := filepath.Join(ws, "run-hook")
	copyPath := filepath.Join(ws, "copy.txt")
	if err := os.Link(cfg, notes); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(hook, runHook); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(secret, copyPath); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(ws, "plain.txt")
	mustWrite(t, plain, "plain\n")
	for _, ceiling := range []Level{LevelMedium, LevelCritical} {
		for _, tool := range []string{"Write", "Edit"} {
			wantAsk(t, evalWrite(testEngine(t), ceiling, ws, ws, tool, notes))
			wantAsk(t, evalWrite(testEngine(t), ceiling, ws, ws, tool, runHook))
			wantAsk(t, evalWrite(testEngine(t), ceiling, ws, ws, tool, copyPath))
			wantAsk(t, evalWrite(testEngine(t), ceiling, ws, ws, tool, "notes.txt"))
			wantAsk(t, evalWrite(testEngine(t), ceiling, ws, ws, tool, "copy.txt"))
		}
	}
	wantCeilingAllow(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", plain))
	wantCeilingAllow(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", filepath.Join(ws, "brand-new.txt")))
}

func TestCeilingManagedGitEnvPlace(t *testing.T) {
	ws, home, userHome := cleanRepo(t)
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	prime := func(env []string) *Engine {
		t.Helper()
		e := testEngine(t)
		e.SetBotContext(ceilingBot, ws, nil)
		e.SetBotRuntime(ceilingBot, home, userHome, env)
		e.SnapshotBot(ceilingBot)
		return e
	}
	wantCeilingAllow(t, evalShell(prime(nil), LevelLow, ws, ws, "git status"))
	for _, ceiling := range []Level{LevelLow, LevelCritical} {
		wantAsk(t, evalShell(prime([]string{"GIT_DIR=" + filepath.Join(t.TempDir(), "missing-git")}), ceiling, ws, ws, "git status"))
		wantAsk(t, evalShell(prime([]string{"GIT_WORK_TREE=" + outside}), ceiling, ws, ws, "git status"))
	}
	wantAsk(t, evalShell(prime([]string{"GIT_DIR=missing-dir"}), LevelLow, ws, ws, "git status"))
	wantAsk(t, evalShell(prime([]string{"GIT_DIR=" + filepath.Join(ws, ".git", "config")}), LevelLow, ws, ws, "git status"))
	wantAsk(t, evalShell(prime([]string{"GIT_WORK_TREE=sub"}), LevelLow, ws, ws, "git status"))
	wantAsk(t, evalShell(prime([]string{
		"GIT_DIR=" + filepath.Join(ws, ".git"),
		"GIT_WORK_TREE=" + ws,
	}), LevelLow, ws, ws, "git status"))
	wantAsk(t, evalShell(prime([]string{"GIT_WORK_TREE=."}), LevelLow, ws, ws, "git status"))
	wantAsk(t, evalShell(prime([]string{"GIT_DIR="}), LevelLow, ws, ws, "git status"))
	wantCeilingAllow(t, evalShell(prime([]string{"GIT_AUTHOR_NAME=hooksPath"}), LevelLow, ws, ws, "git status"))
}

func TestCeilingQuotedExtFetchAsks(t *testing.T) {
	ws := t.TempDir()
	mustWrite(t, filepath.Join(ws, ".git", "config"), "[core]\n\trepositoryformatversion = 0\n")
	cmds := []string{
		`git fetch 'ext::touch /tmp/x'`,
		`git fetch "ext::sh -c id"`,
		`git ls-remote 'ext::touch /tmp/x'`,
		`git ls-remote "EXT::id"`,
		"git fetch ext::touch /tmp/x",
		"git ls-remote ext::id",
	}
	for _, cmd := range cmds {
		for _, ceiling := range []Level{LevelMedium, LevelCritical} {
			wantAsk(t, evalShell(testEngine(t), ceiling, ws, ws, cmd))
		}
	}
	wantAsk(t, evalShell(testEngine(t), LevelMedium, ws, ws, "git fetch origin"))
	wantAsk(t, evalShell(testEngine(t), LevelMedium, ws, ws, "git ls-remote origin"))
	wantCeilingAllow(t, evalShell(testEngine(t), LevelMedium, ws, ws, "git status"))
}

func TestCeilingGitApplyKeepsLinkBytes(t *testing.T) {
	requireGit(t)
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, ws, "init", "-q")
	mustWrite(t, filepath.Join(ws, ".git", "hooks", "pre-commit"), "#!/bin/sh\n")
	mustWrite(t, filepath.Join(ws, ".claude", "settings.json"), "{}\n")
	mustWrite(t, filepath.Join(ws, ".grok", "settings.json"), "{}\n")
	mustWrite(t, filepath.Join(ws, "q", "r"), "decoy\n")
	mustWrite(t, filepath.Join(ws, "foo"), "decoy\n")
	mustWrite(t, filepath.Join(ws, "inn3"), "decoy\n")
	mustWrite(t, filepath.Join(ws, "bar"), "decoy\n")
	mustWrite(t, filepath.Join(ws, "baz"), "decoy\n")
	mustWrite(t, filepath.Join(ws, "hd", "pre-commit"), "decoy\n")
	mustWrite(t, filepath.Join(ws, "keep.txt"), "keep\n")
	runGit(t, ws, "add", "-A")
	runGit(t, ws, "commit", "-q", "-m", "init")
	gen := filepath.Join(root, "gen")
	runGit(t, root, "clone", "-q", ws, gen)
	links := []struct{ name, target string }{
		{"inn", `q\r`},
		{`q\r`, ".git/config"},
		{"inn2", "foo "},
		{"foo ", ".git/config"},
		{"inn3 ", ".git/config"},
		{"inn4", "\tbar"},
		{"\tbar", ".claude/settings.json"},
		{"inn5", " baz"},
		{" baz", ".grok/settings.json"},
		{"hk", `hd\pre-commit`},
		{`hd\pre-commit`, ".git/hooks/pre-commit"},
	}
	for _, l := range links {
		mustSymlink(t, l.target, filepath.Join(gen, l.name))
	}
	runGit(t, gen, "add", "-A")
	patch := runGitOut(t, gen, "diff", "--cached", "--binary")
	if !bytesContainsLink(patch, "foo ") || !bytesContainsLink(patch, `q\r`) {
		t.Fatalf("patch dropped a link target:\n%s", patch)
	}
	mustWrite(t, filepath.Join(ws, "p.patch"), string(patch))
	wantAsk(t, evalShell(testEngine(t), LevelMedium, ws, ws, "git apply p.patch"))
	runGit(t, ws, "apply", "p.patch")
	for _, l := range links {
		got, err := os.Readlink(filepath.Join(ws, l.name))
		if err != nil {
			t.Fatalf("readlink %q: %v", l.name, err)
		}
		if got != l.target {
			t.Fatalf("applied %q target %q want %q", l.name, got, l.target)
		}
	}
	assertFaithful(t, ws, filepath.Join(ws, "inn2"), "/.git/config")
	assertFaithful(t, ws, filepath.Join(ws, "inn"), "/.git/config")
	assertFaithful(t, ws, filepath.Join(ws, "inn3 "), "/.git/config")
	assertFaithful(t, ws, filepath.Join(ws, "hk"), "/.git/hooks/pre-commit")
	assertFaithful(t, ws, filepath.Join(ws, "inn4"), "/.claude/settings.json")
	assertFaithful(t, ws, filepath.Join(ws, "inn5"), "/.grok/settings.json")
	wantAsk(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", filepath.Join(ws, "inn2")))
	wantAsk(t, evalWrite(testEngine(t), LevelCritical, ws, ws, "Edit", "inn3 "))
}

func bytesContainsLink(patch []byte, target string) bool {
	return strings.Contains(string(patch), target)
}
