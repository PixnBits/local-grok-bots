package permbroker

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGolden_GitCodeExecSurface(t *testing.T) {
	cases := []struct {
		name  string
		risky bool
		plant func(t *testing.T, ws, home, userHome string)
	}{
		{name: "exec-hook", risky: true, plant: func(t *testing.T, ws, _, _ string) {
			hook := filepath.Join(ws, ".git", "hooks", "pre-commit")
			mustWrite(t, hook, "#!/bin/sh\nexit 0\n")
			if err := os.Chmod(hook, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink-hook", risky: true, plant: func(t *testing.T, ws, _, _ string) {
			target := filepath.Join(ws, "hook-target")
			mustWrite(t, target, "#!/bin/sh\nexit 0\n")
			link := filepath.Join(ws, ".git", "hooks", "post-checkout")
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "sample-hook", plant: func(t *testing.T, ws, _, _ string) {
			hook := filepath.Join(ws, ".git", "hooks", "pre-commit.sample")
			mustWrite(t, hook, "#!/bin/sh\nexit 0\n")
			if err := os.Chmod(hook, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "info-attr-diff", risky: true, plant: func(t *testing.T, ws, _, _ string) {
			mustWrite(t, filepath.Join(ws, ".git", "info", "attributes"), "* diff=x\n")
		}},
		{name: "gitattributes-merge", risky: true, plant: func(t *testing.T, ws, _, _ string) {
			mustWrite(t, filepath.Join(ws, ".gitattributes"), "* merge=x\n")
		}},
		{name: "gitattributes-filter", risky: true, plant: func(t *testing.T, ws, _, _ string) {
			mustWrite(t, filepath.Join(ws, ".gitattributes"), "* filter=x\n")
		}},
		{name: "plain-attr", plant: func(t *testing.T, ws, _, _ string) {
			mustWrite(t, filepath.Join(ws, ".gitattributes"), "* diff -diff binary\n")
		}},
		{name: "home-textconv", risky: true, plant: func(t *testing.T, _, home, _ string) {
			mustWrite(t, filepath.Join(home, ".gitconfig"), "[diff \"x\"]\n\ttextconv = cat\n")
		}},
		{name: "attributes-file", risky: true, plant: func(t *testing.T, _, home, _ string) {
			mustWrite(t, filepath.Join(home, "drivers"), "* diff=x\n")
			mustWrite(t, filepath.Join(home, ".gitconfig"), "[core]\n\tattributesFile = ~/drivers\n")
		}},
		{name: "xdg-attributes", risky: true, plant: func(t *testing.T, _, home, _ string) {
			mustWrite(t, filepath.Join(home, ".config", "git", "attributes"), "* diff=x\n")
		}},
		{name: "alias", risky: true, plant: func(t *testing.T, _, home, _ string) {
			mustWrite(t, filepath.Join(home, ".gitconfig"), "[alias]\n\tst = status\n")
		}},
		{name: "askpass", risky: true, plant: func(t *testing.T, _, home, _ string) {
			mustWrite(t, filepath.Join(home, ".gitconfig"), "[core]\n\taskPass = /bin/true\n")
		}},
		{name: "gpg-program", risky: true, plant: func(t *testing.T, _, home, _ string) {
			mustWrite(t, filepath.Join(home, ".gitconfig"), "[gpg]\n\tprogram = gpg\n")
		}},
		{name: "sequence-editor", risky: true, plant: func(t *testing.T, _, home, _ string) {
			mustWrite(t, filepath.Join(home, ".gitconfig"), "[sequence]\n\teditor = true\n")
		}},
		{name: "protocol-ext", risky: true, plant: func(t *testing.T, ws, _, _ string) {
			writeGit(t, ws, "[protocol \"ext\"]\n\tallow = always\n")
		}},
		{name: "protocol-always", risky: true, plant: func(t *testing.T, ws, _, _ string) {
			writeGit(t, ws, "[protocol]\n\tallow = always\n")
		}},
		{name: "protocol-never", plant: func(t *testing.T, ws, _, _ string) {
			writeGit(t, ws, "[protocol \"ext\"]\n\tallow = never\n")
		}},
		{name: "url-ext", risky: true, plant: func(t *testing.T, ws, _, _ string) {
			writeGit(t, ws, "[url \"https://example.invalid\"]\n\tinsteadOf = ext::remote\n")
		}},
		{name: "gitdir-hook", risky: true, plant: func(t *testing.T, ws, _, _ string) {
			real := filepath.Join(ws, "real-git")
			hook := filepath.Join(real, "hooks", "pre-commit")
			mustWrite(t, hook, "#!/bin/sh\nexit 0\n")
			if err := os.Chmod(hook, 0o755); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(real, "config"), "[core]\n\trepositoryformatversion = 0\n")
			if err := os.RemoveAll(filepath.Join(ws, ".git")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(ws, ".git"), []byte("gitdir: "+real+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := testEngine(t)
			ws, home, userHome := cleanRepo(t)
			if !tc.risky {
				tc.plant(t, ws, home, userHome)
			}
			e.SetBotContext("bot", ws, nil)
			e.SetBotRuntime("bot", home, userHome, nil)
			e.SnapshotBot("bot")
			if _, err := e.SaveRule(Rule{Effect: EffectAllow, Argv: []string{"git", "status"}, Tool: ToolShell, Scope: ScopeBot, BotID: "bot"}); err != nil {
				t.Fatal(err)
			}
			if tc.risky {
				assertGitAllow(t, e, ws)
				tc.plant(t, ws, home, userHome)
				assertGitAsk(t, e, ws)
				if err := e.RebaselineBot("bot"); err != nil {
					t.Fatal(err)
				}
				assertGitAsk(t, e, ws)
				return
			}
			assertGitAllow(t, e, ws)
		})
	}
}

func TestGolden_GitBaselineNoTurnRebaseline(t *testing.T) {
	e := testEngine(t)
	ws, home, userHome := cleanRepo(t)
	cfg := filepath.Join(ws, ".git", "config")
	original, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	turn := func(eng *Engine) {
		t.Helper()
		eng.SetBotContext("bot", ws, nil)
		eng.SetBotRuntime("bot", home, userHome, nil)
		eng.SnapshotBot("bot")
		eng.NoteTurn("bot", "sess", "run", "task")
	}
	turn(e)
	if _, err := e.SaveRule(Rule{Effect: EffectAllow, Argv: []string{"git", "status"}, Tool: ToolShell, Scope: ScopeBot, BotID: "bot"}); err != nil {
		t.Fatal(err)
	}
	assertGitAllow(t, e, ws)
	basePath := filepath.Join(e.dir, gitBaselineName)
	st, err := os.Stat(basePath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("baseline mode %v %v", st, err)
	}
	dst, err := os.Stat(e.dir)
	if err != nil || dst.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v %v", dst, err)
	}
	stored, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, cfg, string(original)+"\tlogallrefupdates = true\n")
	assertGitAsk(t, e, ws)
	turn(e)
	assertGitAsk(t, e, ws)
	afterTurn, err := os.ReadFile(basePath)
	if err != nil || !bytes.Equal(stored, afterTurn) {
		t.Fatal("turn rewrote the baseline")
	}
	dir := e.dir
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e2, err := Open(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e2.resolver = fakeBinary
	t.Cleanup(func() { _ = e2.Close() })
	turn(e2)
	assertGitAsk(t, e2, ws)
	reloaded, err := os.ReadFile(basePath)
	if err != nil || !bytes.Equal(stored, reloaded) {
		t.Fatal("reload rewrote the baseline")
	}
	if err := os.WriteFile(cfg, original, 0o644); err != nil {
		t.Fatal(err)
	}
	assertGitAllow(t, e2, ws)
	if err := e2.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(basePath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	e3, err := Open(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e3.resolver = fakeBinary
	t.Cleanup(func() { _ = e3.Close() })
	if !strings.Contains(logs.String(), basePath) {
		t.Fatalf("corrupt baseline was not logged: %s", logs.String())
	}
	turn(e3)
	assertGitAsk(t, e3, ws)
}

func TestGolden_LegacyDenyCrossesSlash(t *testing.T) {
	e := testEngine(t)
	if err := e.MigrateLegacy([]LegacyRule{
		{BotID: "bot", Effect: EffectDeny, Text: "Bash(curl *)"},
		{BotID: "bot", Effect: EffectDeny, Text: "Bash(rm *)"},
		{BotID: "bot", Effect: EffectAsk, Text: "Bash(wget *)"},
	}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, cmd := range []string{
		"curl http://192.0.2.10/",
		"curl ./x",
		"curl -o /tmp/z http://192.0.2.10/a/b",
		"rm -rf /tmp/zz",
	} {
		d := e.Evaluate(ctx, shellReq("Bash", cmd))
		if d.Verdict != VerdictDeny || d.PendingID != "" || !strings.Contains(d.Reason, "denied by rule") {
			t.Fatalf("%s %+v", cmd, d)
		}
	}
	other := e.Evaluate(ctx, shellReq("Bash", "echo hi"))
	if other.Verdict == VerdictAllow || other.PendingID == "" {
		t.Fatalf("non-match %+v", other)
	}
	asked := e.Evaluate(ctx, shellReq("Bash", "wget http://192.0.2.10/a"))
	if asked.Verdict == VerdictAllow || asked.PendingID == "" {
		t.Fatalf("ask %+v", asked)
	}
}

func cleanRepo(t *testing.T) (ws, home, userHome string) {
	t.Helper()
	ws = t.TempDir()
	home = t.TempDir()
	userHome = t.TempDir()
	if err := os.Mkdir(filepath.Join(ws, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(ws, ".git", "config"), "[core]\n\trepositoryformatversion = 0\n")
	return ws, home, userHome
}

func assertGitAllow(t *testing.T, e *Engine, ws string) {
	t.Helper()
	for _, tool := range []string{"Bash", "run_shell"} {
		req := shellReq(tool, "git status")
		req.Cwd = ws
		req.Workspace = ws
		if d := e.Evaluate(context.Background(), req); d.Verdict != VerdictAllow {
			t.Fatalf("%s %+v", tool, d)
		}
	}
}

func assertGitAsk(t *testing.T, e *Engine, ws string) {
	t.Helper()
	for _, tool := range []string{"Bash", "run_shell"} {
		req := shellReq(tool, "git status")
		req.Cwd = ws
		req.Workspace = ws
		d := e.Evaluate(context.Background(), req)
		if d.Verdict == VerdictAllow || d.PendingID == "" {
			t.Fatalf("%s %+v", tool, d)
		}
	}
}
