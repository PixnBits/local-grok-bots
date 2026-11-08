package permbroker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCeilingUnquotedBackslashAsks(t *testing.T) {
	ws := t.TempDir()
	cmds := []string{
		`git clone . .clau\de`,
		`git clone . .gr\ok`,
		`git clone . .vs\code`,
		`git clone . .devcontaine\r`,
		`git fetch ex\t::id`,
		`git ls-remote ex\t::id`,
		`git pull ex\t::id`,
	}
	for _, cmd := range cmds {
		for _, ceiling := range []Level{LevelLow, LevelMedium, LevelHigh, LevelCritical} {
			d := evalShell(testEngine(t), ceiling, ws, ws, cmd)
			wantAsk(t, d)
			if d.Actor == neverAllowActor {
				t.Fatalf("hard deny %+v", d)
			}
		}
	}
	wantAsk(t, evalShell(testEngine(t), LevelMedium, ws, ws, `git clone . ".clau\de"`))
	wantAsk(t, evalShell(testEngine(t), LevelMedium, ws, ws, "git clone . sub"))
	wantCeilingAllow(t, evalShell(testEngine(t), LevelMedium, ws, ws, `git add ".clau\de"`))
	wantCeilingAllow(t, evalShell(testEngine(t), LevelLow, ws, ws, "git status"))
}

func TestCeilingCloneInitDestAsks(t *testing.T) {
	ws := t.TempDir()
	mustWrite(t, filepath.Join(ws, ".git", "config"), "[core]\n\trepositoryformatversion = 0\n")
	asks := []string{
		"git clone . .vscode",
		"git clone . .idea",
		"git clone . .husky",
		"git clone . .lgb",
		"git clone . .claude",
		"git clone . .grok",
		"git clone . .devcontainer",
		"git init .vscode",
		"git init .idea",
		"git init .husky",
		"git init .lgb",
		"git clone --depth 1 . .vscode",
		"mkdir -p .vscode",
		"install -d .idea",
		"cp -r . .husky",
	}
	for _, cmd := range asks {
		for _, ceiling := range []Level{LevelMedium, LevelCritical} {
			t.Run(cmd+"/"+string(ceiling), func(t *testing.T) {
				wantAsk(t, evalShell(testEngine(t), ceiling, ws, ws, cmd))
			})
		}
	}
	wantAsk(t, evalShell(testEngine(t), LevelMedium, ws, ws, "git clone . sub"))
	wantAsk(t, evalShell(testEngine(t), LevelMedium, ws, ws, "git init"))
	wantCeilingAllow(t, evalShell(testEngine(t), LevelLow, ws, ws, "git status"))
	if err := os.MkdirAll(filepath.Join(ws, ".husky"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, ".lgb", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(ws, ".husky", "pre-commit"), "#!/bin/sh\n")
	mustWrite(t, filepath.Join(ws, ".lgb", "bin", "tool"), "#!/bin/sh\n")
	wantAsk(t, evalShell(testEngine(t), LevelMedium, ws, ws, "git add .husky/pre-commit"))
	wantAsk(t, evalShell(testEngine(t), LevelMedium, ws, ws, "git add .lgb/bin/tool"))

	if err := os.MkdirAll(filepath.Join(ws, ".vscode"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, ".vscode", filepath.Join(ws, "out"))
	wantAsk(t, evalShell(testEngine(t), LevelMedium, ws, ws, "git clone . out"))
	wantAsk(t, evalShell(testEngine(t), LevelCritical, ws, ws, "git init out"))

	mustSymlink(t, ".husky", filepath.Join(ws, "alias"))
	wantAsk(t, evalShell(testEngine(t), LevelMedium, ws, ws, "git add alias/pre-commit"))
}

func TestCeilingExtClonePullAsks(t *testing.T) {
	ws := t.TempDir()
	mustWrite(t, filepath.Join(ws, ".git", "config"), "[core]\n\trepositoryformatversion = 0\n")
	cmds := []string{
		"git clone ext::id dest",
		`git clone 'ext::touch /tmp/x' dest`,
		`git clone "EXT::id" dest`,
		"git pull ext::id",
		`git pull 'ext::touch /tmp/x'`,
		`git pull "EXT::id"`,
	}
	for _, cmd := range cmds {
		for _, ceiling := range []Level{LevelMedium, LevelCritical} {
			wantAsk(t, evalShell(testEngine(t), ceiling, ws, ws, cmd))
		}
	}
	wantAsk(t, evalShell(testEngine(t), LevelMedium, ws, ws, "git clone . sub"))
	wantAsk(t, evalShell(testEngine(t), LevelMedium, ws, ws, "git pull origin"))
	wantCeilingAllow(t, evalShell(testEngine(t), LevelLow, ws, ws, "git status"))
}

func TestCeilingGitLocationEnvAsks(t *testing.T) {
	ws, home, userHome := cleanRepo(t)
	prime := func(env []string) *Engine {
		t.Helper()
		e := testEngine(t)
		e.SetBotContext(ceilingBot, ws, nil)
		e.SetBotRuntime(ceilingBot, home, userHome, env)
		e.SnapshotBot(ceilingBot)
		return e
	}
	cases := [][]string{
		{"GIT_DIR=" + filepath.Join(ws, ".git")},
		{"GIT_CONFIG_PARAMETERS=a=b"},
		{"GIT_EXEC_PATH=/tmp/git"},
		{"GIT_COMMON_DIR=" + filepath.Join(ws, ".git")},
		{"GIT_SSH=/tmp/ssh"},
		{"GIT_CONFIG_COUNT=0"},
		{"GIT_DIR="},
	}
	for _, env := range cases {
		for _, ceiling := range []Level{LevelLow, LevelCritical} {
			e := prime(env)
			d := evalShell(e, ceiling, ws, ws, "git status")
			wantAsk(t, d)
			row := lastPermAudit(t, e)
			if !strings.Contains(row.Classifier, env[0][:strings.Index(env[0], "=")]) {
				t.Fatalf("classifier %q env %q", row.Classifier, env[0])
			}
		}
	}
	e := prime(nil)
	d := evalShell(e, LevelLow, ws, ws, "GIT_DIR=/tmp/elsewhere git status")
	wantAsk(t, d)
	if row := lastPermAudit(t, e); !strings.Contains(row.Classifier, "GIT_DIR") {
		t.Fatalf("classifier %q", row.Classifier)
	}
	e = prime(nil)
	d = evalShell(e, LevelCritical, ws, ws, "GIT_CONFIG_PARAMETERS=a=b git status")
	wantAsk(t, d)
	if row := lastPermAudit(t, e); !strings.Contains(row.Classifier, "GIT_CONFIG_PARAMETERS") {
		t.Fatalf("classifier %q", row.Classifier)
	}
	e = prime(nil)
	d = evalShell(e, LevelLow, ws, ws, "GIT_EXEC_PATH=/tmp/git git status")
	wantAsk(t, d)
	if row := lastPermAudit(t, e); !strings.Contains(row.Classifier, "GIT_EXEC_PATH") {
		t.Fatalf("classifier %q", row.Classifier)
	}
	wantCeilingAllow(t, evalShell(prime([]string{"GIT_AUTHOR_NAME=hooksPath"}), LevelLow, ws, ws, "git status"))
	wantCeilingAllow(t, evalShell(prime(nil), LevelLow, ws, ws, "git status"))
}

func TestCeilingCredentialNeverDeny(t *testing.T) {
	ws := t.TempDir()
	key := filepath.Join(ws, "id_ed25519")
	mustWrite(t, key, "k\n")
	readme := filepath.Join(ws, "README")
	mustWrite(t, readme, "hi\n")
	cmds := []struct {
		cmd, why string
		never    bool
	}{
		{"gh auth token", neverAllowCredential, true},
		{"git credential fill", neverAllowCredential, true},
		{"head " + key, neverAllowCredential, true},
		{"cat " + key, neverAllowCredential, true},
		{"head README", "", false},
	}
	for _, ceiling := range []Level{LevelLow, LevelMedium, LevelHigh, LevelCritical} {
		for _, tc := range cmds {
			e := testEngine(t)
			d := evalShell(e, ceiling, ws, ws, tc.cmd)
			if !tc.never {
				wantCeilingAllow(t, d)
				continue
			}
			wantNeverDeny(t, d)
			if !strings.Contains(d.Reason, tc.why) {
				t.Fatalf("%s %+v", tc.cmd, d)
			}
			row := lastPermAudit(t, e)
			if row.Severity != neverAllowSeverity || row.Source != neverAllowActor || row.Actor != neverAllowActor {
				t.Fatalf("audit %+v", row)
			}
			if row.PendingID != "" || row.Decision != VerdictDeny || !strings.Contains(row.Classifier, tc.why) {
				t.Fatalf("audit %+v", row)
			}
		}
	}
	raw := readReq(ceilingBot, ws, ws, key)
	e := testEngine(t)
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelCritical})
	d := e.Evaluate(context.Background(), raw)
	wantNeverDeny(t, d)
	if !strings.Contains(d.Reason, neverAllowCredential) {
		t.Fatalf("%+v", d)
	}

	link := filepath.Join(ws, "link-key")
	mustSymlink(t, key, link)
	wantNeverDeny(t, evalShell(testEngine(t), LevelLow, ws, ws, "head "+link))

	plain := testEngine(t)
	asked := plain.Evaluate(context.Background(), bashReq(ceilingBot, "sess", "task", ws, "gh auth token"))
	wantAsk(t, asked)
	if asked.Actor == neverAllowActor || asked.PendingID == "" {
		t.Fatalf("no ceiling %+v", asked)
	}
	off := testEngine(t)
	off.SetAllowCeilings("off", map[string]Level{ceilingBot: LevelCritical})
	asked = off.Evaluate(context.Background(), bashReq(ceilingBot, "sess", "task", ws, "gh auth token"))
	wantAsk(t, asked)
	if asked.Actor == neverAllowActor {
		t.Fatalf("broker off %+v", asked)
	}
}

func TestCeilingHookPathNeverDeny(t *testing.T) {
	ws := t.TempDir()
	hook := filepath.Join(ws, ".git", "hooks", "pre-commit")
	mustWrite(t, filepath.Join(ws, ".git", "config"), "[core]\n")
	mustWrite(t, hook, "#!/bin/sh\n")
	cmds := []string{
		"git config core.hooksPath ./h",
		"git config core.hooksPath",
		"git -c core.hooksPath=/tmp/h status",
		"git add .git/hooks/pre-commit",
		"git mv a.txt .git/hooks/pre-commit",
		"git checkout -- .git/hooks/pre-commit",
		"git add .GIT/hooks/pre-commit",
	}
	for _, cmd := range cmds {
		for _, ceiling := range []Level{LevelLow, LevelMedium, LevelCritical} {
			e := testEngine(t)
			d := evalShell(e, ceiling, ws, ws, cmd)
			wantNeverDeny(t, d)
			if !strings.Contains(d.Reason, neverAllowHook) {
				t.Fatalf("%s %+v", cmd, d)
			}
			row := lastPermAudit(t, e)
			if row.Severity != "critical" || row.Actor != neverAllowActor || row.Source != neverAllowActor {
				t.Fatalf("audit %+v", row)
			}
		}
	}
	wantAsk(t, evalShell(testEngine(t), LevelCritical, ws, ws, "git diff .git/hooks/pre-commit"))
	wantAsk(t, evalShell(testEngine(t), LevelCritical, ws, ws, "git add evil/hooks/pre-commit"))
	wantNeverDeny(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", hook))
	wantNeverDeny(t, evalWrite(testEngine(t), LevelCritical, ws, ws, "Edit", hook))

	via := filepath.Join(ws, "hook-link")
	mustSymlink(t, hook, via)
	wantNeverDeny(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", via))

	plain := testEngine(t)
	asked := plain.Evaluate(context.Background(), bashReq(ceilingBot, "sess", "task", ws, "git config core.hooksPath ./h"))
	wantAsk(t, asked)
	if asked.Actor == neverAllowActor {
		t.Fatalf("no ceiling %+v", asked)
	}
}

func TestNeverAllowBeatsAskRule(t *testing.T) {
	e := testEngine(t)
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelCritical})
	e.mu.Lock()
	e.rules.Rules = append(e.rules.Rules, Rule{
		ID: "pat", Effect: EffectAsk, Kind: "pattern", Pattern: "gh * token",
		Tool: ToolShell, Scope: ScopeBot, BotID: ceilingBot,
	})
	e.mu.Unlock()
	d := e.Evaluate(context.Background(), bashReq(ceilingBot, "sess", "task", "/work", "gh auth token"))
	wantNeverDeny(t, d)
	if d.PendingID != "" || !strings.Contains(d.Reason, neverAllowCredential) {
		t.Fatalf("%+v", d)
	}
}

func TestCeilingSymlinkToHardlink(t *testing.T) {
	ws := t.TempDir()
	inside := filepath.Join(ws, "inside.txt")
	mustWrite(t, inside, "a\n")
	hard := filepath.Join(ws, "hard.txt")
	if err := os.Link(inside, hard); err != nil {
		t.Fatal(err)
	}
	via := filepath.Join(ws, "via.txt")
	mustSymlink(t, hard, via)
	for _, ceiling := range []Level{LevelMedium, LevelCritical} {
		for _, tool := range []string{"Write", "Edit"} {
			wantAsk(t, evalWrite(testEngine(t), ceiling, ws, ws, tool, via))
			wantAsk(t, evalWrite(testEngine(t), ceiling, ws, ws, tool, "via.txt"))
		}
	}
	plain := filepath.Join(ws, "plain.txt")
	mustWrite(t, plain, "p\n")
	wantCeilingAllow(t, evalWrite(testEngine(t), LevelMedium, ws, ws, "Write", plain))
}

func lastPermAudit(t *testing.T, e *Engine) AuditRow {
	t.Helper()
	rows := decodeAudit(t, readPermAudit(t, e.dir))
	if len(rows) == 0 {
		t.Fatal("no audit row")
	}
	return rows[len(rows)-1]
}
