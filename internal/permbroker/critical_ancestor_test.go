package permbroker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGolden_CriticalAncestors(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	root := t.TempDir()
	parent := filepath.Join(root, "tree")
	critDir := filepath.Join(parent, "nested")
	if err := os.MkdirAll(critDir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.SetCriticalPaths([]string{critDir})
	ws := filepath.Join(root, "workspace", "bots", "bot")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	if rel, err := filepath.Rel(ws, critDir); err != nil || !strings.HasPrefix(rel, "..") {
		t.Fatalf("workspace %s is an ancestor of %s (%s)", ws, critDir, rel)
	}

	mustCrit := func(cwd, cmd string) {
		t.Helper()
		d := e.Evaluate(ctx, bashReq("bot", "sess", "task", cwd, cmd))
		if d.Level != LevelCritical || d.Eligible || d.Verdict == VerdictAllow {
			t.Fatalf("%s in %s %+v", cmd, cwd, d)
		}
	}
	mustNot := func(cwd, cmd string) {
		t.Helper()
		d := e.Evaluate(ctx, bashReq("bot", "sess", "task", cwd, cmd))
		if d.Level == LevelCritical {
			t.Fatalf("%s in %s became critical %+v", cmd, cwd, d)
		}
	}

	for _, cmd := range []string{
		"rm -rf " + parent,
		"mv " + parent + " " + parent + ".bak",
		"chmod -R 777 " + parent,
		"chown 1:1 " + parent,
		"grep -r token " + parent,
		"tar czf " + filepath.Join(root, "o.tgz") + " " + parent,
		"ls " + parent,
		"cp -r " + parent + " " + filepath.Join(root, "out"),
		"find " + parent + " -name x",
		"rsync -a " + parent + " " + filepath.Join(root, "out2"),
		"du " + parent,
		"ls /",
	} {
		mustCrit("/work", cmd)
	}
	for _, cmd := range []string{
		"grep -r token .",
		"grep -r token ./",
		"ls",
		"ls -la",
		"find",
		"find -name x",
		"du",
		"rm -rf .",
		"tar czf o.tgz .",
	} {
		mustCrit(parent, cmd)
	}
	mustCrit(critDir, "ls")
	for _, cmd := range []string{"echo hi", "git status", "ls", "grep -r token .", "find", "du"} {
		mustNot(ws, cmd)
	}
	mustNot(parent, "echo hi")
	mustNot("/work", "touch "+filepath.Join(parent, "b"))
}

func TestGolden_NonLiteralNearCritical(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	data := t.TempDir()
	cli := filepath.Join(data, "cli")
	botDir := filepath.Join(cli, "bot")
	if err := os.MkdirAll(filepath.Join(data, "permbroker"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(botDir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.SetCriticalPaths([]string{botDir, filepath.Join(data, "permbroker")})
	cases := []string{
		"touch " + cli + "/b*/newfile",
		"touch " + cli + "/?ot/newfile",
		"touch " + cli + "/{bot,zz}/newfile",
		"touch " + cli + "/b\\ot/newfile",
		"P=perm; cat " + data + "/${P}broker/rules.json",
		"cd " + data + " && cat $(ls | grep perm)/rules.json",
	}
	for _, cmd := range cases {
		d := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", cmd))
		if d.Level != LevelCritical || d.Eligible || d.Verdict == VerdictAllow {
			t.Fatalf("%s %+v", cmd, d)
		}
	}
	far := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", "touch "+filepath.Join(data, "zzz*")))
	if far.Level == LevelCritical {
		t.Fatalf("unrelated glob %+v", far)
	}
	quoted := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", "touch "+cli+"/'b'ot/newfile"))
	if quoted.Level != LevelCritical {
		t.Fatalf("quoted literal %+v", quoted)
	}
}

func TestGolden_HomeExpansionCriticalDir(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	parent := t.TempDir()
	cli := filepath.Join(parent, "bot")
	if err := os.MkdirAll(cli, 0o755); err != nil {
		t.Fatal(err)
	}
	e.SetCriticalPaths([]string{cli})
	t.Setenv("HOME", parent)
	for _, cmd := range []string{"touch ~/bot/newfile", "touch $HOME/bot/newfile"} {
		d := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", cmd))
		if d.Level != LevelCritical || d.Eligible {
			t.Fatalf("%s %+v", cmd, d)
		}
	}
}

func TestGolden_BareCdUsesHome(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	home := t.TempDir()
	botDir := filepath.Join(home, "bot")
	if err := os.MkdirAll(botDir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.SetCriticalPaths([]string{botDir})
	t.Setenv("HOME", home)
	for _, cmd := range []string{"cd && touch bot/newfile", "cd ~ && touch bot/newfile", "cd -P && touch bot/newfile"} {
		d := e.Evaluate(ctx, bashReq("bot", "sess", "task", "/work", cmd))
		if d.Level != LevelCritical {
			t.Fatalf("%s %+v", cmd, d)
		}
	}
}

func TestGolden_CdTrackingJoinsCritical(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "a", "crit", "marker")
	if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.SetCriticalPaths([]string{marker})
	start := filepath.Join(root, "start")
	if err := os.MkdirAll(start, 0o755); err != nil {
		t.Fatal(err)
	}
	joined := "cd " + filepath.Join(root, "a", "b") + " && touch ../crit/marker"
	d := e.Evaluate(ctx, bashReq("bot", "sess", "task", start, joined))
	if d.Level != LevelCritical {
		t.Fatalf("joined %+v", d)
	}
	seq := "cd " + filepath.Join(root, "a", "b") + "; touch ../crit/marker"
	if s := e.Evaluate(ctx, bashReq("bot", "sess", "task", start, seq)); s.Level != LevelCritical {
		t.Fatalf("sequence %+v", s)
	}
	alone := e.Evaluate(ctx, bashReq("bot", "sess", "task", start, "touch ../crit/marker"))
	if alone.Level == LevelCritical {
		t.Fatalf("argument alone %+v", alone)
	}
}

func TestGolden_RelativeJoinCritical(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	if err := os.WriteFile(marker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.SetCriticalPaths([]string{marker})
	d := e.Evaluate(ctx, bashReq("bot", "sess", "task", dir, "touch marker"))
	if d.Level != LevelCritical || d.Eligible {
		t.Fatalf("relative %+v", d)
	}
}

func TestGolden_EngineApprovalTTLClamp(t *testing.T) {
	e := testEngine(t)
	e.SetApprovalTTL(48 * time.Hour)
	if e.approvalTTL() != MaxApprovalTTL {
		t.Fatalf("ttl %s", e.approvalTTL())
	}
	e.SetApprovalTTL(0)
	if e.approvalTTL() != DefaultApprovalTTL {
		t.Fatalf("zero %s", e.approvalTTL())
	}
}

func TestGolden_CorruptRulesNamesPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(dir, nil, nil)
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "permission broker rules file") {
		t.Fatalf("err %v", err)
	}
	missing := t.TempDir()
	if err := os.Chmod(missing, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(missing, nil, nil); err != nil {
		t.Fatalf("missing file %v", err)
	}
}
