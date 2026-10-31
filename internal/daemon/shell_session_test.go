package daemon

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/permbroker"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestRunShellSessionCwdBatches(t *testing.T) {
	app := newApp(t, "", nil)
	app.editPol(func(p *policy.Policy) { p.Broker = "hook" })
	bot, err := app.st.CreateBot("Ada", "help", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	ws := app.botWorkspace(bot.ID)
	if err := os.MkdirAll(filepath.Join(ws, "s1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, "s2"), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(ws, "out")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := app.execTool(ctx, bot, "run_shell", map[string]any{"command": "cd .."}); err == nil || !strings.Contains(err.Error(), "cd stays inside the workspace") {
		t.Fatalf("cd .. err %v", err)
	}
	if _, err := app.execTool(ctx, bot, "run_shell", map[string]any{"command": "cd out"}); err == nil || !strings.Contains(err.Error(), "cd stays inside the workspace") {
		t.Fatalf("symlink cd err %v", err)
	}
	if app.shellSessionDir(bot.ID, ws) != ws {
		t.Fatalf("escape moved cwd to %s", app.shellSessionDir(bot.ID, ws))
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		if _, err2 := exec.LookPath("unshare"); err2 != nil {
			t.Skip("shell sandbox unavailable: bwrap and unshare are missing")
		}
	}
	ask(t, app, bot, "cd s1")
	approvePending(t, app, "cd", "s1")
	out, err := app.execTool(ctx, bot, "run_shell", map[string]any{"command": "cd s1"})
	if err != nil {
		t.Fatalf("cd s1 rerun %v %s", err, out)
	}
	if got := app.shellSessionDir(bot.ID, ws); got != filepath.Join(ws, "s1") {
		t.Fatalf("session cwd %s", got)
	}
	ask(t, app, bot, "echo hi")
	ask(t, app, bot, "echo hi")
	echoes := pendingArgv(app, "echo", "hi")
	if len(echoes) != 1 || echoes[0].Cwd != filepath.Join(ws, "s1") {
		t.Fatalf("shared s1 cwd %+v", echoes)
	}
	ask(t, app, bot, "cd ../s2")
	approvePending(t, app, "cd", "../s2")
	out, err = app.execTool(ctx, bot, "run_shell", map[string]any{"command": "cd ../s2"})
	if err != nil {
		t.Fatalf("cd s2 rerun %v %s", err, out)
	}
	ask(t, app, bot, "echo hi")
	echoes = pendingArgv(app, "echo", "hi")
	if len(echoes) != 2 {
		t.Fatalf("batch pair %+v", echoes)
	}
	if echoes[0].Cwd == echoes[1].Cwd {
		t.Fatalf("cwds collapsed %+v", echoes)
	}
	s1n, s2n := 0, 0
	for _, item := range echoes {
		switch item.Cwd {
		case filepath.Join(ws, "s1"):
			s1n++
		case filepath.Join(ws, "s2"):
			s2n++
		default:
			t.Fatalf("cwd %s", item.Cwd)
		}
		if strings.Join(item.Argv, " ") != "echo hi" {
			t.Fatalf("argv %v", item.Argv)
		}
	}
	if s1n != 1 || s2n != 1 {
		t.Fatalf("dirs s1=%d s2=%d", s1n, s2n)
	}
	ask(t, app, bot, "pwd")
	approvePending(t, app, "pwd")
	out, err = app.execTool(ctx, bot, "run_shell", map[string]any{"command": "pwd"})
	if err != nil {
		t.Fatalf("pwd %v %s", err, out)
	}
	if !strings.Contains(out, "/work/s2") {
		t.Fatalf("pwd did not run in the session directory:\n%s", out)
	}
}

func TestRunShellSessionCwdSymlinkSwap(t *testing.T) {
	app := newApp(t, "", nil)
	app.editPol(func(p *policy.Policy) { p.Broker = "hook" })
	bot, err := app.st.CreateBot("Ada", "help", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	ws := app.botWorkspace(bot.ID)
	s1 := filepath.Join(ws, "s1")
	if err := os.MkdirAll(s1, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		if _, err2 := exec.LookPath("unshare"); err2 != nil {
			t.Skip("shell sandbox unavailable: bwrap and unshare are missing")
		}
	}
	ctx := context.Background()
	ask(t, app, bot, "cd s1")
	approvePending(t, app, "cd", "s1")
	out, err := app.execTool(ctx, bot, "run_shell", map[string]any{"command": "cd s1"})
	if err != nil {
		t.Fatalf("cd s1 %v %s", err, out)
	}
	if got := app.shellSessionDir(bot.ID, ws); got != s1 {
		t.Fatalf("session cwd %s", got)
	}
	outside := t.TempDir()
	if err := os.RemoveAll(s1); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, s1); err != nil {
		t.Fatal(err)
	}
	out, err = app.execTool(ctx, bot, "run_shell", map[string]any{"command": "echo hi"})
	if err == nil || !strings.Contains(err.Error(), "working directory is no longer inside the workspace; reset to the workspace root") {
		t.Fatalf("swapped cwd err %v %s", err, out)
	}
	if got := app.shellSessionDir(bot.ID, ws); got != ws {
		t.Fatalf("cwd after reset %s", got)
	}
	ask(t, app, bot, "pwd")
	approvePending(t, app, "pwd")
	out, err = app.execTool(ctx, bot, "run_shell", map[string]any{"command": "pwd"})
	if err != nil {
		t.Fatalf("pwd %v %s", err, out)
	}
	if strings.Contains(out, "/work/s1") || !strings.Contains(out, "stdout:\n/work\n") {
		t.Fatalf("pwd did not run at the workspace root:\n%s", out)
	}
}

func TestShellExecRecheckResetsSwappedCwd(t *testing.T) {
	app := newApp(t, "", nil)
	bot, err := app.st.CreateBot("Ada", "help", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	ws := app.botWorkspace(bot.ID)
	s1 := filepath.Join(ws, "s1")
	if err := os.MkdirAll(s1, 0o755); err != nil {
		t.Fatal(err)
	}
	app.shellCwdMu.Lock()
	app.shellCwd = map[string]string{bot.ID: s1}
	app.shellCwdMu.Unlock()
	outside := t.TempDir()
	if err := os.RemoveAll(s1); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, s1); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	out, err := app.execTool(ctx, bot, "run_shell", map[string]any{"command": "pwd"})
	if err == nil || !strings.Contains(err.Error(), "working directory is no longer inside the workspace; reset to the workspace root") {
		t.Fatalf("exec recheck err %v %s", err, out)
	}
	if got := app.shellSessionDir(bot.ID, ws); got != ws {
		t.Fatalf("cwd after reset %s", got)
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		if _, err2 := exec.LookPath("unshare"); err2 != nil {
			t.Skip("shell sandbox unavailable: bwrap and unshare are missing")
		}
	}
	out, err = app.execTool(ctx, bot, "run_shell", map[string]any{"command": "pwd"})
	if err != nil {
		t.Fatalf("pwd %v %s", err, out)
	}
	if strings.Contains(out, "/work/s1") || !strings.Contains(out, "stdout:\n/work\n") {
		t.Fatalf("pwd did not run at the workspace root:\n%s", out)
	}
}

func TestShellCwdOutsideSeedResets(t *testing.T) {
	app := newApp(t, "", nil)
	bot, err := app.st.CreateBot("Ada", "help", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	ws := app.botWorkspace(bot.ID)
	outside := t.TempDir()
	app.shellCwdMu.Lock()
	app.shellCwd = map[string]string{bot.ID: outside}
	app.shellCwdMu.Unlock()
	if got := app.shellSessionDir(bot.ID, ws); got != ws {
		t.Fatalf("shellSessionDir kept %s", got)
	}
	app.shellCwdMu.Lock()
	app.shellCwd[bot.ID] = ws
	app.shellPlan = map[string]shellCwdPlan{bot.ID: {next: filepath.Join(outside, "leaf"), update: true}}
	app.shellCwdMu.Unlock()
	app.commitShellPlan(bot.ID, ws)
	app.shellCwdMu.Lock()
	got := app.shellCwd[bot.ID]
	app.shellCwdMu.Unlock()
	if got != ws {
		t.Fatalf("commitShellPlan stored %s", got)
	}
}

func ask(t *testing.T, app *App, bot store.Bot, command string) {
	t.Helper()
	out, err := app.execTool(context.Background(), bot, "run_shell", map[string]any{"command": command})
	if err == nil || !strings.Contains(err.Error(), "pending approval") {
		t.Fatalf("%s out %q err %v pending %+v", command, out, err, app.broker.ListPending())
	}
}

func approvePending(t *testing.T, app *App, argv ...string) {
	t.Helper()
	for _, item := range app.broker.ListPending() {
		if strings.Join(item.Argv, "\x00") != strings.Join(argv, "\x00") {
			continue
		}
		if err := app.broker.Decide(item.ID, "approve", permbroker.ScopeOnce); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("no pending %v in %+v", argv, app.broker.ListPending())
}

func pendingArgv(app *App, argv ...string) []permbroker.Pending {
	want := strings.Join(argv, "\x00")
	var out []permbroker.Pending
	for _, item := range app.broker.ListPending() {
		if strings.Join(item.Argv, "\x00") == want {
			out = append(out, item)
		}
	}
	return out
}
