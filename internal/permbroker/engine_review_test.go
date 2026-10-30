package permbroker

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func reviewToolReq(bot, session, cwd, tool string, input any) Request {
	raw, _ := json.Marshal(input)
	return Request{
		BotID: bot, SessionID: session, RunID: "run", TaskID: "task",
		Cwd: cwd, ToolName: tool, ToolInput: raw,
	}
}

func TestOnceTokenBindsTool(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	read := reviewToolReq("bot", "sess", "/work", "Read", map[string]string{"file_path": "/work/notes.txt"})
	first := e.Evaluate(ctx, read)
	if first.PendingID == "" {
		t.Fatalf("%+v", first)
	}
	if err := e.Decide(first.PendingID, "approve", ScopeOnce); err != nil {
		t.Fatal(err)
	}
	edit := reviewToolReq("bot", "sess", "/work", "Edit", map[string]string{"file_path": "/work/notes.txt"})
	if d := e.Evaluate(ctx, edit); d.Verdict == VerdictAllow || d.PendingID == "" {
		t.Fatalf("edit used a read token %+v", d)
	}
	if d := e.Evaluate(ctx, read); d.Verdict != VerdictAllow {
		t.Fatalf("read retry %+v", d)
	}
	bash := bashReq("bot", "sess", "task", "/work", "echo hi")
	asked := e.Evaluate(ctx, bash)
	if err := e.Decide(asked.PendingID, "approve", ScopeOnce); err != nil {
		t.Fatal(err)
	}
	shell := bash
	shell.ToolName = "run_shell"
	if d := e.Evaluate(ctx, shell); d.Verdict != VerdictAllow {
		t.Fatalf("run_shell %+v", d)
	}
}

func TestCriticalOnceTokenDoesNotAllow(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	file := "/work/notes.txt"
	read := reviewToolReq("bot", "sess", "/work", "Read", map[string]string{"file_path": file})
	first := e.Evaluate(ctx, read)
	if err := e.Decide(first.PendingID, "approve", ScopeOnce); err != nil {
		t.Fatal(err)
	}
	e.AddCriticalPaths(file)
	again := e.Evaluate(ctx, read)
	if again.Verdict == VerdictAllow || again.Level != LevelCritical || again.PendingID == "" {
		t.Fatalf("critical once %+v", again)
	}
	e.SetCriticalPaths(nil)
	if d := e.Evaluate(ctx, read); d.Verdict != VerdictAllow {
		t.Fatalf("token was consumed %+v", d)
	}
}

func TestSetRisksInvalidatesGrants(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	req := bashReq("bot", "sess", "task", "/work", "git status")
	first := e.Evaluate(ctx, req)
	before := e.Ruleset()
	if err := e.SetRisks(nil); err != nil {
		t.Fatal(err)
	}
	if e.Ruleset() != before+1 {
		t.Fatalf("ruleset %d", e.Ruleset())
	}
	if err := e.Decide(first.PendingID, "approve", ScopeOnce); err != ErrStale {
		t.Fatalf("pending %v", err)
	}
	asked := e.Evaluate(ctx, req)
	if err := e.Decide(asked.PendingID, "approve", ScopeOnce); err != nil {
		t.Fatal(err)
	}
	if err := e.SetRisks([]RiskEntry{{Tool: "shell", Argv: []string{"git", "status"}, Level: LevelHigh}}); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, req); d.Verdict == VerdictAllow || d.PendingID == "" {
		t.Fatalf("token survived %+v", d)
	}
	task := e.Evaluate(ctx, req)
	if err := e.Decide(task.PendingID, "approve", ScopeTask); err != nil {
		t.Fatal(err)
	}
	if err := e.SetRisks([]RiskEntry{{Tool: "shell", Argv: []string{"git", "status"}, Level: LevelHigh}}); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, req); d.Verdict == VerdictAllow {
		t.Fatalf("grant survived %+v", d)
	}
	if _, err := e.SaveRule(Rule{Effect: EffectAllow, Argv: []string{"git", "status"}, Tool: ToolShell, Scope: ScopeBot, BotID: "bot"}); err != nil {
		t.Fatal(err)
	}
	e.AddCriticalPaths("/work/notes.txt")
	if _, err := e.SaveRule(Rule{Effect: EffectAllow, Argv: []string{"git", "grep", "notes", "/work/notes.txt"}, Tool: ToolShell, Scope: ScopeBot, BotID: "bot"}); err != ErrScope {
		t.Fatalf("critical rule %v", err)
	}
}

func TestSlowInspectDoesNotBlockOtherBot(t *testing.T) {
	e := testEngine(t)
	parent, err := os.MkdirTemp("", "sk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	slowLn, err := e.Listen("slow", filepath.Join(parent, "a.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slowLn.Close() })
	fastLn, err := e.Listen("fast", filepath.Join(parent, "b.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fastLn.Close() })
	e.NoteTurn("slow", "sess", "run", "task")
	e.NoteTurn("fast", "sess", "run", "task")
	entered := make(chan struct{})
	var once sync.Once
	e.SetInspectHook(func(ctx context.Context, req Request) {
		if req.BotID != "slow" {
			return
		}
		once.Do(func() { close(entered) })
		<-ctx.Done()
	})
	type slowResult struct {
		rep wireReply
		d   time.Duration
		err error
	}
	slowCh := make(chan slowResult, 1)
	start := time.Now()
	go func() {
		rep, err := sockRoundErr(slowLn.Path(), hookMsg("echo slow"))
		slowCh <- slowResult{rep, time.Since(start), err}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("slow inspect did not start")
	}
	fastStart := time.Now()
	fast, err := sockRoundErr(fastLn.Path(), hookMsg("echo hi"))
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(fastStart) > 500*time.Millisecond {
		t.Fatalf("fast bot waited %s", time.Since(fastStart))
	}
	if fast.Verdict != VerdictDeny || !strings.Contains(fast.Reason, "pending") {
		t.Fatalf("fast %+v", fast)
	}
	slow := <-slowCh
	if slow.err != nil {
		t.Fatal(slow.err)
	}
	if slow.d < time.Second || slow.d > 5*time.Second {
		t.Fatalf("slow took %s %+v", slow.d, slow.rep)
	}
	if slow.rep.Verdict != VerdictDeny || strings.Contains(slow.rep.Reason, "pending") {
		t.Fatalf("slow %+v", slow.rep)
	}
}

func TestDeadlineDenyKeepsOnceToken(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	req := bashReq("bot", "sess", "task", "/work", "git status")
	first := e.Evaluate(ctx, req)
	if first.PendingID == "" {
		t.Fatalf("%+v", first)
	}
	if err := e.Decide(first.PendingID, "approve", ScopeOnce); err != nil {
		t.Fatal(err)
	}
	parent, err := os.MkdirTemp("", "dl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	ln, err := e.Listen("bot", filepath.Join(parent, "s.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	e.NoteTurn("bot", "sess", "run", "task")
	hookDone := make(chan struct{})
	e.SetInspectHook(func(context.Context, Request) {
		time.Sleep(evaluateTimeout + time.Second)
		close(hookDone)
	})
	start := time.Now()
	rep, err := sockRoundErr(ln.Path(), hookMsg("git status"))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != VerdictDeny || rep.Reason != "denied" || strings.Contains(rep.Reason, "pending") {
		t.Fatalf("deadline %+v", rep)
	}
	if elapsed < time.Second || elapsed > 5*time.Second {
		t.Fatalf("deadline took %s", elapsed)
	}
	select {
	case <-hookDone:
	case <-time.After(5 * time.Second):
		t.Fatal("slow inspect did not finish")
	}
	time.Sleep(100 * time.Millisecond)
	e.SetInspectHook(nil)
	again, err := sockRoundErr(ln.Path(), hookMsg("git status"))
	if err != nil {
		t.Fatal(err)
	}
	if again.Verdict != VerdictAllow {
		t.Fatalf("token %+v", again)
	}
	third, err := sockRoundErr(ln.Path(), hookMsg("git status"))
	if err != nil {
		t.Fatal(err)
	}
	if third.Verdict == VerdictAllow {
		t.Fatalf("token reused %+v", third)
	}
}

func hookMsg(command string) map[string]any {
	return map[string]any{
		"op": "evaluate", "hook_event_name": "PreToolUse",
		"cwd": "/work", "tool_name": "Bash",
		"tool_input": map[string]string{"command": command},
	}
}

func sockRoundErr(sock string, msg any) (wireReply, error) {
	c, err := net.Dial("unix", sock)
	if err != nil {
		return wireReply{}, err
	}
	defer c.Close()
	if err := json.NewEncoder(c).Encode(msg); err != nil {
		return wireReply{}, err
	}
	if uc, ok := c.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	var rep wireReply
	if err := json.NewDecoder(c).Decode(&rep); err != nil {
		return wireReply{}, err
	}
	return rep, nil
}
