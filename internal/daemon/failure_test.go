package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// partialRunner streams text, one tool call with its result, and more text,
// then fails (hang=false) or waits for the turn deadline (hang=true).
type partialRunner struct{ hang bool }

func (r partialRunner) Run(ctx context.Context, _ clisession.Spec, on func(clisession.Event)) (clisession.Result, error) {
	on(clisession.Event{Kind: "token", Text: "Looking at the repo."})
	on(clisession.Event{Kind: "tool", ToolName: "Bash", ToolArgs: map[string]any{"command": "ls"}})
	on(clisession.Event{Kind: "tool_result", ToolName: "Bash", Text: "go.mod\nmain.go"})
	on(clisession.Event{Kind: "token", Text: "Partial answer so far"})
	if r.hang {
		<-ctx.Done()
		return clisession.Result{SessionID: "sess-p"}, ctx.Err()
	}
	return clisession.Result{SessionID: "sess-p"}, errors.New("claude exited with status 1")
}

func runFailingCLI(t *testing.T, r clisession.Runner, pol policy.Policy) (*App, string, store.Bot) {
	t.Helper()
	dir := t.TempDir()
	app := newApp(t, dir, nil)
	app.runner = r
	app.cliTTY = func() bool { return false }
	app.rtMu.Lock()
	app.policy = pol
	app.rtMu.Unlock()
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Ada", "description": "p"}, "")
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{"content": "go"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, "")
	return app, srv.URL, bot
}

type failThread struct {
	Messages []store.Message               `json:"messages"`
	Tools    map[string][]store.ToolRecord `json:"tools"`
}

func readThread(t *testing.T, base, botID string) failThread {
	t.Helper()
	res, b := do(t, "GET", base+"/api/bots/"+botID+"/thread", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("thread %d %s", res.StatusCode, b)
	}
	var out failThread
	decodeJSON(t, b, &out)
	return out
}

// assertFailedRunKept checks the thread after a failed run: the partial
// reply, an error notice, and the run's tool records, all tied to the run.
func assertFailedRunKept(t *testing.T, page failThread, partial, notice string, wantTool string) {
	t.Helper()
	var runID string
	var sawPartial, sawNotice bool
	for _, m := range page.Messages {
		if m.Role == "bot" && strings.Contains(m.Content, partial) {
			sawPartial = true
		}
		if m.Role == "system" && strings.HasPrefix(m.Content, "Notice: ") && strings.Contains(m.Content, notice) {
			sawNotice = true
			if m.RunID != nil {
				runID = *m.RunID
			}
		}
	}
	if !sawPartial || !sawNotice || runID == "" {
		t.Fatalf("partial %v notice %v run %q thread %+v", sawPartial, sawNotice, runID, page.Messages)
	}
	found := false
	for _, r := range page.Tools[runID] {
		if r.Name == wantTool && r.OK {
			found = true
		}
	}
	if !found {
		t.Fatalf("tool %s missing from run %s: %+v", wantTool, runID, page.Tools)
	}
}

func cliPolicy() policy.Policy {
	return policy.Policy{Backend: "claude", CLIPermitted: true, TimersEnabled: true, Idle: time.Hour, Imminent: time.Minute}
}

func TestCLIErrorKeepsPartialToolsAndNotice(t *testing.T) {
	app, base, bot := runFailingCLI(t, partialRunner{}, cliPolicy())
	got, _ := app.st.GetBot(bot.ID)
	if got.LastRunStatus != "error" {
		t.Fatalf("status %s", got.LastRunStatus)
	}
	assertFailedRunKept(t, readThread(t, base, bot.ID), "Partial answer so far", "claude exited with status 1", "Bash")
	// A notice is not turn input, so it does not start another run.
	need, err := app.st.NeedsRun(bot.ID)
	if err != nil || need {
		t.Fatalf("notice queued a run: %v %v", need, err)
	}
}

func TestCLITurnTimeoutKeepsPartialToolsAndNotice(t *testing.T) {
	pol := cliPolicy()
	pol.TurnTimeout = 300 * time.Millisecond
	app, base, bot := runFailingCLI(t, partialRunner{hang: true}, pol)
	got, _ := app.st.GetBot(bot.ID)
	if got.LastRunStatus != "error" || got.LastRunError != "turn_timeout" {
		t.Fatalf("status %s %s", got.LastRunStatus, got.LastRunError)
	}
	assertFailedRunKept(t, readThread(t, base, bot.ID), "Partial answer so far", "timed out", "Bash")
}

// A CLI turn is no longer cut at a hidden 10 minute run timeout: the
// deadline is cli.turn_timeout (default 2h) with a managed ceiling.
func TestCLITurnDeadlineFollowsPolicy(t *testing.T) {
	var got time.Duration
	r := runnerFunc(func(ctx context.Context) {
		if d, ok := ctx.Deadline(); ok {
			got = time.Until(d)
		}
	})
	runFailingCLI(t, r, cliPolicy())
	if got < policy.DefaultTurnTimeout-time.Minute || got > policy.DefaultTurnTimeout {
		t.Fatalf("default deadline %s", got)
	}
	pol := cliPolicy()
	pol.TurnTimeout = 5 * time.Hour
	pol.MaxTurnTimeout = 3 * time.Hour
	runFailingCLI(t, r, pol)
	if got < 3*time.Hour-time.Minute || got > 3*time.Hour {
		t.Fatalf("capped deadline %s", got)
	}
}

type runnerFunc func(ctx context.Context)

func (f runnerFunc) Run(ctx context.Context, _ clisession.Spec, _ func(clisession.Event)) (clisession.Result, error) {
	f(ctx)
	return clisession.Result{Text: "ok", SessionID: "s"}, nil
}

// streamErrModel calls a tool in round one, then streams text and fails.
type streamErrModel struct{ calls int }

func (m *streamErrModel) Chat(ctx context.Context, req model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
	m.calls++
	if m.calls == 1 {
		return model.ChatResponse{ToolCalls: []model.ToolCall{{Name: "list_bots", Arguments: map[string]any{}}}}, nil
	}
	onToken("Half of the ")
	onToken("answer")
	return model.ChatResponse{}, errors.New("ollama: connection reset")
}

func TestOllamaErrorKeepsPartialToolsAndNotice(t *testing.T) {
	m := &streamErrModel{}
	app := newApp(t, t.TempDir(), m)
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Ada", "description": "p"}, "")
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{"content": "go"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, "")
	assertFailedRunKept(t, readThread(t, srv.URL, bot.ID), "Half of the answer", "connection reset", "list_bots")
}

func TestRunNoticeText(t *testing.T) {
	cases := map[string]string{
		runNoticeText("cancelled", ""):                   "Notice: Run cancelled.",
		runNoticeText("error", "interrupted"):            "Notice: Run interrupted before it finished.",
		runNoticeText("error", "turn_timeout"):           "Notice: Run timed out (turn_timeout). Partial output and tool results are kept above.",
		runNoticeText("error", ""):                       "Notice: Run failed.",
		runNoticeText("error", "boom"):                   "Notice: Run failed: boom",
		runNoticeText("stopped", "stopped after denial"): "Notice: Stopped after denial.",
	}
	for got, want := range cases {
		if got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}

// A turn blocked on an approval is not idle-killed; the prompt timeout
// governs it. Without the pending request the same turn is killed.
func TestIdleKillSkipsPendingApproval(t *testing.T) {
	app := newApp(t, t.TempDir(), nil)
	app.rtMu.Lock()
	app.policy = cliPolicy()
	app.policy.Idle = time.Minute
	app.rtMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app.rtMu.Lock()
	app.loops["bot1"] = &loopState{running: true, cancel: cancel, cliPID: 4242, runID: "run1"}
	app.activity["bot1"] = time.Now().Add(-time.Hour)
	app.rtMu.Unlock()
	reqCtx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		app.perm.Evaluate(reqCtx, policy.Permission{UIPrompts: true, PromptTimeout: time.Minute},
			permission.Request{RunID: "run1", BotID: "bot1", Tool: "Bash", Args: map[string]any{"command": "ls"}})
		close(done)
	}()
	for i := 0; i < 200 && app.perm.PendingCounts()["bot1"] == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	app.killIdle()
	if ctx.Err() != nil {
		t.Fatal("idle kill cancelled a turn waiting on approval")
	}
	stop()
	<-done
	app.killIdle()
	if ctx.Err() == nil {
		t.Fatal("idle turn was not killed")
	}
	app.rtMu.Lock()
	delete(app.loops, "bot1")
	app.rtMu.Unlock()
}
