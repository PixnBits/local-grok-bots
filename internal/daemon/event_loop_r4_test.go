package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/permbroker"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// A nil interim budget refuses every interim start. It does not open a fresh
// cap and it does not write the capped or suppressed rows.
func TestAsyncShellNilBudgetRefuses(t *testing.T) {
	m := newAsyncModel("run_shell", "mid", "final answer", true)
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app := newApp(t, "", m)
	app.editPol(func(p *policy.Policy) { p.EventLoop = true })
	app.eventClk = clk
	app.toolExec = tool.exec
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "NilBudget")
	run, err := app.st.CreateRun(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	app.rtMu.Lock()
	app.loops[bot.ID] = &loopState{running: true, runID: run.ID, gen: 1}
	app.rtMu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = app.execShellAsync(context.Background(), bot, run.ID, "run_shell",
			map[string]any{"command": "echo hi"}, 0, nil, "", map[string]bool{},
			"test-model", app.pol(), nil)
	}()
	t.Cleanup(func() {
		tool.letGo()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	waitCh(t, tool.started, "shell")

	for i := 1; i <= 8; i++ {
		postUser(t, srv.URL, bot.ID, fmt.Sprintf("m%d", i))
		clk.Advance(500 * time.Millisecond)
		deadline := time.Now().Add(5 * time.Second)
		for nilRefusedCount(app, bot.ID) < i {
			select {
			case n := <-m.entered:
				t.Fatalf("nil budget started interim %d", n)
			default:
			}
			if batches := eventLoopBatchCounts(t, app, bot.ID); len(batches) != 0 {
				t.Fatalf("nil budget wrote event_loop_batch %v", batches)
			}
			if time.Now().After(deadline) {
				t.Fatalf("nil refusals %d, want >= %d", nilRefusedCount(app, bot.ID), i)
			}
			runtime.Gosched()
		}
	}
	if got := toolsNilReqs(m.snapshot()); len(got) != 0 {
		t.Fatalf("interim starts %d, want 0", len(got))
	}
	assertNoInterimCapStory(t, app, bot.ID)
	tool.letGo()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shell did not return")
	}
	assertNoInterimCapStory(t, app, bot.ID)
	if batches := eventLoopBatchCounts(t, app, bot.ID); len(batches) != 0 {
		t.Fatalf("batch rows after return %v", batches)
	}
}

func assertNoInterimCapStory(t *testing.T, app *App, botID string) {
	t.Helper()
	if rows := eventLoopInterimRows(t, app, botID); len(rows) != 0 {
		t.Fatalf("event_loop_interim rows %+v", rows)
	}
	if caps := eventLoopInterimCaps(t, app, botID); len(caps) != 0 {
		t.Fatalf("capped rows %+v", caps)
	}
	if sup := eventLoopInterimSuppressed(t, app, botID); len(sup) != 0 {
		t.Fatalf("suppressed rows %+v", sup)
	}
}

// resumeBudgetModel returns three run_shell calls, then a final answer.
// The calls land in two executes when the second one suspends for approval.
type resumeBudgetModel struct {
	*asyncModel
	toolsRound int
}

func (m *resumeBudgetModel) Chat(ctx context.Context, req model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
	if req.Tools == nil {
		return m.asyncModel.Chat(ctx, req, onToken)
	}
	m.toolsRound++
	if m.toolsRound <= 3 {
		return model.ChatResponse{ToolCalls: []model.ToolCall{{
			Name:      "run_shell",
			Arguments: map[string]any{"command": "echo hi"},
		}}}, nil
	}
	if onToken != nil && m.finalText != "" {
		onToken(m.finalText)
	}
	return model.ChatResponse{Content: m.finalText}, nil
}

// An approval resume of the same run keeps the remaining interim budget.
// Three starts, then the ask, then two starts, then the cap. A fresh budget
// on the resumed execute would start another interim.
func TestAsyncShellApprovalResumeKeepsBudget(t *testing.T) {
	m := &resumeBudgetModel{asyncModel: newAsyncModel("run_shell", "mid", "final answer", true)}
	gate1 := newGateTool("shell-1")
	gate2 := newGateTool("shell-2")
	t.Cleanup(gate1.letGo)
	t.Cleanup(gate2.letGo)
	clk := newManualClock()
	var app *App
	const cmd = "echo hi"
	var callN int
	var callMu sync.Mutex
	exec := func(ctx context.Context, bot store.Bot, name string, args map[string]any) (string, error) {
		callMu.Lock()
		callN++
		n := callN
		callMu.Unlock()
		switch n {
		case 1:
			return gate1.exec(ctx, bot, name, args)
		case 2:
			return askShellApproval(ctx, app, bot, cmd)
		default:
			return gate2.exec(ctx, bot, name, args)
		}
	}
	app = newApp(t, "", m)
	app.editPol(func(p *policy.Policy) { p.EventLoop = true })
	if !app.pol().EventLoopEnabled() {
		t.Fatal("event loop flag did not publish")
	}
	app.eventClk = clk
	app.toolExec = exec
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "ResumeCap")
	runID := postUser(t, srv.URL, bot.ID, "go")
	waitCh(t, gate1.started, "shell 1")
	fireInterim(t, srv.URL, bot.ID, "a1", clk, m.entered, 1)
	fireInterim(t, srv.URL, bot.ID, "a2", clk, m.entered, 2)
	fireInterim(t, srv.URL, bot.ID, "a3", clk, m.entered, 3)
	gate1.letGo()
	waitRunStatus(t, app, bot.ID, "waiting")
	run, err := app.st.GetRun(runID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "waiting" || run.WaitingPendingID == "" || run.ID != runID {
		t.Fatalf("waiting run %+v", run)
	}
	snap, ok := app.broker.SnapshotPending(run.WaitingPendingID)
	if !ok {
		t.Fatalf("pending %s is not open", run.WaitingPendingID)
	}
	if err := app.broker.Decide(run.WaitingPendingID, "approve", permbroker.ScopeOnce); err != nil {
		t.Fatal(err)
	}
	app.afterBrokerDecision(run.WaitingPendingID, "approve", snap)
	select {
	case <-gate2.started:
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for shell after approve")
	}
	same, err := app.st.GetRun(runID)
	if err != nil {
		t.Fatal(err)
	}
	if same.ID != runID || same.Status == "done" || same.Status == "error" {
		t.Fatalf("resumed run %+v", same)
	}
	fireInterim(t, srv.URL, bot.ID, "b1", clk, m.entered, 4)
	fireInterim(t, srv.URL, bot.ID, "b2", clk, m.entered, 5)
	postUser(t, srv.URL, bot.ID, "b3")
	clk.Advance(500 * time.Millisecond)
	if got := waitBudgetSuppressed(t, app, bot.ID, 1); got != 1 {
		t.Fatalf("suppressed in run %d, want 1", got)
	}
	if batches := eventLoopBatchCounts(t, app, bot.ID); len(batches) != 5 {
		t.Fatalf("batches %#v, want 5", batches)
	}
	caps := waitInterimCaps(t, app, bot.ID, 1)
	if len(caps) != 1 || caps[0].Count != 5 || caps[0].Cap != 5 || caps[0].RunID != runID {
		t.Fatalf("caps %+v", caps)
	}
	assertNoEntered(t, m.entered)
	if got := toolsNilReqs(m.snapshot()); len(got) != 5 {
		t.Fatalf("interim starts %d, want 5", len(got))
	}
	gate2.letGo()
	waitIdle(t, srv.URL, bot.ID, "")
	if got := toolsNilReqs(m.snapshot()); len(got) != 5 {
		t.Fatalf("interim after finish %d, want 5", len(got))
	}
	done, err := app.st.GetRun(runID)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != "done" || done.ID != runID {
		botNow, _ := app.st.GetBot(bot.ID)
		t.Fatalf("run %s %q bot %s %q", done.Status, done.ID, botNow.LastRunStatus, botNow.LastRunError)
	}
	supp := waitInterimSuppressed(t, app, bot.ID, 1)
	if len(supp) != 1 || supp[0].Suppressed != 1 || supp[0].Count != 5 || supp[0].Cap != 5 || supp[0].RunID != runID {
		t.Fatalf("suppressed %+v", supp)
	}
	if batches := eventLoopBatchCounts(t, app, bot.ID); len(batches) != 5 {
		t.Fatalf("batches after finish %#v", batches)
	}
}

func askShellApproval(ctx context.Context, app *App, bot store.Bot, cmd string) (string, error) {
	if app == nil || app.broker == nil {
		return "", fmt.Errorf("no broker")
	}
	ws := filepath.Clean(app.botWorkspace(bot.ID))
	if err := os.MkdirAll(ws, 0o755); err != nil {
		return "", err
	}
	current, err := app.st.GetBot(bot.ID)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(map[string]string{"command": cmd})
	if err != nil {
		return "", err
	}
	task := app.broker.UserTask(bot.ID)
	d := app.broker.Evaluate(ctx, permbroker.Request{
		BotID: bot.ID, SessionID: "shell:" + bot.ID, RunID: runIDFrom(ctx), TaskID: task,
		Cwd: ws, Workspace: ws, Repos: app.effPol(bot.ID).EffectiveGitHubRepos(current.GitHubAllow),
		ToolName: "run_shell", ToolInput: raw, Origin: permbroker.OriginNative,
	})
	if d.PendingID == "" {
		return "", fmt.Errorf("broker verdict %s (%s)", d.Verdict, d.Reason)
	}
	return "", &approvalWaitError{
		PendingID: d.PendingID, Reason: d.Reason, Cwd: ws,
		SessionID: "shell:" + bot.ID, TaskID: task, Level: string(d.Level),
		Command: cmd,
	}
}

// An interim model error is stored as a class and a short message.
// Absolute paths and key-shaped text are not in the audit row.
// The client reset payload stays run id and reason.
func TestAsyncShellInterimErrorRedacted(t *testing.T) {
	const unixPath = "/home/probe-user/.ssh/id_probe_ev"
	const winPath = `C:\Users\probe\id_probe_ev`
	const secret = "sk-ant-api03-probekeyvalue"
	const interim = "partial reply"
	rawErr := fmt.Errorf("model failed reading %s and %s key %s", unixPath, winPath, secret)
	m := newAsyncModel("run_shell", interim, "final answer", false)
	m.interimErr = rawErr
	m.tokensOut = make(chan struct{})
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app, base, bot, runID := startShellRun(t, "RedactErr", true, clk, m, tool)
	waitCh(t, tool.started, "tool start")
	postUser(t, base, bot.ID, "one")
	clk.Advance(500 * time.Millisecond)
	waitN(t, m.entered, "interim")
	waitCh(t, m.tokensOut, "tokens")
	waitResetReason(t, app, runID, "interim_error")
	reasons := resetReasons(app, runID)
	if len(reasons) != 1 || reasons[0] != "interim_error" {
		t.Fatalf("reset %#v", reasons)
	}
	for _, f := range runFrames(app, runID) {
		blob := string(f.data)
		if strings.Contains(blob, unixPath) || strings.Contains(blob, "id_probe_ev") || strings.Contains(blob, secret) || strings.Contains(blob, "probekeyvalue") {
			t.Fatalf("client frame %s contains the model error: %s", f.event, blob)
		}
		if f.event != "stream_reset" {
			continue
		}
		var keys map[string]any
		if err := json.Unmarshal(f.data, &keys); err != nil {
			t.Fatal(err)
		}
		if len(keys) != 2 || keys["run_id"] != runID || keys["reason"] != "interim_error" {
			t.Fatalf("reset payload %#v", keys)
		}
	}
	ev, err := app.st.ListLog(bot.ID, "event_loop_interim", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 {
		t.Fatalf("interim rows %d", len(ev))
	}
	rawDetail := string(ev[0].Detail)
	var row struct {
		ErrorClass string `json:"error_class"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(ev[0].Detail, &row); err != nil {
		t.Fatal(err)
	}
	if row.ErrorClass != "model_error" || row.Error == "" {
		t.Fatalf("audit error class %q message %q", row.ErrorClass, row.Error)
	}
	if row.Error == rawErr.Error() || strings.Contains(row.Error, unixPath) || strings.Contains(row.Error, winPath) || strings.Contains(row.Error, "id_probe_ev") || strings.Contains(row.Error, secret) || strings.Contains(row.Error, "probekeyvalue") {
		t.Fatalf("audit message %q", row.Error)
	}
	if strings.Contains(rawDetail, unixPath) || strings.Contains(rawDetail, "id_probe_ev") || strings.Contains(rawDetail, secret) || strings.Contains(rawDetail, "probekeyvalue") || strings.Contains(rawDetail, "probe-user") {
		t.Fatalf("audit detail %s", rawDetail)
	}
	tool.letGo()
	waitIdle(t, base, bot.ID, "")
}

// multiModel: tools-bearing request 1 and 2 each return one run_shell call
// (two shells in two model rounds). Request 3 is the final answer.
type multiModel struct {
	*asyncModel
	tc int
}

func (m *multiModel) Chat(ctx context.Context, req model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
	m.asyncModel.mu.Lock()
	m.asyncModel.reqs = append(m.asyncModel.reqs, cloneChatRequest(req))
	m.asyncModel.mu.Unlock()
	if req.Tools == nil {
		return m.asyncModel.interim(ctx, onToken)
	}
	m.tc++
	if m.tc <= 2 {
		return model.ChatResponse{ToolCalls: []model.ToolCall{{Name: "run_shell", Arguments: map[string]any{"command": "echo hi"}}}}, nil
	}
	if onToken != nil {
		onToken("final answer")
	}
	return model.ChatResponse{Content: "final answer"}, nil
}

// Two run_shell calls in two model rounds of one run share one budget.
func TestTesterEvR3TwoRoundsOneBudget(t *testing.T) {
	m := &multiModel{asyncModel: newAsyncModel("run_shell", "mid", "final answer", true)}
	t1, t2 := newGateTool("s1"), newGateTool("s2")
	t.Cleanup(t1.letGo)
	t.Cleanup(t2.letGo)
	clk := newManualClock()
	app, base, bot, runID := startLoopRun(t, "Rounds", true, clk, m, chainTools(t1, t2))
	waitCh(t, t1.started, "shell 1")
	fireInterim(t, base, bot.ID, "a1", clk, m.entered, 1)
	fireInterim(t, base, bot.ID, "a2", clk, m.entered, 2)
	fireInterim(t, base, bot.ID, "a3", clk, m.entered, 3)
	t1.letGo()
	waitCh(t, t2.started, "shell 2")
	fireInterim(t, base, bot.ID, "b1", clk, m.entered, 4)
	fireInterim(t, base, bot.ID, "b2", clk, m.entered, 5)
	postUser(t, base, bot.ID, "b3")
	clk.Advance(500 * time.Millisecond)
	if got := waitBudgetSuppressed(t, app, bot.ID, 1); got != 1 {
		t.Fatalf("suppressed in run %d, want 1", got)
	}
	if batches := eventLoopBatchCounts(t, app, bot.ID); len(batches) != 5 {
		t.Fatalf("batches %#v, want 5", batches)
	}
	assertNoEntered(t, m.entered)
	t2.letGo()
	waitIdle(t, base, bot.ID, "")
	if got := len(toolsNilReqs(m.snapshot())); got != 5 {
		t.Fatalf("interim starts %d want 5", got)
	}
	caps := eventLoopInterimCaps(t, app, bot.ID)
	if len(caps) != 1 || caps[0].Count != 5 || caps[0].RunID != runID {
		t.Fatalf("caps %+v", caps)
	}
	supp := eventLoopInterimSuppressed(t, app, bot.ID)
	if len(supp) != 1 || supp[0].Suppressed != 1 || supp[0].Count != 5 || supp[0].RunID != runID {
		t.Fatalf("suppressed %+v", supp)
	}
}

// A run deadline that fires during an interim publishes interim_cancelled.
func TestTesterEvR3RunDeadlineMidInterim(t *testing.T) {
	m := newStreamingInterim("RUNDEADTOK", "final answer")
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app := newApp(t, "", m)
	app.editPol(func(p *policy.Policy) {
		p.EventLoop = true
		p.OllamaRunTimeout = 1500 * time.Millisecond
	})
	app.eventClk = clk
	app.toolExec = tool.exec
	t.Cleanup(tool.letGo)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "RunDead")
	runID := postUser(t, srv.URL, bot.ID, "go")
	waitCh(t, tool.started, "tool start")
	postUser(t, srv.URL, bot.ID, "one")
	clk.Advance(500 * time.Millisecond)
	waitN(t, m.entered, "interim")
	waitCh(t, m.tokensOut, "tokens")
	waitIdle(t, srv.URL, bot.ID, "")
	got := fetchBot(t, srv.URL, bot.ID)
	reasons := resetReasons(app, runID)
	t.Logf("last_run_status=%s err=%q resets=%v events=%v", got.LastRunStatus, got.LastRunError, reasons, eventNames(app, runID))
	hasTimeout := false
	for _, n := range eventNames(app, runID) {
		if n == "timeout" {
			hasTimeout = true
		}
	}
	if !hasTimeout {
		t.Fatalf("no timeout event: the run deadline did not fire (%v)", eventNames(app, runID))
	}
	for _, r := range reasons {
		if r == "interim_error" {
			t.Fatalf("run deadline labelled interim_error: %v", reasons)
		}
	}
	if len(reasons) != 1 || reasons[0] != "interim_cancelled" {
		t.Fatalf("resets %v want [interim_cancelled]", reasons)
	}
}
