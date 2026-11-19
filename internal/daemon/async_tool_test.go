package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// asyncModel records every chat request and, unlike fakeModel, stops when
// ctx is cancelled. A nil Tools slice is an interim call.
type asyncModel struct {
	mu          sync.Mutex
	reqs        []model.ChatRequest
	interimCtxs []context.Context
	entered     chan int
	returned    chan int
	returnedAt  map[int]struct{}
	atFinal     joinSnap
	block       bool
	hold        chan struct{}
	interimText string
	toolName    string
	finalText   string
	// tokensFirst emits interimText before blocking on ctx cancel.
	tokensFirst bool
	// tokensOut is closed once those tokens have been handed to onToken.
	tokensOut  chan struct{}
	tokensOnce sync.Once
	// dualShell makes the first tools-bearing reply of this model two
	// run_shell calls. Later runs get one call.
	dualShell bool
	dualSent  bool
	// toolsEmitted counts tools-bearing replies in the current run cycle.
	toolsEmitted int
	// interimErr, when set, is returned from an interim call after any tokens.
	interimErr error
}

// joinSnap is what a Tools != nil call observed about earlier interims.
type joinSnap struct {
	recorded  bool
	cancelled bool
	returned  bool
	enteredN  int
	returnedN int
}

func newAsyncModel(toolName, interimText, finalText string, block bool) *asyncModel {
	return &asyncModel{
		entered:     make(chan int, 16),
		returned:    make(chan int, 16),
		returnedAt:  map[int]struct{}{},
		block:       block,
		interimText: interimText,
		toolName:    toolName,
		finalText:   finalText,
	}
}

func (m *asyncModel) Chat(ctx context.Context, req model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
	if err := ctx.Err(); err != nil {
		return model.ChatResponse{}, err
	}
	cp := cloneChatRequest(req)
	m.mu.Lock()
	m.reqs = append(m.reqs, cp)
	if req.Tools != nil && len(m.interimCtxs) > 0 && !m.atFinal.recorded {
		m.atFinal.recorded = true
		m.atFinal.enteredN = len(m.interimCtxs)
		m.atFinal.returnedN = len(m.returnedAt)
		cancelled := len(m.interimCtxs) > 0
		for _, c := range m.interimCtxs {
			if c.Err() == nil {
				cancelled = false
				break
			}
		}
		m.atFinal.cancelled = cancelled
		m.atFinal.returned = len(m.returnedAt) == len(m.interimCtxs) && len(m.interimCtxs) > 0
	}
	var toolCalls []model.ToolCall
	final := false
	if req.Tools != nil {
		if m.toolsEmitted < 1 {
			m.toolsEmitted++
			call := model.ToolCall{Name: m.toolName, Arguments: map[string]any{"command": "echo hi"}}
			toolCalls = []model.ToolCall{call}
			if m.dualShell && !m.dualSent && m.toolsEmitted == 1 {
				m.dualSent = true
				toolCalls = append(toolCalls, model.ToolCall{Name: m.toolName, Arguments: map[string]any{"command": "echo hi"}})
			}
		} else {
			m.toolsEmitted = 0
			final = true
		}
	}
	m.mu.Unlock()
	if req.Tools == nil {
		return m.interim(ctx, onToken)
	}
	if !final {
		return model.ChatResponse{ToolCalls: toolCalls}, nil
	}
	if onToken != nil && m.finalText != "" {
		onToken(m.finalText)
	}
	return model.ChatResponse{Content: m.finalText}, nil
}

func (m *asyncModel) interim(ctx context.Context, onToken func(string)) (model.ChatResponse, error) {
	m.mu.Lock()
	m.interimCtxs = append(m.interimCtxs, ctx)
	n := len(m.interimCtxs)
	m.mu.Unlock()
	select {
	case m.entered <- n:
	case <-ctx.Done():
		m.markReturned(n)
		return model.ChatResponse{}, ctx.Err()
	}
	if m.interimErr != nil {
		if onToken != nil && m.interimText != "" {
			onToken(m.interimText)
		}
		m.signalTokens()
		m.markReturned(n)
		return model.ChatResponse{}, m.interimErr
	}
	if m.block {
		if m.tokensFirst {
			if onToken != nil && m.interimText != "" {
				onToken(m.interimText)
			}
			m.signalTokens()
		}
		select {
		case <-ctx.Done():
			m.markReturned(n)
			return model.ChatResponse{}, ctx.Err()
		case <-m.hold:
		}
	}
	if err := ctx.Err(); err != nil {
		m.markReturned(n)
		return model.ChatResponse{}, err
	}
	if onToken != nil && m.interimText != "" && !m.tokensFirst {
		onToken(m.interimText)
	}
	m.markReturned(n)
	return model.ChatResponse{Content: m.interimText}, nil
}

func (m *asyncModel) signalTokens() {
	if m == nil || m.tokensOut == nil {
		return
	}
	m.tokensOnce.Do(func() { close(m.tokensOut) })
}

func (m *asyncModel) markReturned(n int) {
	m.mu.Lock()
	if m.returnedAt == nil {
		m.returnedAt = map[int]struct{}{}
	}
	m.returnedAt[n] = struct{}{}
	m.mu.Unlock()
	m.returned <- n
}

func (m *asyncModel) snapshot() []model.ChatRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]model.ChatRequest, len(m.reqs))
	copy(out, m.reqs)
	return out
}

func (m *asyncModel) contexts() []context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]context.Context(nil), m.interimCtxs...)
}

func (m *asyncModel) interimCounts() (entered, returned int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.interimCtxs), len(m.returnedAt)
}

func (m *asyncModel) joinAtFinal() joinSnap {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.atFinal
}

func cloneChatRequest(req model.ChatRequest) model.ChatRequest {
	out := req
	if req.Messages != nil {
		out.Messages = make([]model.Message, len(req.Messages))
		for i, msg := range req.Messages {
			out.Messages[i] = msg
			if len(msg.ToolCalls) > 0 {
				calls := make([]model.ToolCall, len(msg.ToolCalls))
				for j, c := range msg.ToolCalls {
					calls[j] = c
					if c.Arguments != nil {
						args := make(map[string]any, len(c.Arguments))
						for k, v := range c.Arguments {
							args[k] = v
						}
						calls[j].Arguments = args
					}
				}
				out.Messages[i].ToolCalls = calls
			}
		}
	}
	if req.Tools != nil {
		out.Tools = append([]model.Tool(nil), req.Tools...)
	}
	return out
}

// gateTool blocks in the tool until letGo or ctx cancel. No timers.
type gateTool struct {
	mu          sync.Mutex
	ctx         context.Context
	started     chan struct{}
	release     chan struct{}
	once        sync.Once
	result      string
	done        chan struct{}
	afterCancel time.Duration
}

func newGateTool(result string) *gateTool {
	return &gateTool{
		started: make(chan struct{}),
		release: make(chan struct{}),
		done:    make(chan struct{}),
		result:  result,
	}
}

func (g *gateTool) letGo() { g.once.Do(func() { close(g.release) }) }

func (g *gateTool) exec(ctx context.Context, _ store.Bot, _ string, _ map[string]any) (string, error) {
	g.mu.Lock()
	g.ctx = ctx
	g.mu.Unlock()
	close(g.started)
	select {
	case <-g.release:
		close(g.done)
		return g.result, nil
	case <-ctx.Done():
		if g.afterCancel > 0 {
			time.Sleep(g.afterCancel)
		}
		close(g.done)
		return "", ctx.Err()
	}
}

func (g *gateTool) context() context.Context {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.ctx
}

func (g *gateTool) finished() bool {
	select {
	case <-g.done:
		return true
	default:
		return false
	}
}

func startShellRun(t *testing.T, botName string, on bool, clk *manualClock, m model.Client, tool *gateTool) (*App, string, store.Bot, string) {
	t.Helper()
	var exec func(context.Context, store.Bot, string, map[string]any) (string, error)
	if tool != nil {
		exec = tool.exec
		t.Cleanup(tool.letGo)
	}
	return startLoopRun(t, botName, on, clk, m, exec)
}

func startLoopRun(t *testing.T, botName string, on bool, clk *manualClock, m model.Client, exec func(context.Context, store.Bot, string, map[string]any) (string, error)) (*App, string, store.Bot, string) {
	t.Helper()
	app := newApp(t, "", m)
	if on {
		app.editPol(func(p *policy.Policy) { p.EventLoop = true })
		if !app.pol().EventLoopEnabled() {
			t.Fatal("event loop flag did not publish")
		}
	}
	if clk != nil {
		app.eventClk = clk
	}
	if exec != nil {
		app.toolExec = exec
	}
	srv := serve(t, app)
	bot := createBot(t, srv.URL, botName)
	runID := postUser(t, srv.URL, bot.ID, "go")
	if runID == "" {
		t.Fatal("no run")
	}
	return app, srv.URL, bot, runID
}

func chainTools(tools ...*gateTool) func(context.Context, store.Bot, string, map[string]any) (string, error) {
	var mu sync.Mutex
	n := 0
	return func(ctx context.Context, bot store.Bot, name string, args map[string]any) (string, error) {
		mu.Lock()
		i := n
		n++
		mu.Unlock()
		if i < 0 || i >= len(tools) {
			return "", fmt.Errorf("unexpected tool call %d", i+1)
		}
		return tools[i].exec(ctx, bot, name, args)
	}
}

func waitCh(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func waitN(t *testing.T, ch <-chan int, what string) int {
	t.Helper()
	select {
	case n := <-ch:
		return n
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return 0
	}
}

func wakeInstalled(app *App, botID string) bool {
	app.rtMu.Lock()
	defer app.rtMu.Unlock()
	st := app.loops[botID]
	return st != nil && st.wake != nil
}

func installedWake(app *App, botID string) (func(string, uint64), string, uint64) {
	app.rtMu.Lock()
	defer app.rtMu.Unlock()
	st := app.loops[botID]
	if st == nil {
		return nil, "", 0
	}
	return st.wake, st.runID, st.gen
}

func toolsNilReqs(reqs []model.ChatRequest) []model.ChatRequest {
	var out []model.ChatRequest
	for _, r := range reqs {
		if r.Tools == nil {
			out = append(out, r)
		}
	}
	return out
}

func eventLoopBatchCounts(t *testing.T, app *App, botID string) []int {
	t.Helper()
	ev, err := app.st.ListLog(botID, "event_loop_batch", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]int, 0, len(ev))
	for i := len(ev) - 1; i >= 0; i-- {
		var p struct {
			Count int `json:"count"`
		}
		if err := json.Unmarshal(ev[i].Detail, &p); err != nil {
			t.Fatalf("batch detail %s: %v", ev[i].Detail, err)
		}
		out = append(out, p.Count)
	}
	return out
}

func waitBatchRows(t *testing.T, app *App, botID string, n int) []int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var got []int
	for time.Now().Before(deadline) {
		got = eventLoopBatchCounts(t, app, botID)
		if len(got) >= n {
			return got
		}
		runtime.Gosched()
	}
	t.Fatalf("event_loop_batch rows %d, want %d (%v)", len(got), n, got)
	return got
}

type interimLogRow struct {
	OK         bool `json:"ok"`
	Superseded bool `json:"superseded"`
}

func eventLoopInterimRows(t *testing.T, app *App, botID string) []interimLogRow {
	t.Helper()
	ev, err := app.st.ListLog(botID, "event_loop_interim", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]interimLogRow, 0, len(ev))
	for i := len(ev) - 1; i >= 0; i-- {
		var p interimLogRow
		if err := json.Unmarshal(ev[i].Detail, &p); err != nil {
			t.Fatalf("interim detail %s: %v", ev[i].Detail, err)
		}
		out = append(out, p)
	}
	return out
}

func waitInterimRows(t *testing.T, app *App, botID string, n int) []interimLogRow {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var got []interimLogRow
	for time.Now().Before(deadline) {
		got = eventLoopInterimRows(t, app, botID)
		if len(got) >= n {
			return got
		}
		runtime.Gosched()
	}
	t.Fatalf("event_loop_interim rows %d, want %d (%v)", len(got), n, got)
	return got
}

type interimCapRow struct {
	RunID string `json:"run_id"`
	Count int    `json:"count"`
	Cap   int    `json:"cap"`
}

func eventLoopInterimCaps(t *testing.T, app *App, botID string) []interimCapRow {
	t.Helper()
	ev, err := app.st.ListLog(botID, "event_loop_interim_capped", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]interimCapRow, 0, len(ev))
	for i := len(ev) - 1; i >= 0; i-- {
		var p interimCapRow
		if err := json.Unmarshal(ev[i].Detail, &p); err != nil {
			t.Fatalf("cap detail %s: %v", ev[i].Detail, err)
		}
		out = append(out, p)
	}
	return out
}

func waitInterimCaps(t *testing.T, app *App, botID string, n int) []interimCapRow {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var got []interimCapRow
	for time.Now().Before(deadline) {
		got = eventLoopInterimCaps(t, app, botID)
		if len(got) >= n {
			return got
		}
		runtime.Gosched()
	}
	t.Fatalf("event_loop_interim_capped rows %d, want %d (%v)", len(got), n, got)
	return got
}

type interimSuppressedRow struct {
	RunID      string `json:"run_id"`
	Suppressed int    `json:"suppressed"`
	Count      int    `json:"count"`
	Cap        int    `json:"cap"`
}

func eventLoopInterimSuppressed(t *testing.T, app *App, botID string) []interimSuppressedRow {
	t.Helper()
	ev, err := app.st.ListLog(botID, "event_loop_interim_capped_suppressed", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]interimSuppressedRow, 0, len(ev))
	for i := len(ev) - 1; i >= 0; i-- {
		var p interimSuppressedRow
		if err := json.Unmarshal(ev[i].Detail, &p); err != nil {
			t.Fatalf("suppressed detail %s: %v", ev[i].Detail, err)
		}
		out = append(out, p)
	}
	return out
}

func waitInterimSuppressed(t *testing.T, app *App, botID string, n int) []interimSuppressedRow {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var got []interimSuppressedRow
	for time.Now().Before(deadline) {
		got = eventLoopInterimSuppressed(t, app, botID)
		if len(got) >= n {
			return got
		}
		runtime.Gosched()
	}
	t.Fatalf("event_loop_interim_capped_suppressed rows %d, want %d (%v)", len(got), n, got)
	return got
}

func budgetSuppressed(app *App, botID string) int {
	app.rtMu.Lock()
	defer app.rtMu.Unlock()
	st := app.loops[botID]
	if st == nil || st.interim == nil {
		return 0
	}
	return st.interim.suppressed
}

func waitBudgetSuppressed(t *testing.T, app *App, botID string, n int) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var got int
	for time.Now().Before(deadline) {
		got = budgetSuppressed(app, botID)
		if got >= n {
			return got
		}
		runtime.Gosched()
	}
	t.Fatalf("in-run suppressed %d, want >= %d", got, n)
	return got
}

func nilRefusedCount(app *App, botID string) int {
	app.rtMu.Lock()
	defer app.rtMu.Unlock()
	st := app.loops[botID]
	if st == nil {
		return 0
	}
	return st.nilRefused
}

type resetFrame struct {
	RunID  string
	Reason string
}

func resetFrames(app *App, runID string) []resetFrame {
	var out []resetFrame
	for _, f := range runFrames(app, runID) {
		if f.event != "stream_reset" {
			continue
		}
		var p struct {
			RunID  string `json:"run_id"`
			Reason string `json:"reason"`
		}
		if json.Unmarshal(f.data, &p) == nil {
			out = append(out, resetFrame{RunID: p.RunID, Reason: p.Reason})
		}
	}
	return out
}

func waitResetReason(t *testing.T, app *App, runID, reason string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range resetFrames(app, runID) {
			if r.Reason == reason {
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatalf("no stream_reset %s in %#v", reason, resetReasons(app, runID))
}

func assertNoEntered(t *testing.T, ch <-chan int) {
	t.Helper()
	select {
	case n := <-ch:
		t.Fatalf("unexpected interim %d", n)
	default:
	}
}

func separatorCount(frames []frame) int {
	n := 0
	for _, f := range frames {
		if f.event != "token" {
			continue
		}
		var p struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(f.data, &p) == nil && p.Text == "\n\n" {
			n++
		}
	}
	return n
}

func waitTokenText(t *testing.T, app *App, runID, sub string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		got = tokenText(app, runID)
		if strings.Contains(got, sub) {
			return got
		}
		runtime.Gosched()
	}
	t.Fatalf("stream %q, want substring %q", got, sub)
	return got
}

func yieldRun() {
	for i := 0; i < 10000; i++ {
		runtime.Gosched()
	}
}

func msgHas(msgs []model.Message, role, content string) bool {
	for _, m := range msgs {
		if m.Role == role && m.Content == content {
			return true
		}
	}
	return false
}

func hasPlaceholder(msgs []model.Message) bool {
	for _, m := range msgs {
		if m.Role == "tool" && m.ToolName == "run_shell" && m.Content == shellStillRunning {
			return true
		}
	}
	return false
}

func runFrames(app *App, runID string) []frame {
	hist, ch := app.bus.Subscribe(runID)
	app.bus.Unsubscribe(runID, ch)
	return hist
}

func eventNames(app *App, runID string) []string {
	hist := runFrames(app, runID)
	names := make([]string, len(hist))
	for i, f := range hist {
		names[i] = f.event
	}
	return names
}

func tokenText(app *App, runID string) string {
	var b strings.Builder
	for _, f := range runFrames(app, runID) {
		if f.event != "token" {
			continue
		}
		var p struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(f.data, &p) == nil {
			b.WriteString(p.Text)
		}
	}
	return b.String()
}

func resetReasons(app *App, runID string) []string {
	var out []string
	for _, f := range runFrames(app, runID) {
		if f.event != "stream_reset" {
			continue
		}
		var p struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(f.data, &p) == nil {
			out = append(out, p.Reason)
		}
	}
	return out
}

func waitRunID(t *testing.T, app *App, runID, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		run, err := app.st.GetRun(runID)
		if err != nil {
			t.Fatal(err)
		}
		last = run.Status
		if run.Status == want {
			return
		}
		select {
		case <-time.After(15 * time.Millisecond):
		}
	}
	t.Fatalf("run status %s, want %s", last, want)
}

// TestAsyncShellInterimWhileToolRuns is the flag-on path: one quiet window
// produces one tool-less call, its tokens are streamed, and the shell's
// context stays live the whole time.
func TestAsyncShellInterimWhileToolRuns(t *testing.T) {
	m := newAsyncModel("run_shell", "still going", "final answer", true)
	m.hold = make(chan struct{})
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app, base, bot, runID := startShellRun(t, "Loop", true, clk, m, tool)
	waitCh(t, tool.started, "tool start")
	if !wakeInstalled(app, bot.ID) {
		t.Fatal("wake hook was not installed for run_shell")
	}
	if err := tool.context().Err(); err != nil {
		t.Fatalf("tool ctx before message: %v", err)
	}
	postUser(t, base, bot.ID, "one")
	if err := tool.context().Err(); err != nil {
		t.Fatalf("tool ctx after message: %v", err)
	}
	clk.Advance(499 * time.Millisecond)
	select {
	case n := <-m.entered:
		t.Fatalf("interim fired at 499ms: %d", n)
	default:
	}
	if len(m.snapshot()) != 1 {
		t.Fatalf("model calls at 499ms: %d", len(m.snapshot()))
	}
	if err := tool.context().Err(); err != nil {
		t.Fatalf("tool ctx at 499ms: %v", err)
	}
	clk.Advance(time.Millisecond)
	if n := waitN(t, m.entered, "interim"); n != 1 {
		t.Fatalf("interim index %d", n)
	}
	batches := eventLoopBatchCounts(t, app, bot.ID)
	if len(batches) != 1 || batches[0] != 1 {
		t.Fatalf("event_loop_batch %#v, want [1]", batches)
	}
	reqs := m.snapshot()
	if len(reqs) != 2 {
		t.Fatalf("model calls = %d, want 2", len(reqs))
	}
	interim := reqs[1]
	if interim.Tools != nil {
		t.Fatalf("interim tools %#v", interim.Tools)
	}
	first := reqs[0]
	if interim.Model != first.Model ||
		interim.FirstOutputTimeout != first.FirstOutputTimeout ||
		interim.StallTimeout != first.StallTimeout ||
		!reflect.DeepEqual(interim.KeepAlive, first.KeepAlive) {
		t.Fatalf("interim limits model=%s first=%s stall=%s keep=%v; main model=%s first=%s stall=%s keep=%v",
			interim.Model, interim.FirstOutputTimeout, interim.StallTimeout, interim.KeepAlive,
			first.Model, first.FirstOutputTimeout, first.StallTimeout, first.KeepAlive)
	}
	if !hasPlaceholder(interim.Messages) || !msgHas(interim.Messages, "user", "one") {
		t.Fatalf("interim transcript %#v", interim.Messages)
	}
	if tool.finished() {
		t.Fatal("tool finished while the interim was running")
	}
	if err := tool.context().Err(); err != nil {
		t.Fatalf("tool ctx during interim: %v", err)
	}
	ctxs := m.contexts()
	if len(ctxs) != 1 || ctxs[0].Err() != nil {
		t.Fatalf("interim ctx %v", ctxs)
	}
	close(m.hold)
	if n := waitN(t, m.returned, "interim return"); n != 1 {
		t.Fatalf("returned %d", n)
	}
	if err := tool.context().Err(); err != nil {
		t.Fatalf("tool ctx after interim: %v", err)
	}
	if tool.finished() {
		t.Fatal("tool finished when the interim returned")
	}
	rows := waitInterimRows(t, app, bot.ID, 1)
	if len(rows) != 1 || !rows[0].OK || rows[0].Superseded {
		t.Fatalf("clean interim log %+v", rows)
	}
	if got := waitTokenText(t, app, runID, "still going\n\n"); strings.Contains(got, "final answer") {
		t.Fatalf("final reply streamed before the tool finished: %q", got)
	}
	if tool.finished() {
		t.Fatal("tool finished before the interim separator")
	}
	tool.letGo()
	waitIdle(t, base, bot.ID, "")
	if !strings.Contains(tokenText(app, runID), "still going\n\n") {
		t.Fatalf("separator missing in %q", tokenText(app, runID))
	}
	if reasons := resetReasons(app, runID); len(reasons) != 0 {
		t.Fatalf("reset %#v", reasons)
	}
	got := fetchBot(t, base, bot.ID)
	if got.LastRunStatus != "done" {
		t.Fatalf("status %s %s", got.LastRunStatus, got.LastRunError)
	}
	reqs = m.snapshot()
	if len(m.contexts()) != 1 {
		t.Fatalf("interim calls %d", len(m.contexts()))
	}
	last := reqs[len(reqs)-1]
	if last.Tools == nil || hasPlaceholder(last.Messages) || !msgHas(last.Messages, "user", "one") {
		t.Fatalf("final request tools-nil %v %#v", last.Tools == nil, last.Messages)
	}
	if !msgHas(last.Messages, "tool", "shell-ok") {
		t.Fatalf("final tool result %#v", last.Messages)
	}
	if n, _ := app.st.LogCount("run_started"); n != 1 {
		t.Fatalf("run_started %d", n)
	}
}

// TestAsyncShellSupersedeCancelsInterimOnly starts a second batch while the
// first interim call is still blocked. Only that call's context is cancelled.
func TestAsyncShellSupersedeCancelsInterimOnly(t *testing.T) {
	m := newAsyncModel("run_shell", "first pass", "final answer", true)
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app, base, bot, runID := startShellRun(t, "Supersede", true, clk, m, tool)
	waitCh(t, tool.started, "tool start")
	postUser(t, base, bot.ID, "one")
	clk.Advance(500 * time.Millisecond)
	if n := waitN(t, m.entered, "first interim"); n != 1 {
		t.Fatalf("first interim %d", n)
	}
	postUser(t, base, bot.ID, "two")
	clk.Advance(500 * time.Millisecond)
	if n := waitN(t, m.entered, "second interim"); n != 2 {
		t.Fatalf("second interim %d", n)
	}
	ctxs := m.contexts()
	if len(ctxs) != 2 {
		t.Fatalf("interim ctxs %d", len(ctxs))
	}
	if ctxs[0].Err() == nil || ctxs[1].Err() != nil {
		t.Fatalf("first %v second %v", ctxs[0].Err(), ctxs[1].Err())
	}
	if err := tool.context().Err(); err != nil {
		t.Fatalf("tool ctx %v", err)
	}
	if tool.finished() {
		t.Fatal("tool finished during supersede")
	}
	reqs := m.snapshot()
	if len(reqs) < 3 {
		t.Fatalf("requests %d", len(reqs))
	}
	if reqs[1].Tools != nil || !hasPlaceholder(reqs[1].Messages) || !msgHas(reqs[1].Messages, "user", "one") || msgHas(reqs[1].Messages, "user", "two") {
		t.Fatalf("first interim %#v", reqs[1].Messages)
	}
	if reqs[2].Tools != nil || !hasPlaceholder(reqs[2].Messages) || !msgHas(reqs[2].Messages, "user", "one") || !msgHas(reqs[2].Messages, "user", "two") {
		t.Fatalf("second interim %#v", reqs[2].Messages)
	}
	reasons := resetReasons(app, runID)
	if len(reasons) != 1 || reasons[0] != "interim_superseded" {
		t.Fatalf("reset %#v", reasons)
	}
	rows := waitInterimRows(t, app, bot.ID, 1)
	if rows[0].OK || !rows[0].Superseded {
		t.Fatalf("superseded interim log %+v", rows)
	}
	tool.letGo()
	waitIdle(t, base, bot.ID, "")
}

func TestAsyncShellToolResultThenFold(t *testing.T) {
	m := newAsyncModel("run_shell", "while it runs", "final answer", false)
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app, base, bot, runID := startShellRun(t, "Folded", true, clk, m, tool)
	waitCh(t, tool.started, "tool start")
	postUser(t, base, bot.ID, "one")
	postUser(t, base, bot.ID, "two")
	clk.Advance(500 * time.Millisecond)
	if n := waitN(t, m.entered, "interim"); n != 1 {
		t.Fatalf("interim %d", n)
	}
	reqs := m.snapshot()
	if len(reqs) != 2 || reqs[1].Tools != nil {
		t.Fatalf("interim request %#v", reqs)
	}
	if !hasPlaceholder(reqs[1].Messages) || !msgHas(reqs[1].Messages, "user", "one") || !msgHas(reqs[1].Messages, "user", "two") {
		t.Fatalf("interim messages %#v", reqs[1].Messages)
	}
	if err := tool.context().Err(); err != nil || tool.finished() {
		t.Fatalf("tool err %v finished %v", tool.context().Err(), tool.finished())
	}
	tool.letGo()
	waitIdle(t, base, bot.ID, "")
	got := fetchBot(t, base, bot.ID)
	if got.LastRunStatus != "done" {
		t.Fatalf("status %s %s", got.LastRunStatus, got.LastRunError)
	}
	run, err := app.st.GetRun(runID)
	if err != nil || run.Status != "done" {
		t.Fatalf("run %v %v", run.Status, err)
	}
	reqs = m.snapshot()
	var final model.ChatRequest
	for _, req := range reqs {
		if req.Tools != nil {
			final = req
		}
	}
	assertShellTail(t, final.Messages, "shell-ok", "one", "two")
	if len(m.contexts()) != 1 {
		t.Fatalf("interim calls %d", len(m.contexts()))
	}
	if n, _ := app.st.LogCount("run_started"); n != 1 {
		t.Fatalf("run_started %d", n)
	}
}

func assertShellTail(t *testing.T, msgs []model.Message, result, u1, u2 string) {
	t.Helper()
	idx := -1
	for i, m := range msgs {
		if m.Role == "assistant" && len(m.ToolCalls) > 0 {
			idx = i
		}
	}
	if idx < 0 || idx+3 >= len(msgs) {
		t.Fatalf("tail missing from %#v", msgs)
	}
	if msgs[idx].ToolCalls[0].Name != "run_shell" {
		t.Fatalf("call %#v", msgs[idx].ToolCalls)
	}
	tool := msgs[idx+1]
	if tool.Role != "tool" || tool.ToolName != "run_shell" || tool.Content != result {
		t.Fatalf("tool message %#v", tool)
	}
	if msgs[idx+2].Role != "user" || msgs[idx+2].Content != u1 || msgs[idx+3].Role != "user" || msgs[idx+3].Content != u2 {
		t.Fatalf("users %#v %#v", msgs[idx+2], msgs[idx+3])
	}
	if hasPlaceholder(msgs) {
		t.Fatalf("placeholder in %#v", msgs)
	}
}

func TestAsyncShellStopCancelsToolAndInterim(t *testing.T) {
	m := newAsyncModel("run_shell", "partial", "final answer", true)
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app, base, bot, runID := startShellRun(t, "Stop", true, clk, m, tool)
	waitCh(t, tool.started, "tool start")
	postUser(t, base, bot.ID, "one")
	clk.Advance(500 * time.Millisecond)
	if n := waitN(t, m.entered, "interim"); n != 1 {
		t.Fatalf("interim %d", n)
	}
	res, body := do(t, "POST", base+"/api/bots/"+bot.ID+"/runs/"+runID+"/cancel", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("cancel %d %s", res.StatusCode, body)
	}
	waitCh(t, tool.done, "tool join")
	if n := waitN(t, m.returned, "interim join"); n != 1 {
		t.Fatalf("interim join %d", n)
	}
	if tool.context().Err() == nil {
		t.Fatal("tool ctx still live after stop")
	}
	ctxs := m.contexts()
	if len(ctxs) != 1 || ctxs[0].Err() == nil {
		t.Fatalf("interim ctx %#v", ctxs)
	}
	waitRunID(t, app, runID, "cancelled")
	if reasons := resetReasons(app, runID); len(reasons) != 0 {
		t.Fatalf("reset %#v", reasons)
	}
}

func TestAsyncShellFlagOffMatchesSync(t *testing.T) {
	baseReqs, baseEvents := runFlagOff(t, false)
	clkReqs, clkEvents := runFlagOff(t, true)
	if diff := transcriptsDiffer(baseReqs, clkReqs); diff != "" {
		t.Fatal(diff)
	}
	if !reflect.DeepEqual(baseEvents, clkEvents) {
		t.Fatalf("events\nbase %v\nclock %v", baseEvents, clkEvents)
	}
}

func runFlagOff(t *testing.T, clock bool) ([]model.ChatRequest, []string) {
	t.Helper()
	m := newAsyncModel("run_shell", "should-not-run", "final answer", false)
	tool := newGateTool("SYNC-OUT")
	var clk *manualClock
	if clock {
		clk = newManualClock()
	}
	app, base, bot, runID := startShellRun(t, "Sync", false, clk, m, tool)
	if app.pol().EventLoopEnabled() {
		t.Fatal("event loop defaulted on")
	}
	waitCh(t, tool.started, "tool start")
	if wakeInstalled(app, bot.ID) {
		t.Fatal("wake hook installed while the flag is off")
	}
	postUser(t, base, bot.ID, "mid")
	if clk != nil {
		clk.Advance(2 * time.Second)
	}
	if wakeInstalled(app, bot.ID) {
		t.Fatal("wake hook appeared after a message")
	}
	if len(m.snapshot()) != 1 {
		t.Fatalf("model calls during the tool: %d", len(m.snapshot()))
	}
	tool.letGo()
	waitIdle(t, base, bot.ID, "")
	reqs := m.snapshot()
	for i, req := range reqs {
		if req.Tools == nil {
			t.Fatalf("request %d has nil tools", i)
		}
		if hasPlaceholder(req.Messages) || msgHas(req.Messages, "assistant", "should-not-run") {
			t.Fatalf("request %d looks like an interim %#v", i, req.Messages)
		}
	}
	for _, kind := range []string{"event_loop_batch", "event_loop_interim", "event_loop_interim_capped", "event_loop_interim_capped_suppressed", "event_loop_interim_refused"} {
		ev, err := app.st.ListLog(bot.ID, kind, "", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(ev) != 0 {
			t.Fatalf("%s rows %d", kind, len(ev))
		}
	}
	return reqs, eventNames(app, runID)
}

var currentTimeLine = regexp.MustCompile(`Current time: [^\n]*`)

func transcriptsDiffer(a, b []model.ChatRequest) string {
	if len(a) != len(b) {
		return fmt.Sprintf("request count %d vs %d", len(a), len(b))
	}
	for i := range a {
		am := normMessages(a[i].Messages)
		bm := normMessages(b[i].Messages)
		if !reflect.DeepEqual(am, bm) {
			return fmt.Sprintf("request %d\n%s\n---\n%s", i, briefMsgs(am), briefMsgs(bm))
		}
	}
	return ""
}

func briefMsgs(msgs []model.Message) string {
	var b strings.Builder
	for i, m := range msgs {
		text := m.Content
		if len(text) > 120 {
			text = text[:120] + "..."
		}
		fmt.Fprintf(&b, "%d %s %s", i, m.Role, text)
		if m.ToolName != "" {
			fmt.Fprintf(&b, " tool=%s", m.ToolName)
		}
		for _, c := range m.ToolCalls {
			fmt.Fprintf(&b, " call=%s", c.Name)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func normMessages(msgs []model.Message) []model.Message {
	out := make([]model.Message, len(msgs))
	for i, m := range msgs {
		m.Content = currentTimeLine.ReplaceAllString(m.Content, "Current time: TIME.")
		out[i] = m
	}
	return out
}

func TestAsyncShellOtherToolStaysSync(t *testing.T) {
	m := newAsyncModel("list_bots", "nope", "listed", false)
	tool := newGateTool("bot-list")
	clk := newManualClock()
	app, base, bot, _ := startShellRun(t, "Other", true, clk, m, tool)
	waitCh(t, tool.started, "tool start")
	if wakeInstalled(app, bot.ID) {
		t.Fatal("non-shell tool installed a wake hook")
	}
	if err := tool.context().Err(); err != nil {
		t.Fatal(err)
	}
	postUser(t, base, bot.ID, "later")
	clk.Advance(2 * time.Second)
	if len(m.snapshot()) != 1 {
		t.Fatalf("model calls while the tool blocked the run: %d", len(m.snapshot()))
	}
	if wakeInstalled(app, bot.ID) {
		t.Fatal("wake hook appeared for a non-shell tool")
	}
	tool.letGo()
	waitIdle(t, base, bot.ID, "")
	reqs := m.snapshot()
	if len(reqs) != 2 {
		t.Fatalf("model calls %d, want 2", len(reqs))
	}
	for i, req := range reqs {
		if req.Tools == nil || hasPlaceholder(req.Messages) {
			t.Fatalf("request %d tools-nil %v placeholder %v", i, req.Tools == nil, hasPlaceholder(req.Messages))
		}
	}
	if !msgHas(reqs[1].Messages, "user", "later") || !msgHas(reqs[1].Messages, "tool", "bot-list") {
		t.Fatalf("final transcript %#v", reqs[1].Messages)
	}
	ev, err := app.st.ListLog(bot.ID, "event_loop_interim", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 0 {
		t.Fatalf("interim rows %d", len(ev))
	}
}

func TestAsyncShellApprovalSuspends(t *testing.T) {
	const cmd = "echo RAN_ONCE"
	r, _ := newResumeRig(t, "", cmd, "continued after approve", nil)
	r.app.editPol(func(p *policy.Policy) { p.EventLoop = true })
	if !r.app.pol().EventLoopEnabled() {
		t.Fatal("event loop flag did not publish")
	}
	r.post("go")
	card := r.waitCard()
	if card.Tool != "shell" || card.RunID == "" {
		t.Fatalf("card %+v", card)
	}
	bot := r.httpBot()
	if bot.LastRunStatus != "waiting" || bot.WaitingTool != "run_shell" {
		t.Fatalf("waiting status %s tool %q", bot.LastRunStatus, bot.WaitingTool)
	}
	if r.modelCalls() != 1 {
		t.Fatalf("model calls %d", r.modelCalls())
	}
	if strings.Contains(r.joinedBodies(), shellStillRunning) {
		t.Fatal("placeholder was sent to the model")
	}
}

func TestAsyncShellInterimTranscript(t *testing.T) {
	msgs := []model.Message{
		{Role: "user", Content: "start"},
		{Role: "assistant", ToolCalls: []model.ToolCall{
			{Name: "list_bots"},
			{Name: "run_shell", Arguments: map[string]any{"command": "ls"}},
			{Name: "read_file"},
		}},
		{Role: "tool", ToolName: "list_bots", Content: "bots"},
	}
	fresh := []model.Message{{Role: "user", Content: "hello"}}
	out := interimTranscript(msgs, 1, fresh)
	if len(out) != 5 {
		t.Fatalf("len %d %#v", len(out), out)
	}
	if out[0].Content != "start" || len(out[1].ToolCalls) != 2 || out[1].ToolCalls[0].Name != "list_bots" || out[1].ToolCalls[1].Name != "run_shell" {
		t.Fatalf("head %#v", out[:2])
	}
	out[1].ToolCalls[0].Name = "changed"
	if msgs[1].ToolCalls[0].Name != "list_bots" || len(msgs[1].ToolCalls) != 3 {
		t.Fatal("live tool calls were aliased")
	}
	if out[2].Role != "tool" || out[2].Content != "bots" {
		t.Fatalf("completed tool %#v", out[2])
	}
	if out[3].Role != "tool" || out[3].ToolName != "run_shell" || out[3].Content != shellStillRunning {
		t.Fatalf("placeholder %#v", out[3])
	}
	if out[4].Role != "user" || out[4].Content != "hello" {
		t.Fatalf("fresh %#v", out[4])
	}
	if len(msgs) != 3 {
		t.Fatalf("live transcript len %d", len(msgs))
	}
}

// TestAsyncShellWakeHookIgnoresOtherRun pins the installed wake closure to
// this run id and loop generation. A notify with a different id or gen
// must not arm the quiet window.
func TestAsyncShellWakeHookIgnoresOtherRun(t *testing.T) {
	m := newAsyncModel("run_shell", "still going", "final answer", false)
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app, base, bot, runID := startShellRun(t, "WakeID", true, clk, m, tool)
	waitCh(t, tool.started, "tool start")
	if !wakeInstalled(app, bot.ID) {
		t.Fatal("wake hook was not installed for run_shell")
	}
	wake, gotRun, gen := installedWake(app, bot.ID)
	if wake == nil || gotRun != runID {
		t.Fatalf("wake=%v run=%s want %s gen=%d", wake != nil, gotRun, runID, gen)
	}

	wake("other-"+runID, gen)
	wake(runID, gen+1)
	clk.Advance(app.pol().EffectiveEventLoopMaxWait() + time.Millisecond)
	yieldRun()
	if got := eventLoopBatchCounts(t, app, bot.ID); len(got) != 0 {
		t.Fatalf("stale wake produced batches %v", got)
	}
	select {
	case n := <-m.entered:
		t.Fatalf("stale wake started interim %d", n)
	default:
	}
	if len(m.snapshot()) != 1 {
		t.Fatalf("model calls after stale wake: %d", len(m.snapshot()))
	}

	postUser(t, base, bot.ID, "one")
	clk.Advance(500 * time.Millisecond)
	if n := waitN(t, m.entered, "first interim"); n != 1 {
		t.Fatalf("interim index %d", n)
	}
	batches := eventLoopBatchCounts(t, app, bot.ID)
	if len(batches) != 1 || batches[0] != 1 {
		t.Fatalf("first live batch %#v, want [1]", batches)
	}
	interims := toolsNilReqs(m.snapshot())
	if len(interims) != 1 || !msgHas(interims[0].Messages, "user", "one") {
		t.Fatalf("first interim %#v", interims)
	}
	if n := waitN(t, m.returned, "first interim return"); n != 1 {
		t.Fatalf("returned %d", n)
	}

	wake(runID, gen)
	clk.Advance(500 * time.Millisecond)
	batches = waitBatchRows(t, app, bot.ID, 2)
	if len(batches) != 2 {
		t.Fatalf("correct wake batches %#v", batches)
	}
	yieldRun()
	select {
	case n := <-m.entered:
		t.Fatalf("correct wake with no new input started interim %d", n)
	default:
	}

	tool.letGo()
	waitIdle(t, base, bot.ID, "")
	if len(m.contexts()) != 1 {
		t.Fatalf("interim calls %d", len(m.contexts()))
	}
}

// TestAsyncShellToolFinishJoinsPendingInterim requires the in-flight
// interim to be cancelled and joined before the final tools-bearing
// model call starts.
func TestAsyncShellToolFinishJoinsPendingInterim(t *testing.T) {
	m := newAsyncModel("run_shell", "still going", "final answer", true)
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app, base, bot, runID := startShellRun(t, "Join", true, clk, m, tool)
	waitCh(t, tool.started, "tool start")
	postUser(t, base, bot.ID, "one")
	clk.Advance(500 * time.Millisecond)
	if n := waitN(t, m.entered, "interim"); n != 1 {
		t.Fatalf("interim index %d", n)
	}
	if len(m.contexts()) != 1 || m.contexts()[0].Err() != nil {
		t.Fatalf("interim ctx before tool finish %#v", m.contexts())
	}

	tool.letGo()
	waitCh(t, tool.done, "tool join")
	waitIdle(t, base, bot.ID, "")

	snap := m.joinAtFinal()
	if !snap.recorded {
		t.Fatal("final tools call did not observe an earlier interim")
	}
	if !snap.cancelled {
		t.Fatal("final call started before the interim ctx was cancelled")
	}
	if !snap.returned {
		t.Fatal("final call started before the interim Chat returned")
	}
	entered, returned := m.interimCounts()
	if entered != returned || entered != 1 {
		t.Fatalf("entered %d returned %d", entered, returned)
	}
	got := fetchBot(t, base, bot.ID)
	if got.LastRunStatus != "done" {
		t.Fatalf("status %s %s", got.LastRunStatus, got.LastRunError)
	}
	if reasons := resetReasons(app, runID); len(reasons) != 0 {
		t.Fatalf("reset %#v", reasons)
	}
}

// TestAsyncShellBatchWithoutNewInputMakesNoInterim pins that a wake with
// no uncovered turn input still logs a batch and does not start a call.
func TestAsyncShellBatchWithoutNewInputMakesNoInterim(t *testing.T) {
	m := newAsyncModel("run_shell", "still going", "final answer", false)
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app, base, bot, runID := startShellRun(t, "EmptyBatch", true, clk, m, tool)
	waitCh(t, tool.started, "tool start")
	wake, gotRun, gen := installedWake(app, bot.ID)
	if wake == nil || gotRun != runID {
		t.Fatalf("wake=%v run=%s want %s", wake != nil, gotRun, runID)
	}

	postUser(t, base, bot.ID, "one")
	clk.Advance(500 * time.Millisecond)
	if n := waitN(t, m.entered, "first interim"); n != 1 {
		t.Fatalf("interim index %d", n)
	}
	if n := waitN(t, m.returned, "first interim return"); n != 1 {
		t.Fatalf("returned %d", n)
	}
	if got := eventLoopBatchCounts(t, app, bot.ID); len(got) != 1 {
		t.Fatalf("batches after first interim %#v", got)
	}

	wake(runID, gen)
	clk.Advance(500 * time.Millisecond)
	batches := waitBatchRows(t, app, bot.ID, 2)
	if len(batches) != 2 {
		t.Fatalf("empty-input batches %#v", batches)
	}
	yieldRun()
	select {
	case n := <-m.entered:
		t.Fatalf("empty-input batch started interim %d", n)
	default:
	}

	postUser(t, base, bot.ID, "two")
	clk.Advance(500 * time.Millisecond)
	if n := waitN(t, m.entered, "second interim"); n != 2 {
		t.Fatalf("next interim %d, want 2", n)
	}
	interims := toolsNilReqs(m.snapshot())
	if len(interims) < 2 || !msgHas(interims[1].Messages, "user", "two") {
		t.Fatalf("second interim %#v", interims)
	}

	tool.letGo()
	waitIdle(t, base, bot.ID, "")
	if len(m.contexts()) != 2 {
		t.Fatalf("interim calls %d, want 2", len(m.contexts()))
	}
}

// TestAsyncShellStopWhileOnlyToolRunning cancels a live shell before any
// interim has started. The tool and the run end; the model is not called again.
func TestAsyncShellStopWhileOnlyToolRunning(t *testing.T) {
	m := newAsyncModel("run_shell", "should-not-run", "final answer", false)
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app, base, bot, runID := startShellRun(t, "StopTool", true, clk, m, tool)
	waitCh(t, tool.started, "tool start")
	if !wakeInstalled(app, bot.ID) {
		t.Fatal("wake hook was not installed for run_shell")
	}
	if len(m.snapshot()) != 1 {
		t.Fatalf("model calls before stop: %d", len(m.snapshot()))
	}

	res, body := do(t, "POST", base+"/api/bots/"+bot.ID+"/runs/"+runID+"/cancel", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("cancel %d %s", res.StatusCode, body)
	}
	waitCh(t, tool.done, "tool join")
	if tool.context().Err() == nil {
		t.Fatal("tool ctx still live after stop")
	}
	waitRunID(t, app, runID, "cancelled")
	if len(m.snapshot()) != 1 {
		t.Fatalf("model calls after stop: %d", len(m.snapshot()))
	}
	if len(m.contexts()) != 0 {
		t.Fatalf("interim calls %d", len(m.contexts()))
	}
}

func TestAsyncShellMaxInterimDefaults(t *testing.T) {
	if defaultEventLoopMaxInterim != 5 {
		t.Fatalf("defaultEventLoopMaxInterim = %d, want 5", defaultEventLoopMaxInterim)
	}
	var none *App
	if none.maxInterim() != defaultEventLoopMaxInterim {
		t.Fatalf("nil app %d", none.maxInterim())
	}
	app := &App{}
	if app.maxInterim() != defaultEventLoopMaxInterim {
		t.Fatalf("default %d", app.maxInterim())
	}
	app.eventLoopMaxInterim = 2
	if app.maxInterim() != 2 {
		t.Fatalf("override %d", app.maxInterim())
	}
	app.eventLoopMaxInterim = -1
	if app.maxInterim() != defaultEventLoopMaxInterim {
		t.Fatalf("negative %d", app.maxInterim())
	}
}

func TestAsyncShellInterimCap(t *testing.T) {
	m := newAsyncModel("run_shell", "mid", "final answer", true)
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app := newApp(t, "", m)
	app.editPol(func(p *policy.Policy) { p.EventLoop = true })
	if !app.pol().EventLoopEnabled() {
		t.Fatal("event loop flag did not publish")
	}
	app.eventClk = clk
	app.eventLoopMaxInterim = 2
	app.toolExec = tool.exec
	t.Cleanup(tool.letGo)
	srv := serve(t, app)
	base := srv.URL
	bot := createBot(t, base, "Cap")
	runID := postUser(t, base, bot.ID, "go")
	if runID == "" {
		t.Fatal("no run")
	}
	waitCh(t, tool.started, "tool start")

	postUser(t, base, bot.ID, "one")
	clk.Advance(500 * time.Millisecond)
	if n := waitN(t, m.entered, "first interim"); n != 1 {
		t.Fatalf("first interim %d", n)
	}
	postUser(t, base, bot.ID, "two")
	clk.Advance(500 * time.Millisecond)
	if n := waitN(t, m.entered, "second interim"); n != 2 {
		t.Fatalf("second interim %d", n)
	}
	if n := waitN(t, m.returned, "first interim joined"); n != 1 {
		t.Fatalf("first join %d", n)
	}

	postUser(t, base, bot.ID, "three")
	clk.Advance(500 * time.Millisecond)
	caps := waitInterimCaps(t, app, bot.ID, 1)
	if batches := eventLoopBatchCounts(t, app, bot.ID); len(batches) != 2 {
		t.Fatalf("batches %#v, want 2", batches)
	}
	if got := waitBudgetSuppressed(t, app, bot.ID, 1); got != 1 {
		t.Fatalf("suppressed in run %d, want 1", got)
	}
	if len(eventLoopInterimSuppressed(t, app, bot.ID)) != 0 {
		t.Fatal("suppressed row before the shell ended")
	}
	// A second skipped batch cannot start an interim until the first cap
	// path has returned, so a cancel in that path is visible here. The
	// second skip needs new input; a wake with none is not counted.
	wake, gotRun, gen := installedWake(app, bot.ID)
	if wake == nil || gotRun != runID || gen == 0 {
		t.Fatalf("wake=%v run=%s gen=%d", wake != nil, gotRun, gen)
	}
	postUser(t, base, bot.ID, "four")
	clk.Advance(500 * time.Millisecond)
	if got := waitBudgetSuppressed(t, app, bot.ID, 2); got != 2 {
		t.Fatalf("suppressed in run %d, want 2", got)
	}
	if batches := eventLoopBatchCounts(t, app, bot.ID); len(batches) != 2 {
		t.Fatalf("batches after cap %#v, want 2", batches)
	}
	caps = eventLoopInterimCaps(t, app, bot.ID)
	if len(caps) != 1 {
		t.Fatalf("capped rows %d, want 1 (%+v)", len(caps), caps)
	}
	// Refusal only happens when starts >= cap, so count always equals cap.
	if caps[0].Cap != 2 || caps[0].Count != 2 || caps[0].RunID != runID {
		t.Fatalf("cap row %+v", caps[0])
	}
	if got := toolsNilReqs(m.snapshot()); len(got) != 2 {
		t.Fatalf("interim calls %d", len(got))
	}
	ctxs := m.contexts()
	if len(ctxs) != 2 || ctxs[1].Err() != nil {
		t.Fatalf("in-flight interim cancelled at the cap: %v", ctxErrs(ctxs))
	}
	select {
	case n := <-m.returned:
		t.Fatalf("cap cancelled in-flight interim %d", n)
	default:
	}
	assertNoEntered(t, m.entered)

	tool.letGo()
	waitIdle(t, base, bot.ID, "")
	if got := toolsNilReqs(m.snapshot()); len(got) != 2 {
		t.Fatalf("interim calls after finish %d", len(got))
	}
	supp := waitInterimSuppressed(t, app, bot.ID, 1)
	if len(supp) != 1 || supp[0].Suppressed != 2 || supp[0].Count != 2 || supp[0].Cap != 2 || supp[0].RunID != runID {
		t.Fatalf("suppressed %+v", supp)
	}
	if got := eventLoopInterimCaps(t, app, bot.ID); len(got) != 1 {
		t.Fatalf("capped rows after finish %d", len(got))
	}
	reqs := m.snapshot()
	last := reqs[len(reqs)-1]
	if last.Tools == nil {
		t.Fatal("final request has no tools")
	}
	assertUsersAfterTool(t, last.Messages, "shell-ok", "one", "two", "three", "four")
}

func ctxErrs(ctxs []context.Context) []error {
	out := make([]error, len(ctxs))
	for i, c := range ctxs {
		if c != nil {
			out[i] = c.Err()
		}
	}
	return out
}

func assertUsersAfterTool(t *testing.T, msgs []model.Message, result string, users ...string) {
	t.Helper()
	idx := -1
	for i, m := range msgs {
		if m.Role == "assistant" && len(m.ToolCalls) > 0 {
			idx = i
		}
	}
	if idx < 0 || idx+1+len(users) >= len(msgs) {
		t.Fatalf("tail missing from %#v", msgs)
	}
	tool := msgs[idx+1]
	if tool.Role != "tool" || tool.ToolName != "run_shell" || tool.Content != result {
		t.Fatalf("tool message %#v", tool)
	}
	for i, u := range users {
		m := msgs[idx+2+i]
		if m.Role != "user" || m.Content != u {
			t.Fatalf("user %d %#v", i, m)
		}
	}
	if hasPlaceholder(msgs) {
		t.Fatalf("placeholder in %#v", msgs)
	}
}

func newStreamingInterim(interim, final string) *asyncModel {
	m := newAsyncModel("run_shell", interim, final, true)
	m.tokensFirst = true
	m.tokensOut = make(chan struct{})
	return m
}

func tokenIndex(frames []frame, text string) int {
	for i, f := range frames {
		if f.event != "token" {
			continue
		}
		var p struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(f.data, &p) == nil && strings.Contains(p.Text, text) {
			return i
		}
	}
	return -1
}

func resetIndex(frames []frame, reason string) int {
	for i, f := range frames {
		if f.event != "stream_reset" {
			continue
		}
		var p struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(f.data, &p) == nil && p.Reason == reason {
			return i
		}
	}
	return -1
}

func TestAsyncShellToolFinishMidInterimResetsStream(t *testing.T) {
	const interim = "partial reply"
	const final = "final answer"
	m := newStreamingInterim(interim, final)
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app, base, bot, runID := startShellRun(t, "ResetFinish", true, clk, m, tool)
	waitCh(t, tool.started, "tool start")
	postUser(t, base, bot.ID, "one")
	clk.Advance(500 * time.Millisecond)
	if n := waitN(t, m.entered, "interim"); n != 1 {
		t.Fatalf("interim %d", n)
	}
	waitCh(t, m.tokensOut, "interim tokens")
	if !strings.Contains(tokenText(app, runID), interim) {
		t.Fatalf("stream before finish %q", tokenText(app, runID))
	}
	tool.letGo()
	waitIdle(t, base, bot.ID, "")

	reasons := resetReasons(app, runID)
	if strings.Contains(strings.Join(reasons, ","), "interim_superseded") {
		t.Fatalf("reset %#v", reasons)
	}
	frames := runFrames(app, runID)
	resetAt := resetIndex(frames, "interim_cancelled")
	partialAt := tokenIndex(frames, interim)
	finalAt := tokenIndex(frames, final)
	if resetAt < 0 || partialAt < 0 || finalAt < 0 || partialAt > resetAt || finalAt < resetAt {
		t.Fatalf("partial %d reset %d final %d reasons %#v", partialAt, resetAt, finalAt, reasons)
	}
	for i, f := range frames {
		if f.event != "token" || i > resetAt {
			continue
		}
		var p struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(f.data, &p) == nil && strings.Contains(p.Text, final) {
			t.Fatalf("final token before reset at %d", i)
		}
	}

	msgs, err := app.st.ListMessages(bot.ID, "user", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	bots := 0
	for _, msg := range msgs {
		if strings.Contains(msg.Content, interim) || strings.Contains(msg.Content, shellStillRunning) {
			t.Fatalf("stored %#v", msg)
		}
		if msg.Role == "bot" {
			bots++
			if msg.Content != final {
				t.Fatalf("bot reply %q", msg.Content)
			}
		}
	}
	if bots != 1 {
		t.Fatalf("bot messages %d", bots)
	}
	reqs := m.snapshot()
	last := reqs[len(reqs)-1]
	if last.Tools == nil || hasPlaceholder(last.Messages) {
		t.Fatalf("final request tools-nil %v placeholder %v", last.Tools == nil, hasPlaceholder(last.Messages))
	}
	for _, msg := range last.Messages {
		if strings.Contains(msg.Content, interim) || msg.Content == final {
			t.Fatalf("final request contains interim or the reply %#v", msg)
		}
	}
	if separatorToken(frames) {
		t.Fatal("blank-line separator published with interim_cancelled")
	}
}

func TestAsyncShellStopMidInterimResetsStream(t *testing.T) {
	const interim = "partial reply"
	m := newStreamingInterim(interim, "final answer")
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app, base, bot, runID := startShellRun(t, "ResetStop", true, clk, m, tool)
	waitCh(t, tool.started, "tool start")
	postUser(t, base, bot.ID, "one")
	clk.Advance(500 * time.Millisecond)
	if n := waitN(t, m.entered, "interim"); n != 1 {
		t.Fatalf("interim %d", n)
	}
	waitCh(t, m.tokensOut, "interim tokens")
	res, body := do(t, "POST", base+"/api/bots/"+bot.ID+"/runs/"+runID+"/cancel", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("cancel %d %s", res.StatusCode, body)
	}
	waitCh(t, tool.done, "tool join")
	if n := waitN(t, m.returned, "interim join"); n != 1 {
		t.Fatalf("interim join %d", n)
	}
	waitRunID(t, app, runID, "cancelled")
	if tool.context().Err() == nil {
		t.Fatal("tool ctx still live after stop")
	}
	ctxs := m.contexts()
	if len(ctxs) != 1 || ctxs[0].Err() == nil {
		t.Fatalf("interim ctx %#v", ctxs)
	}
	reasons := resetReasons(app, runID)
	if resetIndex(runFrames(app, runID), "interim_cancelled") < 0 {
		t.Fatalf("reset %#v", reasons)
	}
	for _, reason := range reasons {
		if reason == "interim_superseded" {
			t.Fatalf("reset %#v", reasons)
		}
	}
	partialAt := tokenIndex(runFrames(app, runID), interim)
	resetAt := resetIndex(runFrames(app, runID), "interim_cancelled")
	if partialAt < 0 || resetAt < 0 || partialAt > resetAt {
		t.Fatalf("partial %d reset %d", partialAt, resetAt)
	}
	if separatorToken(runFrames(app, runID)) {
		t.Fatal("blank-line separator published with interim_cancelled")
	}
}

func separatorToken(frames []frame) bool {
	for _, f := range frames {
		if f.event != "token" {
			continue
		}
		var p struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(f.data, &p) == nil && p.Text == "\n\n" {
			return true
		}
	}
	return false
}

func TestAsyncShellStopJoinsTool(t *testing.T) {
	m := newAsyncModel("run_shell", "should-not-run", "final answer", false)
	tool := newGateTool("shell-ok")
	tool.afterCancel = 150 * time.Millisecond
	clk := newManualClock()
	app, base, bot, runID := startShellRun(t, "JoinTool", true, clk, m, tool)
	waitCh(t, tool.started, "tool start")
	res, body := do(t, "POST", base+"/api/bots/"+bot.ID+"/runs/"+runID+"/cancel", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("cancel %d %s", res.StatusCode, body)
	}
	waitRunID(t, app, runID, "cancelled")
	if !tool.finished() {
		t.Fatal("run cancelled before the tool returned")
	}
}

func TestAsyncShellInterimFreshSkipsSeen(t *testing.T) {
	app := newApp(t, "", nil)
	bot, err := app.st.CreateBot("Fresh", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	seenMsg, err := app.st.AddMessage(store.Message{BotID: bot.ID, Thread: "user", Role: "user", Content: "already seen"})
	if err != nil {
		t.Fatal(err)
	}
	freshMsg, err := app.st.AddMessage(store.Message{BotID: bot.ID, Thread: "user", Role: "user", Content: "still fresh"})
	if err != nil {
		t.Fatal(err)
	}
	msgs, ids := app.interimFresh(bot.ID, "", map[string]bool{seenMsg.ID: true})
	for _, id := range ids {
		if id == seenMsg.ID {
			t.Fatalf("seen id returned in %v", ids)
		}
	}
	if msgHas(msgs, "user", "already seen") {
		t.Fatalf("seen message in %#v", msgs)
	}
	if !msgHas(msgs, "user", "still fresh") {
		t.Fatalf("fresh message missing from %#v", msgs)
	}
	found := false
	for _, id := range ids {
		if id == freshMsg.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("fresh id missing from %v", ids)
	}
}

func fireInterim(t *testing.T, base, botID, text string, clk *manualClock, entered <-chan int, want int) {
	t.Helper()
	postUser(t, base, botID, text)
	clk.Advance(500 * time.Millisecond)
	if n := waitN(t, entered, "interim"); n != want {
		t.Fatalf("interim %d, want %d", n, want)
	}
}

func TestAsyncShellInterimCapSpansShells(t *testing.T) {
	m := newAsyncModel("run_shell", "mid", "final answer", true)
	m.dualShell = true
	t1 := newGateTool("shell-1")
	t2 := newGateTool("shell-2")
	t3 := newGateTool("shell-3")
	t.Cleanup(t1.letGo)
	t.Cleanup(t2.letGo)
	t.Cleanup(t3.letGo)
	clk := newManualClock()
	app, base, bot, runID := startLoopRun(t, "Span", true, clk, m, chainTools(t1, t2, t3))
	if app.eventLoopMaxInterim != 0 {
		t.Fatalf("override set %d", app.eventLoopMaxInterim)
	}
	waitCh(t, t1.started, "shell 1")
	fireInterim(t, base, bot.ID, "s1a", clk, m.entered, 1)
	fireInterim(t, base, bot.ID, "s1b", clk, m.entered, 2)
	fireInterim(t, base, bot.ID, "s1c", clk, m.entered, 3)
	t1.letGo()
	waitCh(t, t2.started, "shell 2")
	fireInterim(t, base, bot.ID, "s2a", clk, m.entered, 4)
	fireInterim(t, base, bot.ID, "s2b", clk, m.entered, 5)
	postUser(t, base, bot.ID, "s2c")
	clk.Advance(500 * time.Millisecond)
	if batches := eventLoopBatchCounts(t, app, bot.ID); len(batches) != 5 {
		t.Fatalf("batches %#v, want 5", batches)
	}
	if got := waitBudgetSuppressed(t, app, bot.ID, 1); got != 1 {
		t.Fatalf("suppressed in run %d, want 1", got)
	}
	caps := waitInterimCaps(t, app, bot.ID, 1)
	if caps[0].Count != 5 || caps[0].Cap != 5 || caps[0].RunID != runID {
		t.Fatalf("cap row %+v", caps[0])
	}
	assertNoEntered(t, m.entered)
	if got := toolsNilReqs(m.snapshot()); len(got) != 5 {
		t.Fatalf("interim calls %d, want 5", len(got))
	}
	t2.letGo()
	waitIdle(t, base, bot.ID, "")
	if got := toolsNilReqs(m.snapshot()); len(got) != 5 {
		t.Fatalf("interim after finish %d", len(got))
	}

	run2 := postUser(t, base, bot.ID, "next")
	if run2 == "" || run2 == runID {
		t.Fatalf("second run %q first %q", run2, runID)
	}
	waitCh(t, t3.started, "run 2 shell")
	fireInterim(t, base, bot.ID, "r2", clk, m.entered, 6)
	if got := toolsNilReqs(m.snapshot()); len(got) != 6 {
		t.Fatalf("new run interims %d, want 6", len(got))
	}
	t3.letGo()
	waitIdle(t, base, bot.ID, "")
}

func TestTesterEvR2DefaultCapExactlyFive(t *testing.T) {
	m := newAsyncModel("run_shell", "mid", "final answer", true)
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app, base, bot, runID := startShellRun(t, "R2D", true, clk, m, tool)
	if app.eventLoopMaxInterim != 0 {
		t.Fatalf("override set %d", app.eventLoopMaxInterim)
	}
	waitCh(t, tool.started, "tool start")
	users := []string{}
	for i := 1; i <= 8; i++ {
		u := fmt.Sprintf("m%d", i)
		users = append(users, u)
		postUser(t, base, bot.ID, u)
		clk.Advance(500 * time.Millisecond)
		if i <= 5 {
			if n := waitN(t, m.entered, "interim"); n != i {
				t.Fatalf("interim %d at msg %d", n, i)
			}
		} else {
			if got := waitBudgetSuppressed(t, app, bot.ID, i-5); got != i-5 {
				t.Fatalf("suppressed in run %d at msg %d", got, i)
			}
			if batches := eventLoopBatchCounts(t, app, bot.ID); len(batches) != 5 {
				t.Fatalf("batches after cap %#v", batches)
			}
			if i == 6 {
				waitInterimCaps(t, app, bot.ID, 1)
			}
		}
	}
	if got := eventLoopInterimSuppressed(t, app, bot.ID); len(got) != 0 {
		t.Fatalf("suppressed row before the shell ended %+v", got)
	}
	caps := waitInterimCaps(t, app, bot.ID, 1)
	if len(caps) != 1 {
		t.Fatalf("capped rows %d, want 1 (%+v)", len(caps), caps)
	}
	// Refusal only happens when starts >= cap, so count always equals cap.
	if caps[0].Cap != 5 || caps[0].Count != 5 || caps[0].RunID != runID {
		t.Fatalf("cap row %+v", caps[0])
	}
	if got := toolsNilReqs(m.snapshot()); len(got) != 5 {
		t.Fatalf("interim starts %d, want 5", len(got))
	}
	ctxs := m.contexts()
	if len(ctxs) != 5 || ctxs[4].Err() != nil {
		t.Fatalf("5th interim cancelled by capped batches: %v", ctxErrs(ctxs))
	}
	if got := resetReasons(app, runID); len(got) != 4 {
		t.Fatalf("resets %v, want 4 supersedes", got)
	}
	tool.letGo()
	waitIdle(t, base, bot.ID, "")
	supp := waitInterimSuppressed(t, app, bot.ID, 1)
	if len(supp) != 1 || supp[0].Suppressed != 3 || supp[0].Count != 5 || supp[0].Cap != 5 || supp[0].RunID != runID {
		t.Fatalf("suppressed %+v", supp)
	}
	if got := eventLoopInterimCaps(t, app, bot.ID); len(got) != 1 {
		t.Fatalf("capped rows after finish %d", len(got))
	}
	reqs := m.snapshot()
	last := reqs[len(reqs)-1]
	if last.Tools == nil {
		t.Fatal("no final tools request")
	}
	assertUsersAfterTool(t, last.Messages, "shell-ok", users...)
	if got := toolsNilReqs(m.snapshot()); len(got) != 5 {
		t.Fatalf("interim after finish %d", len(got))
	}
}

func TestAsyncShellCappedRowThrottle(t *testing.T) {
	t.Run("exact-cap-no-row", func(t *testing.T) {
		m := newAsyncModel("run_shell", "mid", "final answer", true)
		tool := newGateTool("shell-ok")
		clk := newManualClock()
		app := newApp(t, "", m)
		app.editPol(func(p *policy.Policy) { p.EventLoop = true })
		app.eventClk = clk
		app.eventLoopMaxInterim = 2
		app.toolExec = tool.exec
		t.Cleanup(tool.letGo)
		srv := serve(t, app)
		bot := createBot(t, srv.URL, "CapExact")
		runID := postUser(t, srv.URL, bot.ID, "go")
		waitCh(t, tool.started, "tool start")
		fireInterim(t, srv.URL, bot.ID, "one", clk, m.entered, 1)
		fireInterim(t, srv.URL, bot.ID, "two", clk, m.entered, 2)
		tool.letGo()
		waitIdle(t, srv.URL, bot.ID, "")
		if got := eventLoopInterimCaps(t, app, bot.ID); len(got) != 0 {
			t.Fatalf("capped rows %+v", got)
		}
		if got := eventLoopInterimSuppressed(t, app, bot.ID); len(got) != 0 {
			t.Fatalf("suppressed rows %+v", got)
		}
		_ = runID
	})

	t.Run("flood-one-shell", func(t *testing.T) {
		// N=4 batches past the cap. Each one, including the batch that
		// writes the capped row, is counted on the suppressed row.
		// None of them add an event_loop_batch row.
		const past = 4
		m := newAsyncModel("run_shell", "mid", "final answer", true)
		tool := newGateTool("shell-ok")
		clk := newManualClock()
		app := newApp(t, "", m)
		app.editPol(func(p *policy.Policy) { p.EventLoop = true })
		app.eventClk = clk
		app.eventLoopMaxInterim = 2
		app.toolExec = tool.exec
		t.Cleanup(tool.letGo)
		srv := serve(t, app)
		bot := createBot(t, srv.URL, "CapFlood")
		runID := postUser(t, srv.URL, bot.ID, "go")
		waitCh(t, tool.started, "tool start")
		fireInterim(t, srv.URL, bot.ID, "one", clk, m.entered, 1)
		fireInterim(t, srv.URL, bot.ID, "two", clk, m.entered, 2)
		for i := 0; i < past; i++ {
			postUser(t, srv.URL, bot.ID, fmt.Sprintf("x%d", i))
			clk.Advance(500 * time.Millisecond)
			if got := waitBudgetSuppressed(t, app, bot.ID, i+1); got != i+1 {
				t.Fatalf("suppressed in run %d", got)
			}
			if batches := eventLoopBatchCounts(t, app, bot.ID); len(batches) != 2 {
				t.Fatalf("batches after cap %#v", batches)
			}
		}
		caps := waitInterimCaps(t, app, bot.ID, 1)
		// Refusal only happens when starts >= cap, so count always equals cap.
		if len(caps) != 1 || caps[0].Count != 2 || caps[0].Cap != 2 || caps[0].RunID != runID {
			t.Fatalf("cap row %+v", caps)
		}
		if got := eventLoopInterimSuppressed(t, app, bot.ID); len(got) != 0 {
			t.Fatalf("suppressed before end %+v", got)
		}
		assertNoEntered(t, m.entered)
		tool.letGo()
		waitIdle(t, srv.URL, bot.ID, "")
		if got := eventLoopInterimCaps(t, app, bot.ID); len(got) != 1 {
			t.Fatalf("capped rows after finish %d", len(got))
		}
		supp := waitInterimSuppressed(t, app, bot.ID, 1)
		if len(supp) != 1 || supp[0].Suppressed != past || supp[0].Count != 2 || supp[0].Cap != 2 || supp[0].RunID != runID {
			t.Fatalf("suppressed %+v", supp)
		}
	})

	t.Run("two-shells-both-flood", func(t *testing.T) {
		m := newAsyncModel("run_shell", "mid", "final answer", true)
		m.dualShell = true
		t1 := newGateTool("shell-1")
		t2 := newGateTool("shell-2")
		t.Cleanup(t1.letGo)
		t.Cleanup(t2.letGo)
		clk := newManualClock()
		app := newApp(t, "", m)
		app.editPol(func(p *policy.Policy) { p.EventLoop = true })
		app.eventClk = clk
		app.eventLoopMaxInterim = 2
		app.toolExec = chainTools(t1, t2)
		srv := serve(t, app)
		bot := createBot(t, srv.URL, "CapTwo")
		runID := postUser(t, srv.URL, bot.ID, "go")
		waitCh(t, t1.started, "shell 1")
		fireInterim(t, srv.URL, bot.ID, "a", clk, m.entered, 1)
		fireInterim(t, srv.URL, bot.ID, "b", clk, m.entered, 2)
		for i := 0; i < 3; i++ {
			postUser(t, srv.URL, bot.ID, fmt.Sprintf("c%d", i))
			clk.Advance(500 * time.Millisecond)
			if got := waitBudgetSuppressed(t, app, bot.ID, i+1); got != i+1 {
				t.Fatalf("shell 1 suppressed in run %d", got)
			}
			if batches := eventLoopBatchCounts(t, app, bot.ID); len(batches) != 2 {
				t.Fatalf("batches after cap %#v", batches)
			}
		}
		caps := waitInterimCaps(t, app, bot.ID, 1)
		if len(caps) != 1 || caps[0].Count != 2 || caps[0].Cap != 2 || caps[0].RunID != runID {
			t.Fatalf("cap row %+v", caps)
		}
		t1.letGo()
		waitCh(t, t2.started, "shell 2")
		supp1 := waitInterimSuppressed(t, app, bot.ID, 1)
		if len(supp1) != 1 || supp1[0].Suppressed != 3 || supp1[0].RunID != runID {
			t.Fatalf("shell 1 suppressed %+v", supp1)
		}
		for i := 0; i < 4; i++ {
			postUser(t, srv.URL, bot.ID, fmt.Sprintf("d%d", i))
			clk.Advance(500 * time.Millisecond)
			if got := waitBudgetSuppressed(t, app, bot.ID, i+1); got != i+1 {
				t.Fatalf("shell 2 suppressed in run %d", got)
			}
			if batches := eventLoopBatchCounts(t, app, bot.ID); len(batches) != 2 {
				t.Fatalf("batches after cap %#v", batches)
			}
		}
		if got := eventLoopInterimCaps(t, app, bot.ID); len(got) != 1 {
			t.Fatalf("capped rows during shell 2: %d", len(got))
		}
		if got := eventLoopInterimSuppressed(t, app, bot.ID); len(got) != 1 {
			t.Fatalf("extra suppressed before shell 2 ended %+v", got)
		}
		assertNoEntered(t, m.entered)
		t2.letGo()
		waitIdle(t, srv.URL, bot.ID, "")
		if got := eventLoopInterimCaps(t, app, bot.ID); len(got) != 1 {
			t.Fatalf("capped rows after finish %d", len(got))
		}
		supp := waitInterimSuppressed(t, app, bot.ID, 2)
		if len(supp) != 2 {
			t.Fatalf("suppressed rows %d, want 2 (%+v)", len(supp), supp)
		}
		if supp[0].Suppressed != 3 || supp[0].Count != 2 || supp[0].Cap != 2 || supp[0].RunID != runID {
			t.Fatalf("shell 1 suppressed %+v", supp[0])
		}
		if supp[1].Suppressed != 4 || supp[1].Count != 2 || supp[1].Cap != 2 || supp[1].RunID != runID {
			t.Fatalf("shell 2 suppressed %+v", supp[1])
		}
	})
}

func TestAsyncShellResetPayloadRunID(t *testing.T) {
	t.Run("interim_superseded", func(t *testing.T) {
		m := newAsyncModel("run_shell", "first pass", "final answer", true)
		tool := newGateTool("shell-ok")
		clk := newManualClock()
		app, base, bot, runID := startShellRun(t, "R11S", true, clk, m, tool)
		waitCh(t, tool.started, "tool start")
		postUser(t, base, bot.ID, "one")
		clk.Advance(500 * time.Millisecond)
		waitN(t, m.entered, "first interim")
		postUser(t, base, bot.ID, "two")
		clk.Advance(500 * time.Millisecond)
		waitN(t, m.entered, "second interim")
		waitResetReason(t, app, runID, "interim_superseded")
		got := resetFrames(app, runID)
		if len(got) != 1 || got[0].Reason != "interim_superseded" || got[0].RunID != runID {
			t.Fatalf("reset %#v want run_id %s", got, runID)
		}
		tool.letGo()
		waitIdle(t, base, bot.ID, "")
	})
	t.Run("interim_cancelled", func(t *testing.T) {
		m := newStreamingInterim("PARTIALTOK", "final answer")
		tool := newGateTool("shell-ok")
		clk := newManualClock()
		app, base, bot, runID := startShellRun(t, "R11C", true, clk, m, tool)
		waitCh(t, tool.started, "tool start")
		postUser(t, base, bot.ID, "one")
		clk.Advance(500 * time.Millisecond)
		waitN(t, m.entered, "interim")
		waitCh(t, m.tokensOut, "tokens")
		tool.letGo()
		waitIdle(t, base, bot.ID, "")
		got := resetFrames(app, runID)
		if len(got) != 1 || got[0].Reason != "interim_cancelled" || got[0].RunID != runID {
			t.Fatalf("reset %#v want run_id %s", got, runID)
		}
	})
	t.Run("interim_error", func(t *testing.T) {
		m := newAsyncModel("run_shell", "ERRTOK", "final answer", false)
		m.interimErr = errors.New("boom")
		tool := newGateTool("shell-ok")
		clk := newManualClock()
		app, base, bot, runID := startShellRun(t, "R11E", true, clk, m, tool)
		waitCh(t, tool.started, "tool start")
		postUser(t, base, bot.ID, "one")
		clk.Advance(500 * time.Millisecond)
		waitN(t, m.entered, "interim")
		waitResetReason(t, app, runID, "interim_error")
		got := resetFrames(app, runID)
		if len(got) != 1 || got[0].Reason != "interim_error" || got[0].RunID != runID {
			t.Fatalf("reset %#v want run_id %s", got, runID)
		}
		tool.letGo()
		waitIdle(t, base, bot.ID, "")
	})
}

func TestAsyncShellWhitespaceCancelNoReset(t *testing.T) {
	m := newStreamingInterim("  \n", "final answer")
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app, base, bot, runID := startShellRun(t, "R6", true, clk, m, tool)
	waitCh(t, tool.started, "tool start")
	postUser(t, base, bot.ID, "one")
	clk.Advance(500 * time.Millisecond)
	waitN(t, m.entered, "interim")
	waitCh(t, m.tokensOut, "tokens")
	tool.letGo()
	waitIdle(t, base, bot.ID, "")
	if got := resetReasons(app, runID); len(got) != 0 {
		t.Fatalf("reset %#v", got)
	}
	if separatorToken(runFrames(app, runID)) {
		t.Fatal("blank-line token after whitespace-only cancel")
	}
}

func TestAsyncShellCleanFinishBlankLine(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		m := newAsyncModel("run_shell", "", "final answer", false)
		tool := newGateTool("shell-ok")
		clk := newManualClock()
		app, base, bot, runID := startShellRun(t, "R7E", true, clk, m, tool)
		waitCh(t, tool.started, "tool start")
		postUser(t, base, bot.ID, "one")
		clk.Advance(500 * time.Millisecond)
		waitN(t, m.entered, "interim")
		waitN(t, m.returned, "interim return")
		waitInterimRows(t, app, bot.ID, 1)
		yieldRun()
		if got := resetReasons(app, runID); len(got) != 0 {
			t.Fatalf("reset %#v", got)
		}
		if n := separatorCount(runFrames(app, runID)); n != 0 {
			t.Fatalf("separators %d", n)
		}
		tool.letGo()
		waitIdle(t, base, bot.ID, "")
		if got := resetReasons(app, runID); len(got) != 0 {
			t.Fatalf("reset after finish %#v", got)
		}
		if n := separatorCount(runFrames(app, runID)); n != 0 {
			t.Fatalf("separators after finish %d", n)
		}
	})
	t.Run("whitespace", func(t *testing.T) {
		m := newAsyncModel("run_shell", "  \n", "final answer", false)
		tool := newGateTool("shell-ok")
		clk := newManualClock()
		app, base, bot, runID := startShellRun(t, "R7W", true, clk, m, tool)
		waitCh(t, tool.started, "tool start")
		postUser(t, base, bot.ID, "one")
		clk.Advance(500 * time.Millisecond)
		waitN(t, m.entered, "interim")
		waitN(t, m.returned, "interim return")
		waitInterimRows(t, app, bot.ID, 1)
		yieldRun()
		if got := resetReasons(app, runID); len(got) != 0 {
			t.Fatalf("reset %#v", got)
		}
		if n := separatorCount(runFrames(app, runID)); n != 0 {
			t.Fatalf("separators %d", n)
		}
		tool.letGo()
		waitIdle(t, base, bot.ID, "")
		if got := resetReasons(app, runID); len(got) != 0 {
			t.Fatalf("reset after finish %#v", got)
		}
		if n := separatorCount(runFrames(app, runID)); n != 0 {
			t.Fatalf("separators after finish %d", n)
		}
	})
	t.Run("text", func(t *testing.T) {
		m := newAsyncModel("run_shell", "still going", "final answer", false)
		tool := newGateTool("shell-ok")
		clk := newManualClock()
		app, base, bot, runID := startShellRun(t, "R7T", true, clk, m, tool)
		waitCh(t, tool.started, "tool start")
		postUser(t, base, bot.ID, "one")
		clk.Advance(500 * time.Millisecond)
		waitN(t, m.entered, "interim")
		waitN(t, m.returned, "interim return")
		waitTokenText(t, app, runID, "still going\n\n")
		if got := resetReasons(app, runID); len(got) != 0 {
			t.Fatalf("reset %#v", got)
		}
		if n := separatorCount(runFrames(app, runID)); n != 1 {
			t.Fatalf("separators %d, want 1", n)
		}
		tool.letGo()
		waitIdle(t, base, bot.ID, "")
		if n := separatorCount(runFrames(app, runID)); n != 1 {
			t.Fatalf("separators after finish %d", n)
		}
	})
}

func TestAsyncShellInterimErrorReset(t *testing.T) {
	const interim = "ERRTOK"
	const final = "final answer"
	m := newAsyncModel("run_shell", interim, final, false)
	m.interimErr = errors.New("boom")
	m.tokensOut = make(chan struct{})
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app, base, bot, runID := startShellRun(t, "ErrReset", true, clk, m, tool)
	waitCh(t, tool.started, "tool start")
	postUser(t, base, bot.ID, "one")
	clk.Advance(500 * time.Millisecond)
	waitN(t, m.entered, "interim")
	waitCh(t, m.tokensOut, "tokens")
	waitResetReason(t, app, runID, "interim_error")
	if tool.finished() {
		t.Fatal("shell finished during interim error")
	}
	reasons := resetReasons(app, runID)
	if len(reasons) != 1 || reasons[0] != "interim_error" {
		t.Fatalf("reset %#v", reasons)
	}
	for _, r := range reasons {
		if r == "interim_cancelled" {
			t.Fatalf("reset %#v", reasons)
		}
	}
	frames := runFrames(app, runID)
	resetAt := resetIndex(frames, "interim_error")
	tokAt := tokenIndex(frames, interim)
	if resetAt < 0 || tokAt < 0 || tokAt > resetAt {
		t.Fatalf("token %d reset %d", tokAt, resetAt)
	}
	if separatorToken(frames) {
		t.Fatal("blank-line token with interim_error")
	}
	tool.letGo()
	waitIdle(t, base, bot.ID, "")
	got := fetchBot(t, base, bot.ID)
	if got.LastRunStatus != "done" {
		t.Fatalf("status %s %s", got.LastRunStatus, got.LastRunError)
	}
	msgs, err := app.st.ListMessages(bot.ID, "user", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	bots := 0
	for _, msg := range msgs {
		if strings.Contains(msg.Content, interim) || strings.Contains(msg.Content, shellStillRunning) {
			t.Fatalf("stored %#v", msg)
		}
		if msg.Role == "bot" {
			bots++
			if msg.Content != final {
				t.Fatalf("bot reply %q", msg.Content)
			}
		}
	}
	if bots != 1 {
		t.Fatalf("bot messages %d", bots)
	}
}

func TestAsyncShellInterimDeadlineIsError(t *testing.T) {
	m := newStreamingInterim("DEADTOK", "final answer")
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app := newApp(t, "", m)
	app.editPol(func(p *policy.Policy) {
		p.EventLoop = true
		p.OllamaModelTimeout = 250 * time.Millisecond
	})
	if !app.pol().EventLoopEnabled() {
		t.Fatal("event loop flag did not publish")
	}
	app.eventClk = clk
	app.toolExec = tool.exec
	t.Cleanup(tool.letGo)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "DeadErr")
	runID := postUser(t, srv.URL, bot.ID, "go")
	waitCh(t, tool.started, "tool start")
	postUser(t, srv.URL, bot.ID, "one")
	clk.Advance(500 * time.Millisecond)
	waitN(t, m.entered, "interim")
	waitCh(t, m.tokensOut, "tokens")
	waitN(t, m.returned, "interim deadline")
	waitResetReason(t, app, runID, "interim_error")
	got := resetReasons(app, runID)
	if len(got) != 1 || got[0] != "interim_error" {
		t.Fatalf("reset %#v", got)
	}
	if tool.finished() {
		t.Fatal("shell finished during model deadline")
	}
	if separatorToken(runFrames(app, runID)) {
		t.Fatal("blank-line token with deadline interim_error")
	}
	tool.letGo()
	waitIdle(t, srv.URL, bot.ID, "")
}
