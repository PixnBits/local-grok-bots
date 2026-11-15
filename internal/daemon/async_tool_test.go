package daemon

import (
	"context"
	"encoding/json"
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
		entered:     make(chan int, 8),
		returned:    make(chan int, 8),
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
	nTools := 0
	if req.Tools != nil {
		for _, r := range m.reqs {
			if r.Tools != nil {
				nTools++
			}
		}
	}
	m.mu.Unlock()
	if req.Tools == nil {
		return m.interim(ctx, onToken)
	}
	if nTools == 1 {
		return model.ChatResponse{ToolCalls: []model.ToolCall{{
			Name:      m.toolName,
			Arguments: map[string]any{"command": "echo hi"},
		}}}, nil
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
	if m.block {
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
	if onToken != nil && m.interimText != "" {
		onToken(m.interimText)
	}
	m.markReturned(n)
	return model.ChatResponse{Content: m.interimText}, nil
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
	mu      sync.Mutex
	ctx     context.Context
	started chan struct{}
	release chan struct{}
	once    sync.Once
	result  string
	done    chan struct{}
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
	if tool != nil {
		app.toolExec = tool.exec
		t.Cleanup(tool.letGo)
	}
	srv := serve(t, app)
	bot := createBot(t, srv.URL, botName)
	runID := postUser(t, srv.URL, bot.ID, "go")
	if runID == "" {
		t.Fatal("no run")
	}
	return app, srv.URL, bot, runID
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
	if !strings.Contains(tokenText(app, runID), "still going") {
		t.Fatalf("stream %q", tokenText(app, runID))
	}
	tool.letGo()
	waitIdle(t, base, bot.ID, "")
	if !strings.Contains(tokenText(app, runID), "still going\n\n") {
		t.Fatalf("separator missing in %q", tokenText(app, runID))
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
	ev, err := app.st.ListLog(bot.ID, "event_loop_batch", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 0 {
		t.Fatalf("event_loop_batch rows %d", len(ev))
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
	_, base, bot, _ := startShellRun(t, "Join", true, clk, m, tool)
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
