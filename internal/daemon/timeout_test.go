package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func setPolicy(app *App, fn func(*policy.Policy)) {
	app.rtMu.Lock()
	p := app.pol()
	fn(&p)
	app.setPol(p)
	app.rtMu.Unlock()
}

type seqModel struct {
	mu    sync.Mutex
	calls []model.ChatRequest
	steps []func(context.Context, model.ChatRequest, func(string)) (model.ChatResponse, error)
}

func (m *seqModel) Chat(ctx context.Context, req model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
	m.mu.Lock()
	m.calls = append(m.calls, req)
	i := len(m.calls) - 1
	m.mu.Unlock()
	if i >= len(m.steps) {
		if onToken != nil {
			onToken("extra")
		}
		return model.ChatResponse{Content: "extra"}, nil
	}
	return m.steps[i](ctx, req, onToken)
}

func (m *seqModel) snapshot() []model.ChatRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]model.ChatRequest, len(m.calls))
	copy(out, m.calls)
	return out
}

type blockModel struct {
	calls   atomic.Int32
	entered chan struct{}
}

func (m *blockModel) Chat(ctx context.Context, req model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
	if m.calls.Add(1) == 1 && m.entered != nil {
		close(m.entered)
	}
	<-ctx.Done()
	return model.ChatResponse{}, ctx.Err()
}

func stallErr() *model.TimeoutError {
	return &model.TimeoutError{Limit: "stall_timeout", After: 2 * time.Minute, GotOutput: true, Partial: "Hello"}
}

func postRetry(t *testing.T, base, botID, runID string) (*http.Response, []byte) {
	t.Helper()
	return do(t, http.MethodPost, base+"/api/bots/"+botID+"/runs/"+runID+"/retry", nil, "")
}

func threadNotice(page failThread) string {
	for i := len(page.Messages) - 1; i >= 0; i-- {
		m := page.Messages[i]
		if m.Role == "system" && strings.HasPrefix(m.Content, "Notice:") {
			return m.Content
		}
	}
	return ""
}

func botReplies(page failThread) []store.Message {
	var out []store.Message
	for _, m := range page.Messages {
		if m.Role == "bot" {
			out = append(out, m)
		}
	}
	return out
}

func retryLogs(t *testing.T, base string) int {
	t.Helper()
	n := 0
	for _, e := range logKind(t, base, "model_call") {
		var d struct {
			OK    bool `json:"ok"`
			Retry bool `json:"retry"`
		}
		if err := json.Unmarshal(e.Detail, &d); err != nil {
			t.Fatal(err)
		}
		if d.Retry && !d.OK {
			n++
		}
	}
	return n
}

func sawStreamReset(app *App, runID, reason string) bool {
	hist, ch := app.bus.Subscribe(runID)
	app.bus.Unsubscribe(runID, ch)
	for _, f := range hist {
		if f.event != "stream_reset" {
			continue
		}
		var payload struct {
			RunID  string `json:"run_id"`
			Reason string `json:"reason"`
		}
		if json.Unmarshal(f.data, &payload) == nil && payload.RunID == runID && payload.Reason == reason {
			return true
		}
	}
	return false
}

func TestCompactDurationAndTimeoutBody(t *testing.T) {
	if compactDuration(0) != "0s" || compactDuration(150*time.Millisecond) != "150ms" ||
		compactDuration(45*time.Second) != "45s" || compactDuration(2*time.Minute) != "2m" ||
		compactDuration(90*time.Minute) != "1h30m" || compactDuration(time.Hour+30*time.Second) != "1h30s" {
		t.Fatalf("compact %s %s %s %s %s %s",
			compactDuration(0), compactDuration(150*time.Millisecond), compactDuration(45*time.Second),
			compactDuration(2*time.Minute), compactDuration(90*time.Minute), compactDuration(time.Hour+30*time.Second))
	}
	cases := []struct{ got, want string }{
		{timeoutBody("stall_timeout", 2*time.Minute, 1, "Hello"), "No output from the model for 2m (stall_timeout). Retried once. The partial reply is kept above."},
		{timeoutBody("stall_timeout", 2*time.Minute, 0, "Hello"), "No output from the model for 2m (stall_timeout). The partial reply is kept above."},
		{timeoutBody("stall_timeout", 2*time.Minute, 0, "  "), "No output from the model for 2m (stall_timeout)."},
		{timeoutBody("stall_timeout", 2*time.Minute, 2, ""), "No output from the model for 2m (stall_timeout). Retried 2 times."},
		{timeoutBody("first_output_timeout", 5*time.Minute, 1, ""), "The model sent no output within 5m (first_output_timeout). Retried once."},
		{timeoutBody("model_timeout", 10*time.Minute, 0, "Hello"), "The model call hit its 10m limit (model_timeout). The partial reply is kept above."},
		{timeoutBody("run_timeout", 150*time.Millisecond, 0, ""), "The run hit its 150ms limit (run_timeout)."},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Fatalf("got %q want %q", c.got, c.want)
		}
		if runNoticeText("timeout", c.got) != "Notice: "+c.want {
			t.Fatalf("notice %q", runNoticeText("timeout", c.got))
		}
	}
}

func TestStallThenRetrySucceeds(t *testing.T) {
	mdl := &seqModel{steps: []func(context.Context, model.ChatRequest, func(string)) (model.ChatResponse, error){
		func(_ context.Context, req model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
			if req.KeepAlive != "30m" || req.FirstOutputTimeout != 5*time.Minute || req.StallTimeout != 2*time.Minute {
				t.Errorf("timeouts keep=%v first=%s stall=%s", req.KeepAlive, req.FirstOutputTimeout, req.StallTimeout)
			}
			if onToken != nil {
				onToken("nope")
			}
			return model.ChatResponse{}, &model.TimeoutError{Limit: "stall_timeout", After: time.Minute, GotOutput: true, Partial: "nope", FirstOutput: 20 * time.Millisecond}
		},
		func(_ context.Context, _ model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
			if onToken != nil {
				onToken("final")
			}
			return model.ChatResponse{Content: "final", FirstOutput: 5 * time.Millisecond}, nil
		},
	}}
	app := newApp(t, "", mdl)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Ada")
	runID := postUser(t, srv.URL, bot.ID, "hi")
	bot = waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "done"
	})
	if bot.LastRunError != "" {
		t.Fatalf("error %s", bot.LastRunError)
	}
	if retryLogs(t, srv.URL) != 1 {
		t.Fatalf("retry logs %d", retryLogs(t, srv.URL))
	}
	page := readThread(t, srv.URL, bot.ID)
	replies := botReplies(page)
	if len(replies) != 1 || replies[0].Content != "final" || replies[0].TimedOut {
		t.Fatalf("replies %#v", replies)
	}
	if !sawStreamReset(app, runID, "stall_timeout") {
		t.Fatal("no stream_reset")
	}
	var sawRetrying bool
	hist, ch := app.bus.Subscribe(runID)
	app.bus.Unsubscribe(runID, ch)
	for _, f := range hist {
		if f.event != "status" {
			continue
		}
		var payload struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(f.data, &payload)
		if payload.Text == "retrying" {
			sawRetrying = true
		}
	}
	if !sawRetrying {
		t.Fatal("no retrying status")
	}
	calls := mdl.snapshot()
	if len(calls) != 2 {
		t.Fatalf("calls %d", len(calls))
	}
}

func TestStallRetriesZeroKeepsPartial(t *testing.T) {
	mdl := &seqModel{steps: []func(context.Context, model.ChatRequest, func(string)) (model.ChatResponse, error){
		func(context.Context, model.ChatRequest, func(string)) (model.ChatResponse, error) {
			return model.ChatResponse{}, nil
		},
	}}
	// The step above is replaced: onToken must run, so use a closure that does.
	mdl.steps[0] = func(_ context.Context, _ model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
		if onToken != nil {
			onToken("Hello")
		}
		return model.ChatResponse{}, stallErr()
	}
	app := newApp(t, "", mdl)
	setPolicy(app, func(p *policy.Policy) {
		p.OllamaStallTimeout = 2 * time.Minute
		p.OllamaStallRetries = 0
		p.OllamaStallRetriesSet = true
	})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Ada")
	postUser(t, srv.URL, bot.ID, "hi")
	bot = waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "timeout"
	})
	const body = "No output from the model for 2m (stall_timeout). The partial reply is kept above."
	if bot.LastRunError != body {
		t.Fatalf("error %q", bot.LastRunError)
	}
	if retryLogs(t, srv.URL) != 0 || len(mdl.snapshot()) != 1 {
		t.Fatalf("calls %d retries %d", len(mdl.snapshot()), retryLogs(t, srv.URL))
	}
	page := readThread(t, srv.URL, bot.ID)
	if threadNotice(page) != "Notice: "+body {
		t.Fatalf("notice %q", threadNotice(page))
	}
	replies := botReplies(page)
	if len(replies) != 1 || replies[0].Content != "Hello" || !replies[0].TimedOut {
		t.Fatalf("replies %#v", replies)
	}
	if bot.ContinueRunID == "" {
		t.Fatal("no continue offer")
	}
}

func TestToolExecutesOnceAcrossStallRetry(t *testing.T) {
	mdl := &seqModel{steps: []func(context.Context, model.ChatRequest, func(string)) (model.ChatResponse, error){
		func(context.Context, model.ChatRequest, func(string)) (model.ChatResponse, error) {
			return model.ChatResponse{ToolCalls: []model.ToolCall{{Name: "list_bots", Arguments: map[string]any{}}}}, nil
		},
		func(_ context.Context, _ model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
			if onToken != nil {
				onToken("mid")
			}
			return model.ChatResponse{}, &model.TimeoutError{Limit: "first_output_timeout", After: time.Minute, Partial: "mid", GotOutput: true}
		},
		func(_ context.Context, _ model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
			if onToken != nil {
				onToken("after tool")
			}
			return model.ChatResponse{Content: "after tool"}, nil
		},
	}}
	app := newApp(t, "", mdl)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Ada")
	runID := postUser(t, srv.URL, bot.ID, "list them")
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "done"
	})
	calls := mdl.snapshot()
	if len(calls) != 3 {
		t.Fatalf("calls %d", len(calls))
	}
	if !reflect.DeepEqual(calls[1].Messages, calls[2].Messages) {
		t.Fatalf("retry changed the transcript\n%#v\n%#v", calls[1].Messages, calls[2].Messages)
	}
	page := readThread(t, srv.URL, bot.ID)
	n := 0
	for _, rec := range page.Tools[runID] {
		if rec.Name == "list_bots" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("list_bots ran %d times: %#v", n, page.Tools[runID])
	}
	replies := botReplies(page)
	if len(replies) != 1 || replies[0].Content != "after tool" || replies[0].TimedOut {
		t.Fatalf("replies %#v", replies)
	}
}

func TestNoRetryOnStopOrRunTimeout(t *testing.T) {
	t.Run("stop", func(t *testing.T) {
		entered := make(chan struct{})
		mdl := &blockModel{entered: entered}
		app := newApp(t, "", mdl)
		srv := serve(t, app)
		bot := createBot(t, srv.URL, "Ada")
		runID := postUser(t, srv.URL, bot.ID, "hi")
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("model was not called")
		}
		res, b := do(t, http.MethodPost, srv.URL+"/api/bots/"+bot.ID+"/runs/"+runID+"/cancel", nil, "")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("cancel %d %s", res.StatusCode, b)
		}
		bot = waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool { return b.Status != "running" })
		if bot.LastRunStatus != "cancelled" {
			t.Fatalf("status %s %s", bot.LastRunStatus, bot.LastRunError)
		}
		if mdl.calls.Load() != 1 || retryLogs(t, srv.URL) != 0 {
			t.Fatalf("calls %d", mdl.calls.Load())
		}
	})
	t.Run("run_timeout", func(t *testing.T) {
		mdl := &blockModel{}
		app := newApp(t, "", mdl)
		setPolicy(app, func(p *policy.Policy) {
			p.OllamaRunTimeout = 150 * time.Millisecond
			p.OllamaStallRetries = 3
			p.OllamaStallRetriesSet = true
		})
		srv := serve(t, app)
		bot := createBot(t, srv.URL, "Bea")
		postUser(t, srv.URL, bot.ID, "hi")
		bot = waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool { return b.Status != "running" })
		const body = "The run hit its 150ms limit (run_timeout)."
		if bot.LastRunStatus != "timeout" || bot.LastRunError != body {
			t.Fatalf("status %s %s", bot.LastRunStatus, bot.LastRunError)
		}
		if mdl.calls.Load() > 1 || retryLogs(t, srv.URL) != 0 {
			t.Fatalf("calls %d", mdl.calls.Load())
		}
		page := readThread(t, srv.URL, bot.ID)
		if threadNotice(page) != "Notice: "+body {
			t.Fatalf("notice %q", threadNotice(page))
		}
		if len(botReplies(page)) != 0 {
			t.Fatalf("partial %#v", botReplies(page))
		}
	})
}

func TestModelTimeoutIsNotRetried(t *testing.T) {
	mdl := &seqModel{steps: []func(context.Context, model.ChatRequest, func(string)) (model.ChatResponse, error){
		func(_ context.Context, _ model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
			if onToken != nil {
				onToken("Hello")
			}
			return model.ChatResponse{}, &model.TimeoutError{Limit: "model_timeout", After: 10 * time.Minute, GotOutput: true, Partial: "Hello"}
		},
	}}
	app := newApp(t, "", mdl)
	setPolicy(app, func(p *policy.Policy) {
		p.OllamaModelTimeout = 10 * time.Minute
		p.OllamaStallRetries = 3
		p.OllamaStallRetriesSet = true
	})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Ada")
	postUser(t, srv.URL, bot.ID, "hi")
	bot = waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool { return b.Status != "running" })
	const body = "The model call hit its 10m limit (model_timeout). The partial reply is kept above."
	if bot.LastRunStatus != "timeout" || bot.LastRunError != body {
		t.Fatalf("status %s %q", bot.LastRunStatus, bot.LastRunError)
	}
	if len(mdl.snapshot()) != 1 || retryLogs(t, srv.URL) != 0 {
		t.Fatalf("calls %d", len(mdl.snapshot()))
	}
	page := readThread(t, srv.URL, bot.ID)
	if threadNotice(page) != "Notice: "+body {
		t.Fatalf("notice %q", threadNotice(page))
	}
	replies := botReplies(page)
	if len(replies) != 1 || !replies[0].TimedOut || replies[0].Content != "Hello" {
		t.Fatalf("replies %#v", replies)
	}
}

func TestContinueAfterTimeoutIncludesPartial(t *testing.T) {
	mdl := &seqModel{steps: []func(context.Context, model.ChatRequest, func(string)) (model.ChatResponse, error){
		func(_ context.Context, _ model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
			if onToken != nil {
				onToken("Half")
			}
			return model.ChatResponse{}, &model.TimeoutError{Limit: "stall_timeout", After: time.Minute, GotOutput: true, Partial: "Half"}
		},
		func(_ context.Context, req model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
			var sawPartial, sawNudge bool
			for _, m := range req.Messages {
				if m.Role == "assistant" && m.Content == "Half" {
					sawPartial = true
				}
				if m.Role == "user" && m.Content == "Continue from where you stopped." {
					sawNudge = true
				}
			}
			if !sawPartial || !sawNudge {
				t.Errorf("continue transcript partial=%v nudge=%v", sawPartial, sawNudge)
			}
			if onToken != nil {
				onToken("rest")
			}
			return model.ChatResponse{Content: "rest"}, nil
		},
	}}
	app := newApp(t, "", mdl)
	setPolicy(app, func(p *policy.Policy) {
		p.OllamaStallRetries = 0
		p.OllamaStallRetriesSet = true
		p.OllamaStallTimeout = 2 * time.Minute
	})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Ada")
	runID := postUser(t, srv.URL, bot.ID, "go on")
	bot = waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "timeout" && b.ContinueRunID == runID
	})
	waitRunReleased(t, app, bot.ID)
	res, b := postContinue(t, srv.URL, bot.ID, runID)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("continue %d %s", res.StatusCode, b)
	}
	bot = waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "done"
	})
	if len(mdl.snapshot()) != 2 {
		t.Fatalf("calls %d", len(mdl.snapshot()))
	}
}

func TestRetryEndpoint(t *testing.T) {
	mdl := &seqModel{steps: []func(context.Context, model.ChatRequest, func(string)) (model.ChatResponse, error){
		func(_ context.Context, _ model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
			if onToken != nil {
				onToken("Half")
			}
			return model.ChatResponse{}, &model.TimeoutError{Limit: "stall_timeout", After: time.Minute, GotOutput: true, Partial: "Half"}
		},
		func(_ context.Context, req model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
			var sawUser, sawPartial, sawNotice bool
			for _, m := range req.Messages {
				if m.Role == "user" && m.Content == "please answer" {
					sawUser = true
				}
				if strings.Contains(m.Content, "Half") {
					sawPartial = true
				}
				if strings.Contains(m.Content, "stall_timeout") {
					sawNotice = true
				}
			}
			if !sawUser || sawPartial || sawNotice {
				t.Errorf("retry history user=%v partial=%v notice=%v", sawUser, sawPartial, sawNotice)
			}
			if onToken != nil {
				onToken("fresh")
			}
			return model.ChatResponse{Content: "fresh"}, nil
		},
	}}
	app := newApp(t, "", mdl)
	setPolicy(app, func(p *policy.Policy) {
		p.OllamaStallRetries = 0
		p.OllamaStallRetriesSet = true
	})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Ada")
	runID := postUser(t, srv.URL, bot.ID, "please answer")
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "timeout"
	})
	waitRunReleased(t, app, bot.ID)

	res, b := postRetry(t, srv.URL, bot.ID, "missing-run")
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown run %d %s", res.StatusCode, b)
	}
	res, b = postRetry(t, srv.URL, "missing-bot", runID)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown bot %d %s", res.StatusCode, b)
	}
	if err := app.st.SetStatus(bot.ID, "paused"); err != nil {
		t.Fatal(err)
	}
	res, b = postRetry(t, srv.URL, bot.ID, runID)
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("paused %d %s", res.StatusCode, b)
	}
	if err := app.st.SetStatus(bot.ID, "running"); err != nil {
		t.Fatal(err)
	}
	res, b = postRetry(t, srv.URL, bot.ID, runID)
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("running %d %s", res.StatusCode, b)
	}
	if err := app.st.SetStatus(bot.ID, "idle"); err != nil {
		t.Fatal(err)
	}
	res, b = postRetry(t, srv.URL, bot.ID, runID)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("retry %d %s", res.StatusCode, b)
	}
	var posted struct {
		RunID string `json:"run_id"`
	}
	decodeJSON(t, b, &posted)
	if posted.RunID == "" || posted.RunID == runID {
		t.Fatalf("new run %q", posted.RunID)
	}
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "done"
	})
	page := readThread(t, srv.URL, bot.ID)
	replies := botReplies(page)
	if len(replies) != 1 || replies[0].Content != "fresh" || replies[0].TimedOut {
		t.Fatalf("replies %#v", replies)
	}
	if strings.Contains(threadNotice(page), "stall_timeout") {
		t.Fatalf("notice kept %q", threadNotice(page))
	}
	res, b = postRetry(t, srv.URL, bot.ID, runID)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("old run %d %s", res.StatusCode, b)
	}
	res, b = postRetry(t, srv.URL, bot.ID, posted.RunID)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("done run %d %s", res.StatusCode, b)
	}
}

func TestKeepAliveReachesFakeOllama(t *testing.T) {
	var body atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body.Store(string(b))
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = w.Write([]byte("{\"message\":{\"role\":\"assistant\",\"content\":\"ok\"},\"done\":true}\n"))
	}))
	defer upstream.Close()
	app := newApp(t, "", model.NewOllama(upstream.URL))
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Ada")
	postUser(t, srv.URL, bot.ID, "hi")
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "done"
	})
	got, _ := body.Load().(string)
	if !strings.Contains(got, `"keep_alive":"30m"`) {
		t.Fatalf("body %s", got)
	}
}

// fakeClock is the stall watchdog and per-call cap clock. Advance fires due
// timers synchronously and never moves time backwards.
type fakeClock struct {
	mu     sync.Mutex
	advMu  sync.Mutex
	now    time.Time
	nextID int
	timers []*fakeTimer
	// latestFirst fires the newest timer when several share a deadline.
	// The per-call cap is armed before the silence watchdog, so this is the
	// tie where Chat sees the watchdog first.
	latestFirst bool
}

type fakeTimer struct {
	id      int
	at      time.Time
	fn      func()
	stopped bool
	clock   *fakeClock
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Now()}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) AfterFunc(d time.Duration, fn func()) model.ClockTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d < 0 {
		d = 0
	}
	c.nextID++
	t := &fakeTimer{id: c.nextID, at: c.now.Add(d), fn: fn, clock: c}
	c.timers = append(c.timers, t)
	return t
}

func (t *fakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if t.stopped {
		return false
	}
	t.stopped = true
	return true
}

func (c *fakeClock) armedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.timers {
		if !t.stopped {
			n++
		}
	}
	return n
}

func (c *fakeClock) soonest() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	var best time.Duration
	ok := false
	for _, t := range c.timers {
		if t.stopped {
			continue
		}
		d := t.at.Sub(c.now)
		if !ok || d < best {
			best = d
			ok = true
		}
	}
	if !ok {
		return -1
	}
	return best
}

func (c *fakeClock) Advance(d time.Duration) {
	c.advMu.Lock()
	defer c.advMu.Unlock()
	end := c.Now().Add(d)
	for {
		c.mu.Lock()
		var next *fakeTimer
		for _, t := range c.timers {
			if t.stopped {
				continue
			}
			if next == nil || t.at.Before(next.at) {
				next = t
				continue
			}
			if t.at.Equal(next.at) && ((c.latestFirst && t.id > next.id) || (!c.latestFirst && t.id < next.id)) {
				next = t
			}
		}
		if next == nil || next.at.After(end) {
			if c.now.Before(end) {
				c.now = end
			}
			c.mu.Unlock()
			return
		}
		c.now = next.at
		next.stopped = true
		fn := next.fn
		c.mu.Unlock()
		if fn != nil {
			fn()
		}
	}
}

func timedOutPartialBytes(t *testing.T, base string) int {
	t.Helper()
	events := logKind(t, base, "run_timed_out")
	if len(events) != 1 {
		t.Fatalf("run_timed_out events %d", len(events))
	}
	var d struct {
		PartialBytes int `json:"partial_bytes"`
	}
	if err := json.Unmarshal(events[0].Detail, &d); err != nil {
		t.Fatal(err)
	}
	return d.PartialBytes
}

func TestProdModelTimeoutAllowsSlowFirstToken(t *testing.T) {
	// Prod shape from a parsed policy file: model_timeout 10m, run_timeout
	// 30m, no silence keys. The old defaults (first_output 5m, stall 2m)
	// cancel a first token at 5m30s, retry, and time out after a second
	// request. The explicit model_timeout must keep that call alive.
	// The fake clock is the watchdog's and the per-call cap's, so this does
	// not wait out the real 5m30s.
	clk := newFakeClock()
	var requests atomic.Int32
	var armed atomic.Int32
	var soon atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if requests.Add(1) == 1 {
			armed.Store(int32(clk.armedCount()))
			soon.Store(int64(clk.soonest()))
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		advanced := make(chan struct{})
		go func() {
			clk.Advance(5*time.Minute + 30*time.Second)
			close(advanced)
		}()
		select {
		case <-r.Context().Done():
			return
		case <-advanced:
		}
		if r.Context().Err() != nil {
			return
		}
		_, _ = io.WriteString(w, "{\"message\":{\"role\":\"assistant\",\"content\":\"ok\"},\"done\":true}\n")
	}))
	defer upstream.Close()

	path := filepath.Join(t.TempDir(), "policy.toml")
	if err := os.WriteFile(path, []byte("[ollama]\nmodel_timeout = \"10m\"\nrun_timeout = \"30m\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(policy.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if pol.EffectiveOllamaFirstOutputTimeout() != 10*time.Minute ||
		pol.EffectiveOllamaStallTimeout() != 10*time.Minute ||
		pol.EffectiveOllamaModelTimeout() != 10*time.Minute ||
		pol.EffectiveOllamaRunTimeout() != 30*time.Minute {
		t.Fatalf("resolved first=%s stall=%s model=%s run=%s",
			pol.EffectiveOllamaFirstOutputTimeout(), pol.EffectiveOllamaStallTimeout(),
			pol.EffectiveOllamaModelTimeout(), pol.EffectiveOllamaRunTimeout())
	}
	ol := model.NewOllama(upstream.URL)
	ol.SetClock(&model.Clock{Now: clk.Now, AfterFunc: clk.AfterFunc})
	app := newApp(t, "", ol)
	app.rtMu.Lock()
	app.setPol(pol)
	app.rtMu.Unlock()
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Ada")
	runID := postUser(t, srv.URL, bot.ID, "hi")
	bot = waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool { return b.Status != "running" })
	// Inherited silence equals the cap, so it is not a second timer.
	// A first token before that cap still succeeds.
	if armed.Load() != 1 {
		t.Fatalf("clock timers armed %d, want only the per-call cap", armed.Load())
	}
	if time.Duration(soon.Load()) < 10*time.Minute {
		t.Fatalf("soonest timer %s, want >= 10m (explicit model_timeout)", time.Duration(soon.Load()))
	}
	if bot.LastRunStatus != "done" || bot.LastRunError != "" {
		t.Fatalf("status %s %q requests %d", bot.LastRunStatus, bot.LastRunError, requests.Load())
	}
	if requests.Load() != 1 || retryLogs(t, srv.URL) != 0 {
		t.Fatalf("requests %d retries %d", requests.Load(), retryLogs(t, srv.URL))
	}
	if sawStreamReset(app, runID, "first_output_timeout") || sawStreamReset(app, runID, "stall_timeout") {
		t.Fatal("stream_reset")
	}
	page := readThread(t, srv.URL, bot.ID)
	replies := botReplies(page)
	if len(replies) != 1 || replies[0].Content != "ok" || replies[0].TimedOut {
		t.Fatalf("replies %#v", replies)
	}
}

func TestStallRetryKeepsLongestPartial(t *testing.T) {
	const kept = "Hello from the first attempt"
	mdl := &seqModel{steps: []func(context.Context, model.ChatRequest, func(string)) (model.ChatResponse, error){
		func(_ context.Context, _ model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
			if onToken != nil {
				onToken(kept)
			}
			return model.ChatResponse{}, &model.TimeoutError{Limit: "stall_timeout", After: time.Minute, GotOutput: true, Partial: kept}
		},
		func(context.Context, model.ChatRequest, func(string)) (model.ChatResponse, error) {
			return model.ChatResponse{}, &model.TimeoutError{Limit: "stall_timeout", After: time.Minute}
		},
	}}
	app := newApp(t, "", mdl)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Ada")
	runID := postUser(t, srv.URL, bot.ID, "hi")
	bot = waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "timeout"
	})
	const body = "No output from the model for 2m (stall_timeout). Retried once. The partial reply is kept above."
	if bot.LastRunError != body {
		t.Fatalf("error %q", bot.LastRunError)
	}
	if bot.ContinueRunID != runID {
		t.Fatalf("continue %q", bot.ContinueRunID)
	}
	page := readThread(t, srv.URL, bot.ID)
	if threadNotice(page) != "Notice: "+body {
		t.Fatalf("notice %q", threadNotice(page))
	}
	replies := botReplies(page)
	if len(replies) != 1 || replies[0].Content != kept || !replies[0].TimedOut {
		t.Fatalf("replies %#v", replies)
	}
	if timedOutPartialBytes(t, srv.URL) != len(kept) {
		t.Fatalf("partial_bytes %d", timedOutPartialBytes(t, srv.URL))
	}
	if !sawStreamReset(app, runID, "stall_timeout") {
		t.Fatal("no stream_reset")
	}
	if len(mdl.snapshot()) != 2 {
		t.Fatalf("calls %d", len(mdl.snapshot()))
	}
}

func TestFirstOutputTimeoutWithoutPartialHasNoContinue(t *testing.T) {
	mdl := &seqModel{steps: []func(context.Context, model.ChatRequest, func(string)) (model.ChatResponse, error){
		func(context.Context, model.ChatRequest, func(string)) (model.ChatResponse, error) {
			return model.ChatResponse{}, &model.TimeoutError{Limit: "first_output_timeout", After: 5 * time.Minute}
		},
		func(context.Context, model.ChatRequest, func(string)) (model.ChatResponse, error) {
			return model.ChatResponse{}, &model.TimeoutError{Limit: "first_output_timeout", After: 5 * time.Minute}
		},
	}}
	app := newApp(t, "", mdl)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Ada")
	runID := postUser(t, srv.URL, bot.ID, "hi")
	bot = waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "timeout"
	})
	const body = "The model sent no output within 5m (first_output_timeout). Retried once."
	if bot.LastRunError != body || bot.ContinueRunID != "" {
		t.Fatalf("status %s error %q continue %q", bot.LastRunStatus, bot.LastRunError, bot.ContinueRunID)
	}
	page := readThread(t, srv.URL, bot.ID)
	if threadNotice(page) != "Notice: "+body {
		t.Fatalf("notice %q", threadNotice(page))
	}
	if len(botReplies(page)) != 0 {
		t.Fatalf("replies %#v", botReplies(page))
	}
	if timedOutPartialBytes(t, srv.URL) != 0 {
		t.Fatalf("partial_bytes %d", timedOutPartialBytes(t, srv.URL))
	}
	waitRunReleased(t, app, bot.ID)
	res, b := postContinue(t, srv.URL, bot.ID, runID)
	if res.StatusCode != http.StatusNotFound || !strings.Contains(string(b), "not found") {
		t.Fatalf("continue %d %s", res.StatusCode, b)
	}
}

func TestRetryWhileClosing(t *testing.T) {
	mdl := &seqModel{steps: []func(context.Context, model.ChatRequest, func(string)) (model.ChatResponse, error){
		func(_ context.Context, _ model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
			if onToken != nil {
				onToken("Half")
			}
			return model.ChatResponse{}, &model.TimeoutError{Limit: "stall_timeout", After: time.Minute, GotOutput: true, Partial: "Half"}
		},
		func(_ context.Context, _ model.ChatRequest, onToken func(string)) (model.ChatResponse, error) {
			if onToken != nil {
				onToken("fresh")
			}
			return model.ChatResponse{Content: "fresh"}, nil
		},
	}}
	app := newApp(t, "", mdl)
	setPolicy(app, func(p *policy.Policy) {
		p.OllamaStallRetries = 0
		p.OllamaStallRetriesSet = true
	})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Ada")
	runID := postUser(t, srv.URL, bot.ID, "hi")
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "timeout"
	})
	waitRunReleased(t, app, bot.ID)

	app.rtMu.Lock()
	app.closing = true
	app.rtMu.Unlock()
	res, b := postRetry(t, srv.URL, bot.ID, runID)
	if res.StatusCode != http.StatusConflict || !strings.Contains(string(b), "shutting down") {
		t.Fatalf("closing %d %s", res.StatusCode, b)
	}
	res, b = postRetry(t, srv.URL, bot.ID, "no-such-run")
	if res.StatusCode != http.StatusConflict || !strings.Contains(string(b), "shutting down") {
		t.Fatalf("unknown run while closing %d %s", res.StatusCode, b)
	}
	app.rtMu.Lock()
	app.closing = false
	app.rtMu.Unlock()
	res, b = postRetry(t, srv.URL, bot.ID, runID)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("cleared %d %s", res.StatusCode, b)
	}
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "done"
	})
}

func ollamaPolicyApp(t *testing.T, body string, ol *model.Ollama) (*App, *httptest.Server, policy.Policy) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(policy.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	app := newApp(t, "", ol)
	app.rtMu.Lock()
	app.setPol(pol)
	app.rtMu.Unlock()
	return app, serve(t, app), pol
}

func assertModelCapAudit(t *testing.T, base, limitValue string, requests int32) {
	t.Helper()
	if requests != 1 {
		t.Fatalf("requests %d", requests)
	}
	if retryLogs(t, base) != 0 {
		t.Fatalf("retries %d", retryLogs(t, base))
	}
	calls := logKind(t, base, "model_call")
	if len(calls) != 1 {
		t.Fatalf("model_call events %d", len(calls))
	}
	var call struct {
		OK         bool   `json:"ok"`
		Retry      bool   `json:"retry"`
		Limit      string `json:"limit"`
		LimitValue string `json:"limit_value"`
	}
	if err := json.Unmarshal(calls[0].Detail, &call); err != nil {
		t.Fatal(err)
	}
	if call.OK || call.Retry || call.Limit != "model_timeout" || call.LimitValue != limitValue {
		t.Fatalf("model_call ok=%v retry=%v limit=%s value=%s", call.OK, call.Retry, call.Limit, call.LimitValue)
	}
	events := logKind(t, base, "run_timed_out")
	if len(events) != 1 {
		t.Fatalf("run_timed_out events %d", len(events))
	}
	var timed struct {
		Limit      string `json:"limit"`
		LimitValue string `json:"limit_value"`
	}
	if err := json.Unmarshal(events[0].Detail, &timed); err != nil {
		t.Fatal(err)
	}
	if timed.Limit != "model_timeout" || timed.LimitValue != limitValue {
		t.Fatalf("run_timed_out limit=%s value=%s", timed.Limit, timed.LimitValue)
	}
}

func streamResetCount(app *App, runID string) int {
	hist, ch := app.bus.Subscribe(runID)
	app.bus.Unsubscribe(runID, ch)
	n := 0
	for _, f := range hist {
		if f.event == "stream_reset" {
			n++
		}
	}
	return n
}

func sawTokenText(app *App, runID, text string) bool {
	hist, ch := app.bus.Subscribe(runID)
	app.bus.Unsubscribe(runID, ch)
	for _, f := range hist {
		if f.event != "token" {
			continue
		}
		var payload struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(f.data, &payload) == nil && payload.Text == text {
			return true
		}
	}
	return false
}

const prodSilenceTOML = "[ollama]\nmodel_timeout = \"10m\"\nrun_timeout = \"30m\"\n"

func TestInheritedSilenceAtModelCapIsNotRetried(t *testing.T) {
	// Prod shape, no silence keys. The model sends nothing past the 10m cap.
	// The inherited silence limit equals that cap, so this is one model_timeout
	// and not a retried first_output_timeout.
	clk := newFakeClock()
	clk.latestFirst = true
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		requests.Add(1)
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Stay open until the client aborts. Returning here would close the
		// body and the call could look like a short success.
		go clk.Advance(11 * time.Minute)
		<-r.Context().Done()
	}))
	defer upstream.Close()
	ol := model.NewOllama(upstream.URL)
	ol.SetClock(&model.Clock{Now: clk.Now, AfterFunc: clk.AfterFunc})
	app, srv, pol := ollamaPolicyApp(t, prodSilenceTOML, ol)
	if pol.EffectiveOllamaFirstOutputTimeout() != 10*time.Minute ||
		pol.EffectiveOllamaStallTimeout() != 10*time.Minute ||
		pol.EffectiveOllamaModelTimeout() != 10*time.Minute ||
		pol.EffectiveOllamaRunTimeout() != 30*time.Minute {
		t.Fatalf("resolved first=%s stall=%s model=%s run=%s",
			pol.EffectiveOllamaFirstOutputTimeout(), pol.EffectiveOllamaStallTimeout(),
			pol.EffectiveOllamaModelTimeout(), pol.EffectiveOllamaRunTimeout())
	}
	bot := createBot(t, srv.URL, "Ada")
	runID := postUser(t, srv.URL, bot.ID, "hi")
	bot = waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool { return b.Status != "running" })
	const body = "The model call hit its 10m limit (model_timeout)."
	if bot.LastRunStatus != "timeout" || bot.LastRunError != body {
		t.Fatalf("status %s %q requests %d", bot.LastRunStatus, bot.LastRunError, requests.Load())
	}
	assertModelCapAudit(t, srv.URL, "10m", requests.Load())
	if streamResetCount(app, runID) != 0 {
		t.Fatal("stream_reset")
	}
	page := readThread(t, srv.URL, bot.ID)
	if threadNotice(page) != "Notice: "+body {
		t.Fatalf("notice %q", threadNotice(page))
	}
	if len(botReplies(page)) != 0 {
		t.Fatalf("replies %#v", botReplies(page))
	}
}

func TestInheritedStallAtModelCapKeepsPartial(t *testing.T) {
	// Prod shape. Some content, then silence through the 10m cap.
	// The inherited stall limit equals the cap, so the partial is kept
	// as model_timeout and the call is not retried.
	clk := newFakeClock()
	clk.latestFirst = true
	var requests atomic.Int32
	release := make(chan struct{})
	wrote := make(chan struct{})
	var wroteOnce sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		n := requests.Add(1)
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		if f != nil {
			f.Flush()
		}
		if n == 1 {
			_, _ = io.WriteString(w, "{\"message\":{\"role\":\"assistant\",\"content\":\"Hello\"}}\n")
			if f != nil {
				f.Flush()
			}
			wroteOnce.Do(func() { close(wrote) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		go clk.Advance(11 * time.Minute)
		<-r.Context().Done()
	}))
	defer upstream.Close()
	ol := model.NewOllama(upstream.URL)
	ol.SetClock(&model.Clock{Now: clk.Now, AfterFunc: clk.AfterFunc})
	app, srv, _ := ollamaPolicyApp(t, prodSilenceTOML, ol)
	bot := createBot(t, srv.URL, "Ada")
	runID := postUser(t, srv.URL, bot.ID, "hi")
	select {
	case <-wrote:
	case <-time.After(5 * time.Second):
		t.Fatal("model produced no chunk")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !sawTokenText(app, runID, "Hello") {
		if time.Now().After(deadline) {
			t.Fatal("token not streamed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	bot = waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool { return b.Status != "running" })
	const body = "The model call hit its 10m limit (model_timeout). The partial reply is kept above."
	if bot.LastRunStatus != "timeout" || bot.LastRunError != body {
		t.Fatalf("status %s %q requests %d", bot.LastRunStatus, bot.LastRunError, requests.Load())
	}
	assertModelCapAudit(t, srv.URL, "10m", requests.Load())
	if streamResetCount(app, runID) != 0 {
		t.Fatal("stream_reset")
	}
	page := readThread(t, srv.URL, bot.ID)
	if threadNotice(page) != "Notice: "+body {
		t.Fatalf("notice %q", threadNotice(page))
	}
	replies := botReplies(page)
	if len(replies) != 1 || replies[0].Content != "Hello" || !replies[0].TimedOut {
		t.Fatalf("replies %#v", replies)
	}
}

func TestShortModelTimeoutWithoutSilenceKeys(t *testing.T) {
	// Real clock. model_timeout 4s and no silence keys: one request, done
	// before a retry could finish (under 8s).
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		requests.Add(1)
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	}))
	defer upstream.Close()
	ol := model.NewOllama(upstream.URL)
	app, srv, pol := ollamaPolicyApp(t, "[ollama]\nmodel_timeout = \"4s\"\n", ol)
	if pol.EffectiveOllamaModelTimeout() != 4*time.Second ||
		pol.EffectiveOllamaFirstOutputTimeout() != 4*time.Second ||
		pol.EffectiveOllamaStallTimeout() != 4*time.Second {
		t.Fatalf("resolved model=%s first=%s stall=%s",
			pol.EffectiveOllamaModelTimeout(), pol.EffectiveOllamaFirstOutputTimeout(), pol.EffectiveOllamaStallTimeout())
	}
	bot := createBot(t, srv.URL, "Ada")
	start := time.Now()
	runID := postUser(t, srv.URL, bot.ID, "hi")
	bot = waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool { return b.Status != "running" })
	elapsed := time.Since(start)
	const body = "The model call hit its 4s limit (model_timeout)."
	if bot.LastRunStatus != "timeout" || bot.LastRunError != body {
		t.Fatalf("status %s %q requests %d elapsed %s", bot.LastRunStatus, bot.LastRunError, requests.Load(), elapsed)
	}
	if elapsed >= 8*time.Second {
		t.Fatalf("elapsed %s, want < 8s", elapsed)
	}
	assertModelCapAudit(t, srv.URL, "4s", requests.Load())
	if streamResetCount(app, runID) != 0 {
		t.Fatal("stream_reset")
	}
}
