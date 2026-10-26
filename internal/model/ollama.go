package model

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Ollama is an HTTP client for a local Ollama daemon.
type Ollama struct {
	BaseURL string
	HTTP    *http.Client
	// clk, when set via SetClock, replaces the process clock for the stall
	// watchdog and for TimeoutContext. The zero value uses time.Now.
	clk callClock
}

func NewOllama(base string) *Ollama {
	return &Ollama{
		BaseURL: strings.TrimRight(base, "/"),
		HTTP:    &http.Client{}, // streaming; timeout lives on the request context
	}
}

type wireMessage struct {
	Role      string         `json:"role"`
	Content   string         `json:"content"`
	Thinking  string         `json:"thinking,omitempty"`
	ToolCalls []wireToolCall `json:"tool_calls,omitempty"`
	ToolName  string         `json:"tool_name,omitempty"`
}

type wireToolCall struct {
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

type wireTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Parameters  any    `json:"parameters"`
	} `json:"function"`
}

type ollamaChunk struct {
	Message         wireMessage `json:"message"`
	Done            bool        `json:"done"`
	DoneReason      string      `json:"done_reason"`
	Error           string      `json:"error"`
	PromptEvalCount int         `json:"prompt_eval_count"`
	EvalCount       int         `json:"eval_count"`
}

func (o *Ollama) Chat(ctx context.Context, req ChatRequest, onToken func(string)) (ChatResponse, error) {
	body := map[string]any{
		"model":    req.Model,
		"messages": toWire(req.Messages),
		"stream":   true,
	}
	if len(req.Tools) > 0 {
		body["tools"] = toWireTools(req.Tools)
	}
	if req.KeepAlive != nil && req.KeepAlive != "" {
		body["keep_alive"] = req.KeepAlive
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return ChatResponse{}, err
	}
	// callCtx is cancelled by the stall watchdog without cancelling the
	// caller's hard cap. A parent deadline still cancels this request.
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	clk := o.activeClock()
	started := clk.now()
	w := newWatchdog(cancel, started, req.FirstOutputTimeout, req.StallTimeout, clk.afterFunc)
	defer w.stop()

	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, o.BaseURL+"/api/chat", bytes.NewReader(raw))
	if err != nil {
		return ChatResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := o.HTTP.Do(httpReq)
	if err != nil {
		if te := w.timeout(""); te != nil {
			return ChatResponse{FirstOutput: te.FirstOutput}, te
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			te := modelTimeout(ctx, started, w.snapshot(), clk.now)
			return ChatResponse{FirstOutput: te.FirstOutput}, te
		}
		return ChatResponse{}, fmt.Errorf("ollama unreachable at %s: %w", o.BaseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(b))
		if msg == "" {
			msg = resp.Status
		}
		return ChatResponse{}, fmt.Errorf("ollama at %s returned %s", o.BaseURL, msg)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var content strings.Builder
	var calls []ToolCall
	var out ChatResponse
	sawDone := false
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var chunk ollamaChunk
		if err := json.Unmarshal(line, &chunk); err != nil {
			return ChatResponse{}, fmt.Errorf("ollama stream: %w", err)
		}
		if chunk.Error != "" {
			if parseErr, ok := AsToolCallParseError(chunk.Error); ok {
				return ChatResponse{}, parseErr
			}
			return ChatResponse{}, fmt.Errorf("ollama: %s", chunk.Error)
		}
		if chunkIsOutput(chunk) {
			w.activity(clk.now())
		}
		if chunk.Message.Content != "" {
			content.WriteString(chunk.Message.Content)
			if onToken != nil {
				onToken(chunk.Message.Content)
			}
		}
		if parsed := parseToolCalls(chunk.Message.ToolCalls); len(parsed) > 0 {
			calls = mergeCalls(calls, parsed)
		}
		if chunk.Done {
			sawDone = true
			out.PromptTokens = chunk.PromptEvalCount
			out.OutputTokens = chunk.EvalCount
		}
	}
	partial := content.String()
	out.Content = partial
	out.ToolCalls = calls
	out.FirstOutput = w.elapsedToFirst()
	if err := sc.Err(); err != nil && !sawDone {
		if te := w.timeout(partial); te != nil {
			out.FirstOutput = te.FirstOutput
			return out, te
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			te := modelTimeout(ctx, started, w.snapshot(), clk.now)
			te.Partial = partial
			out.FirstOutput = te.FirstOutput
			return out, te
		}
		return out, fmt.Errorf("ollama stream: %w", err)
	}
	if te := w.timeout(partial); te != nil && !sawDone {
		out.FirstOutput = te.FirstOutput
		return out, te
	}
	return out, nil
}

// chunkIsOutput reports a chunk that counts as model activity: content,
// thinking, tool calls, or the final done line. Thinking is not copied
// into the reply.
func chunkIsOutput(ch ollamaChunk) bool {
	if ch.Done || ch.Message.Content != "" || ch.Message.Thinking != "" {
		return true
	}
	return len(ch.Message.ToolCalls) > 0
}

func modelTimeout(ctx context.Context, started time.Time, snap watchdogSnap, now func() time.Time) *TimeoutError {
	if now == nil {
		now = time.Now
	}
	after := now().Sub(started)
	if dl, ok := ctx.Deadline(); ok {
		if d := dl.Sub(started); d > 0 {
			after = d
		}
	}
	return &TimeoutError{
		Limit:       "model_timeout",
		After:       after,
		GotOutput:   snap.got,
		FirstOutput: snap.first,
	}
}

// watchdog cancels the request when the first output, or the gap since the
// last output, exceeds its limit. A generation counter drops a timer that
// lost the race with a newer chunk.
type watchdog struct {
	mu       sync.Mutex
	cancel   context.CancelFunc
	started  time.Time
	firstLim time.Duration
	stallLim time.Duration
	after    func(time.Duration, func()) ClockTimer
	timer    ClockTimer
	gen      int
	got      bool
	first    time.Duration
	fired    *TimeoutError
}

type watchdogSnap struct {
	got   bool
	first time.Duration
}

func newWatchdog(cancel context.CancelFunc, started time.Time, first, stall time.Duration, after func(time.Duration, func()) ClockTimer) *watchdog {
	if after == nil {
		after = func(d time.Duration, f func()) ClockTimer { return time.AfterFunc(d, f) }
	}
	w := &watchdog{cancel: cancel, started: started, firstLim: first, stallLim: stall, after: after}
	if first > 0 {
		w.arm(first)
	}
	return w
}

func (w *watchdog) arm(d time.Duration) {
	w.gen++
	gen := w.gen
	if w.timer != nil {
		w.timer.Stop()
	}
	w.timer = w.after(d, func() { w.fire(gen) })
}

func (w *watchdog) fire(gen int) {
	w.mu.Lock()
	var cancel context.CancelFunc
	if gen == w.gen && w.fired == nil {
		limit := "first_output_timeout"
		after := w.firstLim
		if w.got {
			limit = "stall_timeout"
			after = w.stallLim
		}
		w.fired = &TimeoutError{Limit: limit, After: after, GotOutput: w.got, FirstOutput: w.first}
		cancel = w.cancel
	}
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (w *watchdog) activity(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired != nil {
		return
	}
	if !w.got {
		w.got = true
		w.first = now.Sub(w.started)
	}
	if w.stallLim > 0 {
		w.arm(w.stallLim)
		return
	}
	w.gen++
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
}

func (w *watchdog) elapsedToFirst() time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.first
}

func (w *watchdog) snapshot() watchdogSnap {
	w.mu.Lock()
	defer w.mu.Unlock()
	return watchdogSnap{got: w.got, first: w.first}
}

func (w *watchdog) timeout(partial string) *TimeoutError {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired == nil {
		return nil
	}
	te := *w.fired
	te.Partial = partial
	te.GotOutput = w.got
	te.FirstOutput = w.first
	return &te
}

func (w *watchdog) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.gen++
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
}

func toWire(msgs []Message) []wireMessage {
	out := make([]wireMessage, 0, len(msgs))
	for _, m := range msgs {
		w := wireMessage{Role: m.Role, Content: m.Content, ToolName: m.ToolName}
		for _, tc := range m.ToolCalls {
			args, _ := json.Marshal(tc.Arguments)
			var wt wireToolCall
			wt.Function.Name = tc.Name
			wt.Function.Arguments = args
			w.ToolCalls = append(w.ToolCalls, wt)
		}
		out = append(out, w)
	}
	return out
}

func toWireTools(tools []Tool) []wireTool {
	out := make([]wireTool, 0, len(tools))
	for _, t := range tools {
		var w wireTool
		w.Type = "function"
		w.Function.Name = t.Name
		w.Function.Description = t.Description
		if t.Parameters == nil {
			w.Function.Parameters = map[string]any{"type": "object", "properties": map[string]any{}}
		} else {
			w.Function.Parameters = t.Parameters
		}
		out = append(out, w)
	}
	return out
}

func parseToolCalls(in []wireToolCall) []ToolCall {
	out := make([]ToolCall, 0, len(in))
	for _, c := range in {
		if c.Function.Name == "" {
			continue
		}
		out = append(out, ToolCall{Name: c.Function.Name, Arguments: parseArgs(c.Function.Arguments)})
	}
	return out
}

func parseArgs(raw json.RawMessage) map[string]any {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return map[string]any{}
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			raw = bytes.TrimSpace([]byte(s))
		}
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil && m != nil {
		return m
	}
	return map[string]any{}
}

func mergeCalls(dst, next []ToolCall) []ToolCall {
	if len(next) == 0 {
		return dst
	}
	if len(next) >= len(dst) && callsPrefix(next, dst) {
		return next
	}
	return append(dst, next...)
}

func callsPrefix(all, prefix []ToolCall) bool {
	if len(prefix) > len(all) {
		return false
	}
	for i := range prefix {
		if all[i].Name != prefix[i].Name {
			return false
		}
	}
	return true
}
