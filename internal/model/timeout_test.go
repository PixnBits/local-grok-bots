package model

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeNDJSON(w http.ResponseWriter, f http.Flusher, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	_, _ = w.Write(append(b, '\n'))
	f.Flush()
}

func hangUntilCancel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	<-r.Context().Done()
}

func TestStallBeforeFirstChunk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(hangUntilCancel))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := NewOllama(srv.URL).Chat(ctx, ChatRequest{
		Model:              "m",
		FirstOutputTimeout: 40 * time.Millisecond,
		StallTimeout:       time.Second,
	}, nil)
	var te *TimeoutError
	if !errors.As(err, &te) || te.Limit != "first_output_timeout" || te.GotOutput || te.Partial != "" {
		t.Fatalf("%v", err)
	}
	if te.After != 40*time.Millisecond {
		t.Fatalf("after %s", te.After)
	}
}

func TestStallMidStreamKeepsPartial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		f := w.(http.Flusher)
		w.WriteHeader(http.StatusOK)
		writeNDJSON(w, f, map[string]any{
			"message": map[string]any{"role": "assistant", "content": "Hello"},
		})
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var streamed string
	_, err := NewOllama(srv.URL).Chat(ctx, ChatRequest{
		Model:              "m",
		FirstOutputTimeout: time.Second,
		StallTimeout:       40 * time.Millisecond,
	}, func(s string) { streamed += s })
	var te *TimeoutError
	if !errors.As(err, &te) || te.Limit != "stall_timeout" || te.Partial != "Hello" || !te.GotOutput {
		t.Fatalf("%v", err)
	}
	if streamed != "Hello" || te.FirstOutput <= 0 {
		t.Fatalf("stream %q first %s", streamed, te.FirstOutput)
	}
}

func TestSteadyTrickleDoesNotStall(t *testing.T) {
	const chunks = 30
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		f := w.(http.Flusher)
		w.WriteHeader(http.StatusOK)
		for i := 0; i < chunks; i++ {
			writeNDJSON(w, f, map[string]any{
				"message": map[string]any{"role": "assistant", "content": "x"},
			})
			time.Sleep(20 * time.Millisecond)
		}
		writeNDJSON(w, f, map[string]any{
			"message": map[string]any{"role": "assistant", "content": "!"},
			"done":    true,
		})
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	// Gaps stay under the stall limit. The whole call is longer than both limits.
	resp, err := NewOllama(srv.URL).Chat(ctx, ChatRequest{
		Model:              "m",
		FirstOutputTimeout: 200 * time.Millisecond,
		StallTimeout:       100 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("x", chunks) + "!"
	if resp.Content != want {
		t.Fatalf("content %q", resp.Content)
	}
	if resp.FirstOutput <= 0 {
		t.Fatal("missing first output")
	}
}

func TestThinkingChunkResetsStall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		f := w.(http.Flusher)
		w.WriteHeader(http.StatusOK)
		writeNDJSON(w, f, map[string]any{
			"message": map[string]any{"role": "assistant", "content": "A"},
		})
		time.Sleep(60 * time.Millisecond)
		writeNDJSON(w, f, map[string]any{
			"message": map[string]any{"role": "assistant", "thinking": "hmm"},
		})
		time.Sleep(60 * time.Millisecond)
		writeNDJSON(w, f, map[string]any{
			"message": map[string]any{"role": "assistant", "content": "B"},
			"done":    true,
		})
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Each gap is under the stall limit. The gap from "A" to "B" is not,
	// so the run only succeeds because the thinking chunk is activity.
	resp, err := NewOllama(srv.URL).Chat(ctx, ChatRequest{
		Model:              "m",
		FirstOutputTimeout: time.Second,
		StallTimeout:       100 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Content != "AB" {
		t.Fatalf("content %q", resp.Content)
	}
}

func TestModelTimeoutHardCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(hangUntilCancel))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err := NewOllama(srv.URL).Chat(ctx, ChatRequest{
		Model:              "m",
		FirstOutputTimeout: time.Second,
		StallTimeout:       time.Second,
	}, nil)
	var te *TimeoutError
	if !errors.As(err, &te) || te.Limit != "model_timeout" {
		t.Fatalf("%v", err)
	}
}

// deadlineParent reports a deadline and never cancels. The watchdog is the
// only thing that ends the call, so a limit equal to that deadline is a tie
// Chat would otherwise classify as first_output_timeout.
type deadlineParent struct {
	context.Context
	at time.Time
}

func (d deadlineParent) Deadline() (time.Time, bool) { return d.at, true }

func TestWatchdogTiePrefersModelTimeout(t *testing.T) {
	const limit = 10 * time.Minute
	clk := newTieClock()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Stay open until the client aborts so a clean EOF is not a success.
		go clk.Advance(limit)
		<-r.Context().Done()
	}))
	defer srv.Close()
	ol := NewOllama(srv.URL)
	ol.SetClock(&Clock{Now: clk.Now, AfterFunc: clk.AfterFunc})
	ctx := deadlineParent{Context: context.Background(), at: clk.Now().Add(limit)}
	_, err := ol.Chat(ctx, ChatRequest{
		Model:              "m",
		FirstOutputTimeout: limit,
		StallTimeout:       limit,
	}, nil)
	var te *TimeoutError
	if !errors.As(err, &te) || te.Limit != "model_timeout" {
		t.Fatalf("%v", err)
	}
}

type tieClock struct {
	mu     sync.Mutex
	now    time.Time
	nextID int
	timers []*tieTimer
}

type tieTimer struct {
	id      int
	at      time.Time
	fn      func()
	stopped bool
	clock   *tieClock
}

func newTieClock() *tieClock {
	return &tieClock{now: time.Now()}
}

func (c *tieClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *tieClock) AfterFunc(d time.Duration, fn func()) ClockTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d < 0 {
		d = 0
	}
	c.nextID++
	t := &tieTimer{id: c.nextID, at: c.now.Add(d), fn: fn, clock: c}
	c.timers = append(c.timers, t)
	return t
}

func (t *tieTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if t.stopped {
		return false
	}
	t.stopped = true
	return true
}

func (c *tieClock) Advance(d time.Duration) {
	end := c.Now().Add(d)
	for {
		c.mu.Lock()
		var next *tieTimer
		for _, t := range c.timers {
			if t.stopped {
				continue
			}
			if next == nil || t.at.Before(next.at) || (t.at.Equal(next.at) && t.id < next.id) {
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

func TestKeepAliveInRequestBody(t *testing.T) {
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, b)
		w.Header().Set("Content-Type", "application/x-ndjson")
		f := w.(http.Flusher)
		writeNDJSON(w, f, map[string]any{
			"message": map[string]any{"role": "assistant", "content": "ok"},
			"done":    true,
		})
	}))
	defer srv.Close()
	o := NewOllama(srv.URL)
	for _, ka := range []any{"30m", 0, -1} {
		if _, err := o.Chat(context.Background(), ChatRequest{Model: "m", KeepAlive: ka}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(bodies) != 3 {
		t.Fatalf("bodies %d", len(bodies))
	}
	for i, want := range []string{`"keep_alive":"30m"`, `"keep_alive":0`, `"keep_alive":-1`} {
		if !strings.Contains(string(bodies[i]), want) {
			t.Fatalf("body %d %s missing %s", i, bodies[i], want)
		}
	}
}
