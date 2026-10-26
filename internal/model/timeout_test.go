package model

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
