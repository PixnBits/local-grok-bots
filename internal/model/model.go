package model

import (
	"context"
	"fmt"
	"time"
)

// Message is one turn in a model chat. Tool calls use the flat shape;
// the Ollama client maps them onto Ollama's function envelope.
type Message struct {
	Role      string     `json:"role"`
	Content   string     `json:"content"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	ToolName  string     `json:"tool_name,omitempty"`
}

type ToolCall struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type Tool struct {
	Name        string
	Description string
	Parameters  map[string]any
}

type ChatRequest struct {
	Model    string
	Messages []Message
	Tools    []Tool
	// FirstOutputTimeout is the max wait from send until the first output
	// chunk. StallTimeout is the max gap between output chunks after that.
	// Zero turns that watch off. The caller's context is the hard cap
	// (model_timeout).
	FirstOutputTimeout time.Duration
	StallTimeout       time.Duration
	// KeepAlive is Ollama's keep_alive: a duration string or an integer
	// number of seconds (-1 keeps the model loaded). Nil omits the field.
	KeepAlive any
}

type ChatResponse struct {
	Content      string
	ToolCalls    []ToolCall
	PromptTokens int
	OutputTokens int
	// FirstOutput is the time from send until the first output chunk.
	FirstOutput time.Duration
}

// TimeoutError is a stall, a wait for first output, or the per-call hard cap.
// Partial is assistant content streamed before the deadline.
type TimeoutError struct {
	Limit       string
	After       time.Duration
	GotOutput   bool
	FirstOutput time.Duration
	Partial     string
}

func (e *TimeoutError) Error() string {
	if e == nil {
		return "ollama: timeout"
	}
	return fmt.Sprintf("ollama: %s after %s", e.Limit, e.After)
}

// Client talks to a local model. onToken is called for streamed text deltas.
type Client interface {
	Chat(ctx context.Context, req ChatRequest, onToken func(string)) (ChatResponse, error)
}
