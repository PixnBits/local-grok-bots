package model

import "context"

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
}

type ChatResponse struct {
	Content      string
	ToolCalls    []ToolCall
	PromptTokens int
	OutputTokens int
}

// Client talks to a local model. onToken is called for streamed text deltas.
type Client interface {
	Chat(ctx context.Context, req ChatRequest, onToken func(string)) (ChatResponse, error)
}
