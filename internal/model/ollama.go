package model

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Ollama is an HTTP client for a local Ollama daemon.
type Ollama struct {
	BaseURL string
	HTTP    *http.Client
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
	raw, err := json.Marshal(body)
	if err != nil {
		return ChatResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.BaseURL+"/api/chat", bytes.NewReader(raw))
	if err != nil {
		return ChatResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := o.HTTP.Do(httpReq)
	if err != nil {
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
			out.PromptTokens = chunk.PromptEvalCount
			out.OutputTokens = chunk.EvalCount
		}
	}
	if err := sc.Err(); err != nil {
		return ChatResponse{}, fmt.Errorf("ollama stream: %w", err)
	}
	out.Content = content.String()
	out.ToolCalls = calls
	return out, nil
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

// Ensure the client honors a deadline when the caller set one.
var _ = time.Second
