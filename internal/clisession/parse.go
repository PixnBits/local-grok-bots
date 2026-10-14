package clisession

import (
	"encoding/json"
	"strings"
)

// Parse reads one streaming JSON line.
// Non-JSON lines are ignored. The daemon does not scrape unstructured stdout.
func Parse(line string) (Event, bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] != '{' {
		return Event{}, false
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return Event{}, false
	}
	typ, _ := raw["type"].(string)
	session := firstString(raw, "sessionId", "session_id")
	if session == "" {
		if params := asMap(raw["params"]); params != nil {
			session = firstString(params, "sessionId", "session_id")
		}
	}
	if isPermissionPrompt(raw) {
		return Event{Kind: "permission", SessionID: session}, true
	}
	stop := firstString(raw, "stopReason", "stop_reason")
	switch typ {
	case "result", "end":
		text := firstString(raw, "text", "result")
		if truthy(raw["is_error"]) {
			msg := firstString(raw, "message", "error", "text", "result")
			return Event{Kind: "error", Text: msg, SessionID: session, StopReason: stop}, true
		}
		ev := Event{
			Kind: "end", SessionID: session, StopReason: stop,
			NeedsInput: needsInput(stop, firstString(raw, "subtype")),
		}
		if text != "" {
			ev.Text = text
			ev.Final = true
		}
		return ev, true
	case "text":
		return Event{Kind: "token", Text: dataString(raw["data"]), SessionID: session}, true
	case "error":
		msg := firstString(raw, "message", "error", "data")
		if msg == "" {
			msg = dataString(raw["data"])
		}
		return Event{Kind: "error", Text: msg, SessionID: session}, true
	case "tool_call":
		name := firstString(raw, "toolName", "tool", "name", "title")
		return Event{Kind: "tool", ToolName: name, ToolArgs: toolArgs(raw), SessionID: session}, true
	case "tool_result":
		name := firstString(raw, "toolName", "tool", "name", "title")
		text := firstString(raw, "result", "output", "content", "text")
		return Event{Kind: "tool_result", ToolName: name, Text: text, SessionID: session}, true
	case "stream_event":
		text := claudeTextDelta(raw["event"])
		if text == "" {
			if session == "" {
				return Event{}, false
			}
			return Event{Kind: "meta", SessionID: session}, true
		}
		return Event{Kind: "token", Text: text, SessionID: session}, true
	case "assistant":
		if name, args := claudeTool(raw["message"]); name != "" {
			return Event{Kind: "tool", ToolName: name, ToolArgs: args, SessionID: session}, true
		}
		if session == "" {
			return Event{}, false
		}
		return Event{Kind: "meta", SessionID: session}, true
	case "system":
		if firstString(raw, "subtype") == "permission_denied" {
			tool := firstString(raw, "tool")
			if tool == "" {
				tool = "permission_denied"
			}
			return Event{Kind: "tool", ToolName: tool, SessionID: session}, true
		}
		if session == "" {
			return Event{}, false
		}
		return Event{Kind: "meta", SessionID: session}, true
	case "user":
		if name, text, ok := claudeToolResult(raw["message"]); ok {
			return Event{Kind: "tool_result", ToolName: name, Text: text, SessionID: session}, true
		}
		if session == "" {
			return Event{}, false
		}
		return Event{Kind: "meta", SessionID: session}, true
	default:
		if session != "" {
			return Event{Kind: "meta", SessionID: session, StopReason: stop}, true
		}
		return Event{}, false
	}
}

func claudeTextDelta(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	delta, ok := m["delta"].(map[string]any)
	if !ok {
		return ""
	}
	typ, _ := delta["type"].(string)
	if typ != "" && typ != "text_delta" {
		return ""
	}
	s, _ := delta["text"].(string)
	return s
}

func claudeTool(v any) (string, map[string]any) {
	m, ok := v.(map[string]any)
	if !ok {
		return "", nil
	}
	content, ok := m["content"].([]any)
	if !ok {
		return "", nil
	}
	for _, item := range content {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := block["type"].(string)
		if typ != "tool_use" {
			continue
		}
		name, _ := block["name"].(string)
		if name == "" {
			continue
		}
		return name, toolArgs(block)
	}
	return "", nil
}

func claudeToolResult(v any) (string, string, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return "", "", false
	}
	content, ok := m["content"].([]any)
	if !ok {
		return "", "", false
	}
	for _, item := range content {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := block["type"].(string)
		if typ != "tool_result" {
			continue
		}
		name := firstString(block, "name", "tool_use_id")
		text := ""
		switch c := block["content"].(type) {
		case string:
			text = c
		default:
			text = dataString(c)
		}
		return name, text, true
	}
	return "", "", false
}

func toolArgs(raw map[string]any) map[string]any {
	for _, key := range []string{"arguments", "args", "input", "parameters"} {
		if m := asMap(raw[key]); m != nil {
			return m
		}
		s, ok := raw[key].(string)
		if !ok || strings.TrimSpace(s) == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(s), &m) == nil {
			return m
		}
	}
	return nil
}

func asMap(v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return m
}

func dataString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		var s string
		if json.Unmarshal(b, &s) == nil {
			return s
		}
		return string(b)
	}
}

func firstString(raw map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := raw[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func truthy(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

func isPermissionPrompt(raw map[string]any) bool {
	if strings.EqualFold(firstString(raw, "method"), "session/request_permission") {
		return true
	}
	typ := strings.ToLower(firstString(raw, "type"))
	sub := strings.ToLower(firstString(raw, "subtype"))
	if sub == "" {
		if req := asMap(raw["request"]); req != nil {
			sub = strings.ToLower(firstString(req, "subtype"))
		}
	}
	switch typ {
	case "permission_request", "permission_prompt":
		return true
	case "control_request", "system":
		return sub == "can_use_tool" || sub == "permission_prompt" || sub == "permission_request"
	}
	return sub == "can_use_tool" || sub == "permission_prompt" || sub == "permission_request"
}

func needsInput(stop, subtype string) bool {
	s := strings.ToLower(stop + " " + subtype)
	if strings.Contains(s, "end_turn") || strings.Contains(s, "endturn") {
		return false
	}
	return strings.Contains(s, "input") || strings.Contains(s, "ask_user") || strings.Contains(s, "askuser")
}
