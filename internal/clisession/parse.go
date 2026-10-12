package clisession

import (
	"encoding/json"
	"strings"
)

// Parse reads one streaming-json line, or a final json object.
// Non-JSON lines are ignored. Unknown event types are ignored.
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
	stop := firstString(raw, "stopReason", "stop_reason")
	switch typ {
	case "", "end", "result":
		text := firstString(raw, "text", "result")
		ev := Event{
			Kind: "end", SessionID: session, StopReason: stop,
			NeedsInput: needsInput(stop, firstString(raw, "subtype")),
		}
		if text != "" {
			ev.Text = text
			ev.Final = true
		}
		if typ == "" && text == "" && session == "" && stop == "" {
			return Event{}, false
		}
		if truthy(raw["is_error"]) || typ == "error" {
			msg := firstString(raw, "message", "error", "text", "result")
			return Event{Kind: "error", Text: msg, SessionID: session, StopReason: stop}, true
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
		return Event{Kind: "tool", ToolName: name, SessionID: session}, true
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
		if name := claudeToolName(raw["message"]); name != "" {
			return Event{Kind: "tool", ToolName: name, SessionID: session}, true
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

func claudeToolName(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	content, ok := m["content"].([]any)
	if !ok {
		return ""
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
		if name, _ := block["name"].(string); name != "" {
			return name
		}
	}
	return ""
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
		return ""
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

func needsInput(stop, subtype string) bool {
	s := strings.ToLower(stop + " " + subtype)
	if strings.Contains(s, "end_turn") || strings.Contains(s, "endturn") {
		return false
	}
	return strings.Contains(s, "input") || strings.Contains(s, "ask_user") || strings.Contains(s, "askuser")
}
