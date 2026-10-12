package clisession

import "testing"

func TestParseGrokStream(t *testing.T) {
	lines := []string{
		`{"type":"thought","data":"Analyzing the directory structure..."}`,
		`{"type":"tool_call","toolCallId":"call_1","toolName":"read_file","status":"in_progress"}`,
		`{"type":"text","data":"Here's a summary"}`,
		`{"type":"usage","messageId":"resp_1","stopReason":"end_turn"}`,
		`{"type":"end","stopReason":"end_turn","sessionId":"abc123","requestId":"xyz789"}`,
	}
	var text string
	var session, tool string
	for _, line := range lines {
		ev, ok := Parse(line)
		if !ok {
			continue
		}
		switch ev.Kind {
		case "token":
			text += ev.Text
		case "tool":
			tool = ev.ToolName
		case "end":
			if ev.SessionID != "" {
				session = ev.SessionID
			}
			if ev.NeedsInput {
				t.Fatal("end_turn is not input")
			}
		default:
			t.Fatalf("kind %s from %s", ev.Kind, line)
		}
	}
	if text != "Here's a summary" || session != "abc123" || tool != "read_file" {
		t.Fatalf("text=%q session=%q tool=%q", text, session, tool)
	}
}

func TestParseGrokFinalJSON(t *testing.T) {
	ev, ok := Parse(`{"text":"Here's a summary of the codebase...","stopReason":"EndTurn","sessionId":"abc123"}`)
	if !ok || ev.Kind != "end" || !ev.Final || ev.SessionID != "abc123" || ev.Text == "" {
		t.Fatalf("%+v ok=%v", ev, ok)
	}
}

func TestParseClaudeStream(t *testing.T) {
	lines := []string{
		`{"type":"system","subtype":"init","session_id":"550e8400-e29b-41d4-a716-446655440000"}`,
		`{"type":"stream_event","session_id":"550e8400-e29b-41d4-a716-446655440000","event":{"delta":{"type":"text_delta","text":"Hi"}}}`,
		`{"type":"assistant","session_id":"550e8400-e29b-41d4-a716-446655440000","message":{"content":[{"type":"text","text":"Hi"},{"type":"tool_use","name":"Bash","input":{}}]}}`,
		`{"type":"result","subtype":"success","result":"Hi there","session_id":"550e8400-e29b-41d4-a716-446655440000","is_error":false}`,
	}
	var text, session, tool string
	var final string
	for _, line := range lines {
		ev, ok := Parse(line)
		if !ok {
			t.Fatalf("dropped %s", line)
		}
		if ev.SessionID != "" {
			session = ev.SessionID
		}
		switch ev.Kind {
		case "token":
			text += ev.Text
		case "tool":
			tool = ev.ToolName
		case "end":
			if ev.Final {
				final = ev.Text
			}
			if ev.NeedsInput {
				t.Fatal("success is not input")
			}
		case "meta":
		default:
			t.Fatalf("kind %s from %s", ev.Kind, line)
		}
	}
	if text != "Hi" || final != "Hi there" || tool != "Bash" || session != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("text=%q final=%q tool=%q session=%q", text, final, tool, session)
	}
}

func TestParseError(t *testing.T) {
	ev, ok := Parse(`{"type":"error","message":"Couldn't start session: missing"}`)
	if !ok || ev.Kind != "error" || ev.Text == "" {
		t.Fatalf("%+v", ev)
	}
}
