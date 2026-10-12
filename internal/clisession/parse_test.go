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

func TestParseError(t *testing.T) {
	ev, ok := Parse(`{"type":"error","message":"Couldn't start session: missing"}`)
	if !ok || ev.Kind != "error" || ev.Text == "" {
		t.Fatalf("%+v", ev)
	}
}
