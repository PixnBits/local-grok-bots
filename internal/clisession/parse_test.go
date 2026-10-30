package clisession

import "testing"

func TestParseClaudeStream(t *testing.T) {
	ev, ok := Parse(`{"type":"stream_event","session_id":"s1","event":{"delta":{"type":"text_delta","text":"hi"}}}`)
	if !ok || ev.Kind != "token" || ev.Text != "hi" || ev.SessionID != "s1" {
		t.Fatalf("%+v %v", ev, ok)
	}
	ev, ok = Parse(`{"type":"assistant","session_id":"s1","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"ls"}}]}}`)
	if !ok || ev.Kind != "tool" || ev.ToolName != "Bash" || ev.ToolArgs["command"] != "ls" {
		t.Fatalf("%+v", ev)
	}
	ev, ok = Parse(`{"type":"user","session_id":"s1","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"ok"}]}}`)
	if !ok || ev.Kind != "tool_result" || ev.Text != "ok" || ev.Failed {
		t.Fatalf("%+v", ev)
	}
	ev, ok = Parse(`{"type":"user","session_id":"s1","message":{"content":[{"type":"tool_result","tool_use_id":"t1","is_error":true,"content":"blocked"}]}}`)
	if !ok || ev.Kind != "tool_result" || ev.Text != "blocked" || !ev.Failed {
		t.Fatalf("is_error %+v", ev)
	}
	ev, ok = Parse(`{"type":"tool_result","toolName":"Read","result":"no","is_error":true,"session_id":"s1"}`)
	if !ok || !ev.Failed || ev.Text != "no" {
		t.Fatalf("top level is_error %+v", ev)
	}
	ev, ok = Parse(`{"type":"result","result":"hi","session_id":"s1"}`)
	if !ok || ev.Kind != "end" || !ev.Final || ev.Text != "hi" {
		t.Fatalf("%+v", ev)
	}
	if _, ok := Parse("not json"); ok {
		t.Fatal("scraped unstructured stdout")
	}
}

func TestParseGrokStream(t *testing.T) {
	ev, ok := Parse(`{"type":"tool_call","toolName":"bash","arguments":{"cmd":"pwd"},"session_id":"g"}`)
	if !ok || ev.Kind != "tool" || ev.ToolName != "bash" {
		t.Fatalf("%+v", ev)
	}
	ev, ok = Parse(`{"type":"tool_result","toolName":"bash","result":"/work","session_id":"g"}`)
	if !ok || ev.Kind != "tool_result" || ev.Text != "/work" {
		t.Fatalf("%+v", ev)
	}
}
