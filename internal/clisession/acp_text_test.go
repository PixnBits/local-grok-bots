package clisession

import (
	"context"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestChunkTextKeepsWhitespace(t *testing.T) {
	for _, s := range []string{" ", "\n", "\n\n", "Linux"} {
		got, ok := chunkText(map[string]any{"type": "text", "text": s})
		if !ok || got != s {
			t.Fatalf("chunk %q ok %v", got, ok)
		}
	}
	if _, ok := chunkText(map[string]any{"type": "text"}); ok {
		t.Fatal("missing text was present")
	}
	if strOf(map[string]any{"text": " \n"}, "text") != "" {
		t.Fatal("strOf kept a blank value")
	}
	parts := outputText(map[string]any{"content": []any{
		map[string]any{"type": "text", "text": "Linux"},
		map[string]any{"type": "text", "text": "\n"},
		map[string]any{"type": "text", "text": "Linux"},
	}})
	if parts != "Linux\nLinux" {
		t.Fatalf("output %q", parts)
	}
}

func TestACPKeepsWhitespaceOnlyChunks(t *testing.T) {
	script := `#!/bin/sh
id_of() { printf '%s' "$1" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p'; }
reply() { awk -v line="$1" 'BEGIN{print line; fflush()}'; }
IFS= read -r line || exit 1
id=$(id_of "$line")
reply "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"protocolVersion\":1}}"
IFS= read -r line || exit 1
id=$(id_of "$line")
reply "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"sessionId\":\"s\",\"modes\":{\"currentModeId\":\"default\"}}}"
IFS= read -r line || exit 1
id=$(id_of "$line")
reply '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"Linux"}}}}'
reply '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"\\n"}}}}'
reply '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"Linux"}}}}'
reply '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"https://example.com"}}}}'
reply '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":" "}}}}'
reply '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"200"}}}}'
reply '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"\\n"}}}}'
reply '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"https://example.org"}}}}'
reply '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":" "}}}}'
reply '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"000"}}}}'
reply '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"\\n\\n"}}}}'
reply '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"tail"}}}}'
reply "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"stopReason\":\"end_turn\"}}"
exit 0
`
	res := runACPScript(t, script, Spec{Fresh: true, Prompt: "hi", ACP: quietACP()})
	want := "Linux\nLinuxhttps://example.com 200\nhttps://example.org 000\n\ntail"
	if res.Text != want {
		t.Fatalf("text %q", res.Text)
	}
}

func TestACPLateChunkDoesNotCarry(t *testing.T) {
	script := `#!/bin/sh
id_of() { printf '%s' "$1" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p'; }
reply() { awk -v line="$1" 'BEGIN{print line; fflush()}'; }
IFS= read -r line || exit 1
id=$(id_of "$line")
reply "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"protocolVersion\":1}}"
IFS= read -r line || exit 1
id=$(id_of "$line")
case "$line" in
*session/load*)
  reply '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"a"}}}}'
  reply "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"modes\":{\"currentModeId\":\"default\"}}}"
  IFS= read -r line || exit 1
  id=$(id_of "$line")
  reply '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"https://example.com"}}}}'
  reply "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"stopReason\":\"end_turn\"}}"
  ;;
*)
  reply "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"sessionId\":\"s\",\"modes\":{\"currentModeId\":\"default\"}}}"
  IFS= read -r line || exit 1
  id=$(id_of "$line")
  reply '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hello-from-a"}}}}'
  reply "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"stopReason\":\"end_turn\"}}"
  reply '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"a"}}}}'
  ;;
esac
exit 0
`
	dir := t.TempDir()
	first := runACPScript(t, script, Spec{Workspace: dir, Fresh: true, Prompt: "one", ACP: quietACP()})
	if first.Text != "hello-from-a" || first.SessionID != "s" {
		t.Fatalf("first %+v", first)
	}
	second := runACPScript(t, script, Spec{Workspace: dir, SessionID: first.SessionID, Prompt: "two", ACP: quietACP()})
	if second.Text != "https://example.com" || strings.HasPrefix(second.Text, "a") {
		t.Fatalf("second %q", second.Text)
	}
}

func runACPScript(t *testing.T, script string, spec Spec) Result {
	t.Helper()
	dir := t.TempDir()
	if spec.Workspace == "" {
		spec.Workspace = dir
	}
	bin := writeScript(t, dir, "agent.sh", script)
	cmd := exec.Command(bin)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := runACPSession(ctx, cmd, stdout, stdin, spec, nil)
	waitErr := cmd.Wait()
	if err != nil {
		t.Fatalf("run %v wait %v stderr %s res %+v", err, waitErr, stderr.String(), res)
	}
	// Drain is owned by runACPSession. Wait reaps the process.
	if stdout != nil {
		_, _ = io.Copy(io.Discard, stdout)
	}
	return res
}
