package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// acpFakeMain is the Grok process inside the jail. The test hardlinks this
// binary to bin/grok and sets LGB_ACP_FAKE. It speaks ACP and asks the host
// when LGB_ACP_MODE says so. It does not use the network.
func acpFakeMain() {
	logACPArgs()
	mode := os.Getenv("LGB_ACP_MODE")
	if mode == "" {
		mode = "ok"
	}
	if mode == "hang" {
		time.Sleep(time.Hour)
		os.Exit(0)
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	if !readACP(sc) {
		os.Exit(1)
	}
	writeACPResult(sc.Text(), map[string]any{
		"protocolVersion":   1,
		"agentCapabilities": map[string]any{"loadSession": true},
	})
	if !readACP(sc) {
		os.Exit(1)
	}
	const sid = "acp-session"
	writeACPResult(sc.Text(), map[string]any{"sessionId": sid})
	if !readACP(sc) {
		os.Exit(1)
	}
	prompt := sc.Text()
	switch mode {
	case "exit":
		writeACP(map[string]any{
			"jsonrpc": "2.0",
			"method":  "session/update",
			"params": map[string]any{
				"sessionId": sid,
				"update": map[string]any{
					"sessionUpdate": "agent_message_chunk",
					"content":       map[string]any{"type": "text", "text": "partial"},
				},
			},
		})
		os.Exit(0)
	case "malformed":
		writeACP(map[string]any{
			"jsonrpc": "2.0",
			"id":      7,
			"method":  "session/request_permission",
			"params":  map[string]any{"sessionId": sid},
		})
		readACP(sc)
		os.Exit(0)
	case "always-only":
		waitACPGate()
		writeACPPerm(sid, 8, true)
		readACP(sc)
		os.Exit(0)
	case "ask":
		waitACPGate()
		n := acpCount()
		for i := 0; i < n; i++ {
			writeACPPerm(sid, 10+i, false)
			if !readACP(sc) {
				os.Exit(0)
			}
			if acpOption(sc.Text()) == "reject-once" {
				writeACPResult(prompt, map[string]any{"stopReason": "cancelled"})
				os.Exit(0)
			}
		}
		writeACP(map[string]any{
			"jsonrpc": "2.0",
			"method":  "session/update",
			"params": map[string]any{
				"sessionId": sid,
				"update": map[string]any{
					"sessionUpdate": "agent_message_chunk",
					"content":       map[string]any{"type": "text", "text": "done"},
				},
			},
		})
		writeACPResult(prompt, map[string]any{"stopReason": "end_turn"})
		os.Exit(0)
	default:
		writeACP(map[string]any{
			"jsonrpc": "2.0",
			"method":  "session/update",
			"params": map[string]any{
				"sessionId": sid,
				"update": map[string]any{
					"sessionUpdate": "agent_message_chunk",
					"content":       map[string]any{"type": "text", "text": "hello"},
				},
			},
		})
		writeACPResult(prompt, map[string]any{"stopReason": "end_turn"})
		os.Exit(0)
	}
}

func readACP(sc *bufio.Scanner) bool {
	if !sc.Scan() {
		return false
	}
	logACPLine(sc.Text())
	return true
}

func writeACPResult(req string, result any) {
	var head struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal([]byte(req), &head)
	id := head.ID
	if len(id) == 0 {
		id = json.RawMessage("0")
	}
	writeACP(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeACP(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	fmt.Printf("%s\n", b)
}

func writeACPPerm(sid string, id int, alwaysOnly bool) {
	variant := os.Getenv("LGB_ACP_VARIANT")
	name := os.Getenv("LGB_ACP_NAME")
	command := os.Getenv("LGB_ACP_COMMAND")
	path := os.Getenv("LGB_ACP_PATH")
	raw := map[string]any{}
	if variant != "" {
		raw["variant"] = variant
	}
	if command != "" {
		raw["command"] = command
	}
	if path != "" {
		raw["target_file"] = path
	}
	input := map[string]any{}
	if command != "" {
		input["command"] = command
	}
	if path != "" {
		input["path"] = path
	}
	call := map[string]any{
		"toolCallId": fmt.Sprintf("t%d", id),
		"kind":       "execute",
		"title":      "tool",
		"rawInput":   raw,
	}
	if name != "" || len(input) > 0 {
		call["_meta"] = map[string]any{
			"x.ai/tool": map[string]any{"name": name, "input": input},
		}
	}
	opts := []any{
		map[string]any{"optionId": "always-allow", "kind": "allow_always", "name": "Always"},
		map[string]any{"optionId": "allow-once", "kind": "allow_once", "name": "Once"},
		map[string]any{"optionId": "reject-once", "kind": "reject_once", "name": "Reject"},
	}
	if alwaysOnly {
		opts = opts[:1]
	}
	writeACP(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "session/request_permission",
		"params": map[string]any{
			"sessionId": sid,
			"toolCall":  call,
			"options":   opts,
		},
	})
}

func acpOption(line string) string {
	var msg struct {
		Result struct {
			Outcome struct {
				OptionID string `json:"optionId"`
			} `json:"outcome"`
		} `json:"result"`
	}
	if json.Unmarshal([]byte(line), &msg) != nil {
		return ""
	}
	return msg.Result.Outcome.OptionID
}

func acpCount() int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("LGB_ACP_COUNT")))
	if err != nil || n < 1 {
		return 1
	}
	return n
}

func waitACPGate() {
	p := strings.TrimSpace(os.Getenv("LGB_ACP_GATE"))
	if p == "" {
		return
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func logACPArgs() {
	p := os.Getenv("LGB_ARGV_LOG")
	if p == "" {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, strings.Join(os.Args[1:], "\n"))
	fmt.Fprintln(f, "---")
}

func logACPLine(line string) {
	p := os.Getenv("LGB_STDIN_LOG")
	if p == "" {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	io.WriteString(f, line+"\n")
}
