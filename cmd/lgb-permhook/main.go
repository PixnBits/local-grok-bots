// Command lgb-permhook is the Claude Code PreToolUse hook for the
// permission broker. It is stdlib-only so the jail can ship it without
// the daemon's module graph.
//
// Hook contract, checked 2026-10-29:
// https://code.claude.com/docs/en/hooks
// https://code.claude.com/docs/en/hooks-guide
//
// Exit 2 blocks the tool even when stdout JSON says allow. Any other
// non-zero exit is a non-blocking error and the tool continues unless
// the hook sets onFailure to block. This process therefore exits 2 on
// every doubt, and it also prints a PreToolUse deny. Exit 0 is used
// only for a daemon verdict of exactly "allow", with valid JSON.
// A command hook that exceeds its timeout does not block. The settings
// file sets timeout 30 and onFailure block. This process uses its own
// 2.5s deadline so it returns before that timeout.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const (
	// hookDeadline is well under the 30s settings timeout.
	hookDeadline = 2500 * time.Millisecond
	maxStdin     = 256 * 1024
	maxRequest   = 64 * 1024
	maxReply     = 8 * 1024
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), hookDeadline)
	defer cancel()
	reason, allow := decide(ctx, args, stdin)
	if allow {
		writeVerdict(stdout, stderr, "allow", reason)
		return 0
	}
	writeVerdict(stdout, stderr, "deny", reason)
	return 2
}

func decide(ctx context.Context, args []string, stdin io.Reader) (reason string, allow bool) {
	sock, err := socketArg(args)
	if err != nil {
		return err.Error(), false
	}
	body, err := readStdin(ctx, stdin)
	if err != nil {
		return "hook input rejected", false
	}
	// Extra stdin keys are ignored. Claude adds fields across versions.
	// A malformed body, the wrong event, or an unknown daemon verdict
	// still denies. Reply keys stay strict below.
	var in hookInput
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&in); err != nil {
		return "hook input rejected", false
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return "hook input rejected", false
	}
	if in.HookEvent != "" && in.HookEvent != "PreToolUse" {
		return "hook input rejected", false
	}
	if len(in.ToolInput) > 0 && !json.Valid(in.ToolInput) {
		return "hook input rejected", false
	}
	req := wireRequest{
		Op:             "evaluate",
		HookEvent:      "PreToolUse",
		SessionID:      in.SessionID,
		Cwd:            in.Cwd,
		ToolName:       in.ToolName,
		ToolInput:      in.ToolInput,
		ToolUseID:      in.ToolUseID,
		TranscriptPath: in.Transcript,
	}
	payload, err := json.Marshal(req)
	if err != nil || len(payload) > maxRequest {
		return "hook input rejected", false
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", sock)
	if err != nil {
		return "permission broker unavailable", false
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(hookDeadline)
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(payload); err != nil {
		return "permission broker unavailable", false
	}
	if uc, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = uc.CloseWrite()
	}
	reply, err := readReply(conn)
	if err != nil {
		return "permission broker unavailable", false
	}
	if reply.Verdict != "allow" && reply.Verdict != "deny" {
		return "permission broker unavailable", false
	}
	if reply.Verdict == "allow" {
		if reply.Reason == "" {
			return "allowed", true
		}
		return reply.Reason, true
	}
	if reply.Reason == "" {
		return "denied", false
	}
	return reply.Reason, false
}

func socketArg(args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("permission broker unavailable")
	}
	sock := args[0]
	if sock == "" || sock[0] != '/' {
		return "", fmt.Errorf("permission broker unavailable")
	}
	for _, r := range sock {
		if r == '\n' || r == '\r' || r == 0 {
			return "", fmt.Errorf("permission broker unavailable")
		}
	}
	return sock, nil
}

func readStdin(ctx context.Context, stdin io.Reader) ([]byte, error) {
	done := make(chan struct{})
	var buf []byte
	var err error
	go func() {
		buf, err = io.ReadAll(io.LimitReader(stdin, maxStdin+1))
		close(done)
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
	}
	if err != nil || len(buf) == 0 || len(buf) > maxStdin {
		return nil, fmt.Errorf("stdin")
	}
	return buf, nil
}

func readReply(conn net.Conn) (wireReply, error) {
	buf, err := io.ReadAll(io.LimitReader(conn, maxReply+1))
	if err != nil || len(buf) == 0 || len(buf) > maxReply {
		return wireReply{}, fmt.Errorf("reply")
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.DisallowUnknownFields()
	var reply wireReply
	if err := dec.Decode(&reply); err != nil {
		return wireReply{}, err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return wireReply{}, fmt.Errorf("reply")
	}
	return reply, nil
}

func writeVerdict(stdout, stderr io.Writer, verdict, reason string) {
	if reason == "" {
		reason = "denied"
	}
	if verdict != "allow" {
		fmt.Fprintln(stderr, reason)
	}
	enc := json.NewEncoder(stdout)
	_ = enc.Encode(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       verdict,
			"permissionDecisionReason": reason,
		},
	})
}

// hookInput is the PreToolUse stdin object. Unknown keys are ignored.
// Claude adds fields across versions. A malformed body still denies.
type hookInput struct {
	SessionID  string          `json:"session_id"`
	Cwd        string          `json:"cwd"`
	HookEvent  string          `json:"hook_event_name"`
	ToolName   string          `json:"tool_name"`
	ToolInput  json.RawMessage `json:"tool_input"`
	ToolUseID  string          `json:"tool_use_id"`
	Transcript string          `json:"transcript_path"`
	PromptID   string          `json:"prompt_id"`
	Scratchpad string          `json:"scratchpad_dir"`
	PermMode   string          `json:"permission_mode"`
}

// wireRequest is duplicated in internal/permbroker. The hook cannot
// import that package. Keep the JSON keys aligned.
type wireRequest struct {
	Op             string          `json:"op"`
	HookEvent      string          `json:"hook_event_name"`
	SessionID      string          `json:"session_id"`
	Cwd            string          `json:"cwd"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolUseID      string          `json:"tool_use_id"`
	TranscriptPath string          `json:"transcript_path"`
}

type wireReply struct {
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
}
