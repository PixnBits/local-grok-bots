package clisession

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParsePermissionPrompts(t *testing.T) {
	cases := []string{
		`{"type":"control_request","request":{"subtype":"can_use_tool","tool_name":"Bash"},"session_id":"s1"}`,
		`{"jsonrpc":"2.0","method":"session/request_permission","params":{"sessionId":"s2"}}`,
		`{"type":"system","subtype":"permission_prompt","session_id":"s3"}`,
		`{"type":"permission_request","session_id":"s4"}`,
	}
	for _, line := range cases {
		ev, ok := Parse(line)
		if !ok || ev.Kind != "permission" || ev.SessionID == "" {
			t.Fatalf("line %s -> %+v ok=%v", line, ev, ok)
		}
	}
	ev, ok := Parse(`{"type":"system","subtype":"permission_denied","session_id":"s","tool":"Bash","tool_input":{"command":"rm -rf /"}}`)
	if !ok || ev.Kind != "permission_decision" || ev.ToolName != "Bash" || ev.ToolArgs["command"] != "rm -rf /" {
		t.Fatalf("denial was treated as a prompt: %+v", ev)
	}
	ev, ok = Parse(`{"type":"result","result":"ok","session_id":"s","permission_denials":[{"tool_name":"Bash","tool_use_id":"tu","tool_input":{"command":"rm -rf /"}}]}`)
	if !ok || ev.Kind != "end" || len(ev.Denials) != 1 || ev.Denials[0].Tool != "Bash" || ev.Denials[0].UseID != "tu" {
		t.Fatalf("result denials %+v", ev)
	}
}

func TestHeadlessPermissionPromptFails(t *testing.T) {
	dir := t.TempDir()
	bin := writeScript(t, dir, "prompt.sh", `#!/bin/sh
printf '%s\n' '{"type":"control_request","request":{"subtype":"can_use_tool","tool_name":"Bash"},"session_id":"sess-prompt"}'
printf '%s\n' '{"type":"result","result":"should-not-finish","session_id":"sess-prompt"}'
sleep 120
`)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var pid int
	res, err := (ExecRunner{HasTTY: func() bool { return false }}).Run(ctx, Spec{
		Backend: "claude", Bin: bin, Fresh: true, SessionID: "pre", Prompt: "hi", Workspace: dir,
		OnStart: func(p int) { pid = p },
	}, nil)
	if !errors.Is(err, ErrPermissionPrompt) {
		t.Fatalf("err %v res %+v", err, res)
	}
	if err.Error() != "permission prompt requires a TTY or an explicit permission_mode" {
		t.Fatalf("error text %q", err.Error())
	}
	if res.SessionID != "sess-prompt" {
		t.Fatalf("session %q", res.SessionID)
	}
	if pid > 0 && pidRunning(pid) {
		t.Fatalf("cli pid %d still running", pid)
	}
}

func TestStderrPermissionPromptDoesNotHang(t *testing.T) {
	dir := t.TempDir()
	bin := writeScript(t, dir, "stderr.sh", `#!/bin/sh
echo 'no hub transport for the permission prompt; rejecting guarded tool' >&2
sleep 120
`)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var pid int
	_, err := (ExecRunner{HasTTY: func() bool { return false }}).Run(ctx, Spec{
		Backend: "grok", Bin: bin, Fresh: true, Prompt: "hi", Workspace: dir,
		Isolate: &Isolation{GrokSandbox: GrokProfile},
		OnStart: func(p int) { pid = p },
	}, nil)
	// Grok turns use the ACP host. With no broker the host fails closed and
	// kills the process. A stderr phrase is not ErrPermissionPrompt.
	if err == nil || errors.Is(err, ErrPermissionPrompt) || !strings.Contains(err.Error(), "acp host") {
		t.Fatalf("err %v", err)
	}
	if pid > 0 && pidRunning(pid) {
		t.Fatalf("cli pid %d still running", pid)
	}
}

func TestPermissionModeOrTTYDoesNotForceFail(t *testing.T) {
	dir := t.TempDir()
	bin := writeScript(t, dir, "finish.sh", `#!/bin/sh
printf '%s\n' '{"type":"control_request","request":{"subtype":"can_use_tool","tool_name":"Bash"}}'
printf '%s\n' '{"type":"result","result":"ok","session_id":"kept"}'
`)
	noTTY := func() bool { return false }
	withMode, err := (ExecRunner{HasTTY: noTTY}).Run(context.Background(), Spec{
		Backend: "claude", Bin: bin, PermissionMode: "bypassPermissions",
		Fresh: true, Prompt: "hi", Workspace: dir,
	}, nil)
	if err != nil || withMode.Text != "ok" || withMode.SessionID != "kept" {
		t.Fatalf("explicit mode: %v %+v", err, withMode)
	}
	withTTY, err := (ExecRunner{HasTTY: func() bool { return true }}).Run(context.Background(), Spec{
		Backend: "claude", Bin: bin, Fresh: true, Prompt: "hi", Workspace: dir,
	}, nil)
	if err != nil || withTTY.Text != "ok" {
		t.Fatalf("tty present: %v %+v", err, withTTY)
	}
}

func TestPermissionDenialDoesNotFailTheTurn(t *testing.T) {
	dir := t.TempDir()
	bin := writeScript(t, dir, "deny.sh", `#!/bin/sh
printf '%s\n' '{"type":"system","subtype":"permission_denied","session_id":"s","tool":"Bash","tool_input":{"command":"rm -rf /"}}'
printf '%s\n' '{"type":"result","result":"continued","session_id":"s","permission_denials":[{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}]}'
`)
	var kinds []string
	var denials int
	res, err := (ExecRunner{HasTTY: func() bool { return false }}).Run(context.Background(), Spec{
		Backend: "claude", Bin: bin, Fresh: true, Prompt: "hi", Workspace: dir,
	}, func(ev Event) {
		kinds = append(kinds, ev.Kind)
		denials += len(ev.Denials)
	})
	if err != nil || res.Text != "continued" {
		t.Fatalf("err %v res %+v kinds %v", err, res, kinds)
	}
	if !strings.Contains(strings.Join(kinds, ","), "permission_decision") || denials != 1 {
		t.Fatalf("kinds %v denials %d", kinds, denials)
	}
}

func TestModelTextAboutPermissionIsNotAPrompt(t *testing.T) {
	dir := t.TempDir()
	bin := writeScript(t, dir, "talk.sh", `#!/bin/sh
printf '%s\n' '{"type":"stream_event","session_id":"s","event":{"delta":{"type":"text_delta","text":"permission prompt"}}}'
printf '%s\n' '{"type":"result","result":"permission prompt","session_id":"s"}'
`)
	res, err := (ExecRunner{HasTTY: func() bool { return false }}).Run(context.Background(), Spec{
		Backend: "claude", Bin: bin, Fresh: true, Prompt: "hi", Workspace: dir,
	}, nil)
	if err != nil || res.Text != "permission prompt" || res.SessionID != "s" {
		t.Fatalf("err %v res %+v", err, res)
	}
}

func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func pidRunning(pid int) bool {
	out, err := exec.Command("ps", "-o", "state=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return false
	}
	state := strings.TrimSpace(string(out))
	return state != "" && !strings.HasPrefix(state, "Z")
}
