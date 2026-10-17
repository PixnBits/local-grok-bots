package clisession

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// quietACP fails the turn if a jailed probe asks for a tool. The probe
// speaks the handshake and does not request permission.
func quietACP() *ACPHooks {
	return &ACPHooks{
		Decide: func(context.Context, ACPAsk) (ACPDecision, error) {
			return ACPDecision{}, errUnexpectedACPAsk
		},
	}
}

var errUnexpectedACPAsk = errACPAsk("unexpected permission request")

type errACPAsk string

func (e errACPAsk) Error() string { return string(e) }

// acpShellTail answers initialize, session/new or session/load, and
// session/prompt. Jail probes run their check first, then this tail.
// A result line before the handshake is not a successful turn.
func acpShellTail() string {
	return `
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
reply "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"stopReason\":\"end_turn\"}}"
exit 0
`
}

func TestMapACPTool(t *testing.T) {
	bash, args, id, err := mapACPTool(map[string]any{
		"toolCallId": "c1",
		"kind":       "execute",
		"rawInput":   map[string]any{"variant": "Bash", "command": "cat -- a.txt"},
		"_meta": map[string]any{"x.ai/tool": map[string]any{
			"name":  "run_terminal_command",
			"input": map[string]any{"command": "cat -- a.txt"},
		}},
	})
	if err != nil || bash != "Bash" || id != "c1" || args["command"] != "cat -- a.txt" {
		t.Fatalf("bash %s %#v %s %v", bash, args, id, err)
	}
	read, args, _, err := mapACPTool(map[string]any{
		"toolCallId": "c2",
		"rawInput":   map[string]any{"variant": "ReadFile", "target_file": "a.txt"},
		"_meta": map[string]any{"x.ai/tool": map[string]any{
			"name":  "read_file",
			"input": map[string]any{"path": "a.txt"},
		}},
	})
	if err != nil || read != "Read" || args["file_path"] != "a.txt" || args["command"] != nil {
		t.Fatalf("read %s %#v %v", read, args, err)
	}
	grep, args, _, err := mapACPTool(map[string]any{
		"rawInput": map[string]any{"variant": "Grep", "pattern": "fn", "path": "main.go"},
		"_meta":    map[string]any{"x.ai/tool": map[string]any{"name": "grep"}},
	})
	if err != nil || grep != "Grep" || args["file_path"] != "main.go" || args["pattern"] != "fn" {
		t.Fatalf("grep %s %#v %v", grep, args, err)
	}
	glob, args, _, err := mapACPTool(map[string]any{
		"rawInput": map[string]any{"variant": "Glob", "glob": "*.go"},
		"_meta":    map[string]any{"x.ai/tool": map[string]any{"name": "glob"}},
	})
	if err != nil || glob != "Glob" || args["pattern"] != "*.go" {
		t.Fatalf("glob %s %#v %v", glob, args, err)
	}
	list, args, _, err := mapACPTool(map[string]any{
		"rawInput": map[string]any{"variant": "ListDir", "target_directory": "src"},
		"_meta":    map[string]any{"x.ai/tool": map[string]any{"name": "list_dir"}},
	})
	if err != nil || list != "Glob" || args["file_path"] != "src" || args["pattern"] != "*" {
		t.Fatalf("list %s %#v %v", list, args, err)
	}
	edit, args, _, err := mapACPTool(map[string]any{
		"rawInput": map[string]any{"variant": "Edit", "file_path": "a.txt"},
		"_meta":    map[string]any{"x.ai/tool": map[string]any{"name": "search_replace"}},
	})
	if err != nil || edit != "Edit" || args["file_path"] != "a.txt" {
		t.Fatalf("edit %s %#v %v", edit, args, err)
	}
	write, args, _, err := mapACPTool(map[string]any{
		"rawInput": map[string]any{"variant": "Write", "target_file": "b.txt"},
		"_meta":    map[string]any{"x.ai/tool": map[string]any{"name": "write"}},
	})
	if err != nil || write != "Write" || args["file_path"] != "b.txt" {
		t.Fatalf("write %s %#v %v", write, args, err)
	}
	web, args, _, err := mapACPTool(map[string]any{
		"_meta": map[string]any{"x.ai/tool": map[string]any{
			"name":  "web_fetch",
			"input": map[string]any{"url": "https://example.test/a"},
		}},
	})
	if err != nil || web != "WebFetch" || args["url"] != "https://example.test/a" {
		t.Fatalf("web %s %#v %v", web, args, err)
	}
	search, _, _, err := mapACPTool(map[string]any{
		"_meta": map[string]any{"x.ai/tool": map[string]any{"name": "web_search"}},
	})
	if err != nil || search != "WebSearch" {
		t.Fatalf("search %s %v", search, err)
	}
	unknown, _, _, err := mapACPTool(map[string]any{
		"title": "Custom",
		"_meta": map[string]any{"x.ai/tool": map[string]any{"name": "custom_widget"}},
	})
	if err != nil || unknown != "unknown" {
		t.Fatalf("unknown %s %v", unknown, err)
	}
	readCmd, args, _, err := mapACPTool(map[string]any{
		"rawInput": map[string]any{"variant": "ReadFile", "target_file": "a.txt", "command": "cat -- a.txt"},
	})
	if err != nil || readCmd != "Read" || args["file_path"] != "a.txt" || args["command"] != nil || args["cmd"] != nil {
		t.Fatalf("read dropped command %s %#v %v", readCmd, args, err)
	}
	other, _, _, err := mapACPTool(map[string]any{"kind": "other"})
	if err != nil || other != "unknown" {
		t.Fatalf("kind fallback %s %v", other, err)
	}
	if _, _, _, err := mapACPTool(map[string]any{}); err == nil {
		t.Fatal("empty tool was accepted")
	}
	if _, _, _, err := mapACPTool(nil); err == nil {
		t.Fatal("nil call was accepted")
	}
}

func TestSelectACPOptionNeverAllowAlways(t *testing.T) {
	opts := []acpOption{
		{OptionID: "always-allow", Kind: "allow_always"},
		{OptionID: "allow-once", Kind: "allow_once"},
		{OptionID: "reject-once", Kind: "reject_once"},
	}
	got, err := selectACPOption(opts, true)
	if err != nil || got != "allow-once" {
		t.Fatalf("allow %q %v", got, err)
	}
	got, err = selectACPOption(opts, false)
	if err != nil || got != "reject-once" {
		t.Fatalf("deny %q %v", got, err)
	}
	only := []acpOption{{OptionID: "always-allow", Kind: "allow_always"}}
	if _, err := selectACPOption(only, true); err == nil {
		t.Fatal("allow_always was selected")
	}
	if _, err := selectACPOption(only, false); err == nil {
		t.Fatal("missing reject-once was accepted")
	}
	byID := []acpOption{{OptionID: "allow-once", Kind: "other"}}
	got, err = selectACPOption(byID, true)
	if err != nil || got != "allow-once" {
		t.Fatalf("id match %q %v", got, err)
	}
	named := []acpOption{
		{OptionID: "allow-once", Name: "Always", Kind: "allow_once"},
		{OptionID: "reject-once", Name: "No", Kind: "reject_once"},
	}
	if _, err := selectACPOption(named, true); err == nil {
		t.Fatal("name containing always was selected")
	}
	got, err = selectACPOption(named, false)
	if err != nil || got != "reject-once" {
		t.Fatalf("reject name %q %v", got, err)
	}
}

func TestACPStartHasNoBypass(t *testing.T) {
	method, params, err := acpStart(Spec{Fresh: true, SessionID: "daemon-id", Workspace: "/ws"})
	if err != nil || method != "session/new" {
		t.Fatalf("new %s %v", method, err)
	}
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, bad := range []string{"yoloMode", "autoMode", "sessionId", "daemon-id"} {
		if strings.Contains(text, bad) {
			t.Fatalf("session/new has %s: %s", bad, text)
		}
	}
	if params["cwd"] != "/ws" {
		t.Fatalf("cwd %#v", params)
	}
	servers, ok := params["mcpServers"].([]any)
	if !ok || servers == nil || len(servers) != 0 {
		t.Fatalf("mcpServers %#v", params["mcpServers"])
	}
	method, params, err = acpStart(Spec{Fresh: false, SessionID: "kept", Workspace: "/ws"})
	if err != nil || method != "session/load" || params["sessionId"] != "kept" {
		t.Fatalf("load %s %#v %v", method, params, err)
	}
	if _, _, err := acpStart(Spec{Fresh: true}); err == nil {
		t.Fatal("empty workspace started a session")
	}
}

func TestRPCRequestIDPrecedesParams(t *testing.T) {
	b, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 7, Method: "initialize", Params: map[string]any{"protocolVersion": 1}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	idAt := strings.Index(text, `"id":`)
	methodAt := strings.Index(text, `"method":`)
	if idAt < 0 || methodAt < 0 || idAt > methodAt {
		t.Fatalf("order %s", text)
	}
	if !strings.Contains(text, `"id":7`) {
		t.Fatalf("id %s", text)
	}
}

func TestACPHostAnswersAllowOnce(t *testing.T) {
	if grokHostJail() {
		if _, err := exec.LookPath("bwrap"); err != nil {
			t.Skip(err)
		}
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "answer.txt")
	bin := writeScript(t, dir, "agent.sh", `#!/bin/sh
out="$ACP_ANSWER"
id_of() { printf '%s' "$1" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p'; }
reply() { awk -v line="$1" 'BEGIN{print line; fflush()}'; }
IFS= read -r line || exit 1
id=$(id_of "$line")
reply "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"protocolVersion\":1}}"
IFS= read -r line || exit 1
id=$(id_of "$line")
reply "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"sessionId\":\"s\",\"modes\":{\"currentModeId\":\"default\"}}}"
IFS= read -r line || exit 1
prompt=$(id_of "$line")
reply '{"jsonrpc":"2.0","id":9,"method":"session/request_permission","params":{"sessionId":"s","toolCall":{"toolCallId":"t","kind":"execute","rawInput":{"variant":"Bash","command":"cat -- a.txt"},"_meta":{"x.ai/tool":{"name":"run_terminal_command","input":{"command":"cat -- a.txt"}}}},"options":[{"optionId":"always-allow","kind":"allow_always"},{"optionId":"allow-once","kind":"allow_once"},{"optionId":"reject-once","kind":"reject_once"}]}}'
IFS= read -r line || exit 1
printf '%s\n' "$line" > "$out"
reply "{\"jsonrpc\":\"2.0\",\"id\":$prompt,\"result\":{\"stopReason\":\"end_turn\"}}"
exit 0
`)
	var asked ACPAsk
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := (ExecRunner{HasTTY: func() bool { return false }}).Run(ctx, Spec{
		Backend: "grok", Bin: bin, Fresh: true, Prompt: "hi", Workspace: dir,
		Isolate: &Isolation{
			Home:        dir,
			GrokSandbox: GrokProfile,
			Env:         []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "ACP_ANSWER=" + out},
		},
		ACP: &ACPHooks{Decide: func(_ context.Context, ask ACPAsk) (ACPDecision, error) {
			asked = ask
			return ACPDecision{Allow: true}, nil
		}},
	}, nil)
	if err != nil {
		t.Fatalf("run %v %+v", err, res)
	}
	if asked.Tool != "Bash" || asked.Args["command"] != "cat -- a.txt" {
		t.Fatalf("ask %+v", asked)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	if !strings.Contains(text, `"optionId":"allow-once"`) || strings.Contains(text, "always-allow") || strings.Contains(text, "allow_always") {
		t.Fatalf("answer %s", text)
	}
}

// A real agent keeps reading stdin after the prompt answer. The turn ends at
// that answer, and a session/load reply need not echo the session id.
func TestACPTurnEndsAtPromptAnswerAndLoadKeepsID(t *testing.T) {
	if grokHostJail() {
		if _, err := exec.LookPath("bwrap"); err != nil {
			t.Skip(err)
		}
	}
	dir := t.TempDir()
	bin := writeScript(t, dir, "agent.sh", `#!/bin/sh
id_of() { printf '%s' "$1" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p'; }
reply() { awk -v line="$1" 'BEGIN{print line; fflush()}'; }
IFS= read -r line || exit 1
id=$(id_of "$line")
reply "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"protocolVersion\":1}}"
IFS= read -r line || exit 1
id=$(id_of "$line")
reply "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"modes\":{\"currentModeId\":\"default\"}}}"
IFS= read -r line || exit 1
id=$(id_of "$line")
reply "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"stopReason\":\"end_turn\"}}"
while IFS= read -r line; do :; done
sleep 30
`)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	res, err := (ExecRunner{HasTTY: func() bool { return false }}).Run(ctx, Spec{
		Backend: "grok", Bin: bin, SessionID: "prior-session", Prompt: "hi", Workspace: dir,
		Isolate: &Isolation{
			Home:        dir,
			GrokSandbox: GrokProfile,
			Env:         []string{"PATH=/usr/bin:/bin", "HOME=" + dir},
		},
		ACP: quietACP(),
	}, nil)
	if err != nil {
		t.Fatalf("run %v %+v", err, res)
	}
	if res.SessionID != "prior-session" {
		t.Fatalf("session %q", res.SessionID)
	}
	if time.Since(start) > 15*time.Second {
		t.Fatalf("turn waited for the agent to exit: %s", time.Since(start))
	}
}
