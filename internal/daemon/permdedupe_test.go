package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// fakeMulti is the fake Claude for multi-ask turns. LGB_FAKE_ASKS is a JSON
// list of Bash commands. Each is asked in order over the configured
// transport; the CLI then reports the denied ones in result.permission_denials
// (and a permission_denied event per denial on mcp), as Claude does. The
// reply lists each behavior the CLI received, e.g. "allow,deny".
func fakeMulti(args []string) {
	var cmds []string
	_ = json.Unmarshal([]byte(os.Getenv("LGB_FAKE_ASKS")), &cmds)
	sid := flagValue(args, "--session-id")
	if sid == "" {
		sid = flagValue(args, "--resume")
	}
	var got []string
	var denials []map[string]any
	note := func(i int, behavior string) {
		got = append(got, behavior)
		if behavior != "allow" {
			denials = append(denials, map[string]any{
				"tool_name": "Bash", "tool_use_id": fmt.Sprintf("tu_%d", i),
				"tool_input": map[string]any{"command": cmds[i]},
			})
		}
	}
	if streamControlArgs(args) {
		waitFakeGate()
		log := stdinLogger()
		lines := make(chan string, 32)
		go func() {
			sc := bufio.NewScanner(os.Stdin)
			sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
			for sc.Scan() {
				log(sc.Text())
				lines <- sc.Text()
			}
			close(lines)
		}()
		first := mustStdin(lines)
		fakeOut(fmt.Sprintf(`{"type":"control_response","response":{"subtype":"success","request_id":%q,"response":{}}}`, controlRequestID(first)))
		_, _ = readStdin(lines) // the user message
		for i, c := range cmds {
			input, _ := json.Marshal(map[string]any{"command": c})
			fakeOut(fmt.Sprintf(`{"type":"control_request","request_id":"req_%d","request":{"subtype":"can_use_tool","tool_name":"Bash","input":%s,"tool_use_id":"tu_%d"}}`, i, input, i))
			resp := mustStdin(lines)
			if strings.Contains(resp, `"behavior":"allow"`) {
				note(i, "allow")
			} else {
				note(i, "deny")
			}
		}
		emitMultiResult(sid, got, denials, false)
		waitStdinClosed(lines)
		os.Exit(0)
	}
	waitFakeGate()
	url := mcpURL(args)
	if err := rpc(url, 1, "initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "fake", "version": "0"}}, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for i, c := range cmds {
		var called struct {
			Result struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		err := rpc(url, 10+i, "tools/call", map[string]any{"name": "approve", "arguments": map[string]any{
			"tool_name": "Bash", "tool_use_id": fmt.Sprintf("tu_%d", i), "input": map[string]any{"command": c},
		}}, &called)
		behavior := "deny"
		if err == nil && len(called.Result.Content) > 0 && strings.Contains(called.Result.Content[0].Text, `"behavior":"allow"`) {
			behavior = "allow"
		}
		note(i, behavior)
	}
	emitMultiResult(sid, got, denials, true)
	os.Exit(0)
}

func emitMultiResult(sid string, got []string, denials []map[string]any, events bool) {
	if events {
		for range denials {
			fakeOut(fmt.Sprintf(`{"type":"system","subtype":"permission_denied","session_id":%q,"tool":"Bash"}`, sid))
		}
	}
	res, _ := json.Marshal(map[string]any{
		"type": "result", "result": strings.Join(got, ","), "session_id": sid, "permission_denials": denials,
	})
	fakeOut(string(res))
}

type multiCase struct {
	transport string
	cmds      []string
	answers   map[string]string // command -> decision posted by the UI
	double    bool              // post each answer twice
	deny      []string          // policy deny rules
}

func runMulti(t *testing.T, c multiCase) (string, []store.ToolRecord) {
	t.Helper()
	asks, _ := json.Marshal(c.cmds)
	t.Setenv("LGB_FAKE_ASKS", string(asks))
	pol := policy.Policy{UIPrompts: true, PromptTimeout: 20 * time.Second, ClaudeTransport: c.transport, ToolDeny: c.deny}
	f := newStreamTurn(t, "multi", pol, true, true)
	f.openGate()
	answered := 0
	want := 0
	for _, cmd := range c.cmds {
		if _, ok := c.answers[cmd]; ok {
			want++
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for answered < want && time.Now().Before(deadline) {
		select {
		case ev := <-f.events:
			if !strings.HasPrefix(ev, "permission_request\n") {
				continue
			}
			var p struct {
				ID        string         `json:"id"`
				Arguments map[string]any `json:"arguments"`
			}
			_ = json.Unmarshal([]byte(strings.TrimPrefix(ev, "permission_request\n")), &p)
			cmd, _ := p.Arguments["command"].(string)
			decision := c.answers[cmd]
			url := f.url + "/api/bots/" + f.bot.ID + "/runs/" + f.runID + "/permissions/" + p.ID
			res, b := do(t, "POST", url, map[string]any{"decision": decision}, "")
			if res.StatusCode != 200 {
				t.Fatalf("answer %d %s", res.StatusCode, b)
			}
			if c.double {
				res, b = do(t, "POST", url, map[string]any{"decision": decision}, "")
				if res.StatusCode != http.StatusConflict {
					t.Fatalf("second answer %d %s", res.StatusCode, b)
				}
			}
			answered++
		case <-time.After(20 * time.Millisecond):
		}
	}
	got := f.waitDone()
	if got.LastRunStatus != "done" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	var reply string
	for _, m := range thread(t, f.url, f.bot.ID) {
		if m.Role == "bot" {
			reply = m.Content
		}
	}
	tools, err := f.app.st.RunTools([]string{f.runID})
	if err != nil {
		t.Fatal(err)
	}
	var perms []store.ToolRecord
	for _, r := range tools[f.runID] {
		if r.Kind == "permission" {
			perms = append(perms, r)
		}
	}
	return reply, perms
}

func summarize(perms []store.ToolRecord) (int, int) {
	denied := 0
	for _, r := range perms {
		if !r.OK {
			denied++
		}
	}
	return len(perms), denied
}

func TestPermissionRecordsDedupe(t *testing.T) {
	for _, tr := range []string{policy.TransportMCP, policy.TransportStreamControl} {
		t.Run(tr+"/two_allows", func(t *testing.T) {
			reply, perms := runMulti(t, multiCase{transport: tr, cmds: []string{"git status", "git log"},
				answers: map[string]string{"git status": "allow_once", "git log": "allow_once"}})
			if n, d := summarize(perms); reply != "allow,allow" || n != 2 || d != 0 {
				t.Fatalf("reply %q records %d denied %d: %+v", reply, n, d, perms)
			}
		})
		t.Run(tr+"/allow_and_deny", func(t *testing.T) {
			reply, perms := runMulti(t, multiCase{transport: tr, cmds: []string{"git status", "git push"},
				answers: map[string]string{"git status": "allow_once", "git push": "deny"}})
			if n, d := summarize(perms); reply != "allow,deny" || n != 2 || d != 1 {
				t.Fatalf("reply %q records %d denied %d: %+v", reply, n, d, perms)
			}
		})
		t.Run(tr+"/policy_deny_and_echo", func(t *testing.T) {
			reply, perms := runMulti(t, multiCase{transport: tr, cmds: []string{"rm -rf build"}, deny: []string{"Bash(rm *)"}})
			if n, d := summarize(perms); reply != "deny" || n != 1 || d != 1 || !strings.Contains(perms[0].Result, `"source":"policy"`) {
				t.Fatalf("reply %q records %d denied %d: %+v", reply, n, d, perms)
			}
		})
		t.Run(tr+"/double_click", func(t *testing.T) {
			reply, perms := runMulti(t, multiCase{transport: tr, cmds: []string{"git status"},
				answers: map[string]string{"git status": "allow_once"}, double: true})
			if n, d := summarize(perms); reply != "allow" || n != 1 || d != 0 {
				t.Fatalf("reply %q records %d denied %d: %+v", reply, n, d, perms)
			}
		})
	}
}

// An echo of a denial the broker never saw (Claude denied it itself) still
// gets one record.
func TestUnbrokeredDenialStillRecorded(t *testing.T) {
	app, _, bot, _ := isolationApp(t, "claude", "")
	app.noteCLIPermission(bot.ID, "run-x", "Edit", map[string]any{"file_path": "/etc/hosts"}, "tu_9", "cli", "mcp")
	app.noteCLIPermission(bot.ID, "run-x", "Edit", map[string]any{"file_path": "/etc/hosts"}, "tu_9", "cli", "mcp")
	tools, _ := app.st.RunTools([]string{"run-x"})
	if len(tools["run-x"]) != 1 {
		t.Fatalf("records %+v", tools["run-x"])
	}
}
