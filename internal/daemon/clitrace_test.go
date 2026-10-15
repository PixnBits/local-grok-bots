package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

const claudeToolFixture = `{"type":"system","subtype":"init","session_id":"s-claude"}
{"type":"stream_event","session_id":"s-claude","event":{"delta":{"type":"text_delta","text":"Let me check the tree."}}}
{"type":"assistant","session_id":"s-claude","message":{"content":[{"type":"tool_use","id":"tu1","name":"Bash","input":{"command":"git status","token":"sk-ant-api03-SECRETSECRETSECRET"}}]}}
{"type":"user","session_id":"s-claude","message":{"content":[{"type":"tool_result","tool_use_id":"tu1","content":"nothing to commit"}]}}
{"type":"stream_event","session_id":"s-claude","event":{"delta":{"type":"text_delta","text":"All clean."}}}
{"type":"result","result":"All clean.","session_id":"s-claude","permission_denials":[{"tool_name":"Bash","tool_input":{"command":"rm -rf build"}}]}
`

const grokToolFixture = `{"type":"text","sessionId":"s-grok","data":"Looking. "}
{"type":"tool_call","sessionId":"s-grok","toolName":"read_file","arguments":{"path":"a.txt"}}
{"type":"tool_result","sessionId":"s-grok","toolName":"read_file","result":"hello"}
{"type":"text","sessionId":"s-grok","data":"It says hello."}
{"type":"end","sessionId":"s-grok","stopReason":"end_turn"}
`

func runFixture(t *testing.T, backend, fixture string) (*App, store.Bot, []store.Message, []store.ToolRecord) {
	t.Helper()
	app, dir, bot, _ := isolationApp(t, backend, "")
	path := filepath.Join(dir, "fixture.jsonl")
	if err := os.WriteFile(path, []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LGB_FIXTURE", path)
	got := postAndWait(t, app, bot.ID)
	if got.LastRunStatus != "done" {
		t.Fatalf("run %s %s", got.LastRunStatus, got.LastRunError)
	}
	msgs, err := app.st.ListMessages(bot.ID, "user", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	var reply *store.Message
	for i := range msgs {
		if msgs[i].Role == "bot" {
			reply = &msgs[i]
		}
	}
	if reply == nil || reply.RunID == nil {
		t.Fatalf("no bot reply: %+v", msgs)
	}
	tools, err := app.st.RunTools([]string{*reply.RunID})
	if err != nil {
		t.Fatal(err)
	}
	return app, bot, msgs, tools[*reply.RunID]
}

func kinds(recs []store.ToolRecord) string {
	var k []string
	for _, r := range recs {
		k = append(k, r.Kind+":"+r.Name)
	}
	return strings.Join(k, ",")
}

func TestCLIClaudeTurnPersistsTextCallsAndPermissions(t *testing.T) {
	_, _, msgs, recs := runFixture(t, "claude", claudeToolFixture)
	if got := kinds(recs); got != "text:,call:Bash,permission:Bash" {
		t.Fatalf("records %s: %+v", got, recs)
	}
	if recs[0].Result != "Let me check the tree." {
		t.Fatalf("text record %q", recs[0].Result)
	}
	if !recs[1].OK || recs[1].Result != "nothing to commit" || strings.Contains(string(recs[1].Arguments), "SECRETSECRET") {
		t.Fatalf("call record %+v %s", recs[1], recs[1].Arguments)
	}
	if !strings.Contains(string(recs[1].Arguments), "git status") {
		t.Fatalf("call args %s", recs[1].Arguments)
	}
	var detail map[string]any
	if err := json.Unmarshal([]byte(recs[2].Result), &detail); err != nil {
		t.Fatal(err)
	}
	if recs[2].OK || detail["decision"] != "deny" || detail["source"] == "" || !strings.Contains(string(recs[2].Arguments), "rm -rf build") {
		t.Fatalf("permission record %+v %v", recs[2], detail)
	}
	last := msgs[len(msgs)-1]
	if last.Role != "bot" || last.Content != "All clean." {
		t.Fatalf("reply %q", last.Content)
	}
}

func TestCLIGrokTurnStoresOnlyTheTailAsReply(t *testing.T) {
	_, _, msgs, recs := runFixture(t, "grok", grokToolFixture)
	if got := kinds(recs); got != "text:,call:read_file" {
		t.Fatalf("records %s: %+v", got, recs)
	}
	if recs[0].Result != "Looking." || recs[1].Result != "hello" || !strings.Contains(string(recs[1].Arguments), "a.txt") {
		t.Fatalf("records %+v", recs)
	}
	last := msgs[len(msgs)-1]
	if last.Content != "It says hello." {
		t.Fatalf("reply %q", last.Content)
	}
}

func TestCLIToolWithoutResultIsStoredNotOK(t *testing.T) {
	fixture := `{"type":"assistant","session_id":"s","message":{"content":[{"type":"tool_use","id":"t","name":"Edit","input":{"file_path":"x"}}]}}
{"type":"result","result":"Stopped.","session_id":"s"}
`
	_, _, _, recs := runFixture(t, "claude", fixture)
	if len(recs) != 1 || recs[0].Name != "Edit" || recs[0].OK {
		t.Fatalf("records %+v", recs)
	}
}

func TestBrokerAllowIsStoredAsPermissionRecord(t *testing.T) {
	app, _, bot, _ := isolationApp(t, "claude", "")
	app.perm.Record(permission.Request{RunID: "run-1", BotID: bot.ID, Tool: "Bash", Args: map[string]any{"command": "git status"}, Transport: "stream_control"}, permission.Allow, "ui", "")
	tools, err := app.st.RunTools([]string{"run-1"})
	if err != nil {
		t.Fatal(err)
	}
	recs := tools["run-1"]
	if len(recs) != 1 || recs[0].Kind != "permission" || !recs[0].OK || !strings.Contains(recs[0].Result, `"source":"ui"`) || !strings.Contains(recs[0].Result, `"transport":"stream_control"`) {
		t.Fatalf("records %+v", recs)
	}
}

func TestUIAllowOnceIsStoredAsAllowed(t *testing.T) {
	app, _, bot, _ := isolationApp(t, "claude", "")
	for _, d := range []string{permission.AllowOnce, permission.AllowSession} {
		app.perm.Record(permission.Request{RunID: "run-" + d, BotID: bot.ID, Tool: "Bash"}, d, "ui", "")
		tools, _ := app.st.RunTools([]string{"run-" + d})
		if r := tools["run-"+d]; len(r) != 1 || !r[0].OK || !strings.Contains(r[0].Result, `"allowed":true`) {
			t.Fatalf("%s stored as %+v", d, r)
		}
	}
}
