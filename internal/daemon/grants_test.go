package daemon

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
	"github.com/PixnBits/local-grok-bots/web"
)

func TestGrantsAPISetAndClear(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Ada", "description": "stay"}, "")
	if res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	if len(bot.Grants) != 0 || len(bot.NetAllow) != 0 || len(bot.SSHAllow) != 0 {
		t.Fatalf("new bot has grants %#v", bot)
	}

	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{
		"grants": []string{"ssh", "net", "net"}, "net_allow": []string{"Allowed.Test."}, "ssh_allow": []string{"host.example"},
	}, "")
	if res.StatusCode != 200 {
		t.Fatalf("patch %d %s", res.StatusCode, b)
	}
	decodeJSON(t, b, &bot)
	if strings.Join(bot.Grants, ",") != "net,ssh" || strings.Join(bot.NetAllow, ",") != "allowed.test" || strings.Join(bot.SSHAllow, ",") != "host.example" {
		t.Fatalf("grants not stored %#v", bot)
	}

	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"label": "kept"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("label %d %s", res.StatusCode, b)
	}
	decodeJSON(t, b, &bot)
	if bot.Label != "kept" || strings.Join(bot.Grants, ",") != "net,ssh" {
		t.Fatalf("label patch cleared grants %#v", bot)
	}

	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"grants": []string{}, "net_allow": nil, "ssh_allow": []string{}}, "")
	if res.StatusCode != 200 {
		t.Fatalf("clear %d %s", res.StatusCode, b)
	}
	decodeJSON(t, b, &bot)
	if len(bot.Grants) != 0 || len(bot.NetAllow) != 0 || len(bot.SSHAllow) != 0 {
		t.Fatalf("grants not cleared %#v", bot)
	}

	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"grants": []string{"browser"}}, "")
	if res.StatusCode != 400 {
		t.Fatalf("browser grant %d %s", res.StatusCode, b)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"net_allow": []string{"*"}}, "")
	if res.StatusCode != 400 {
		t.Fatalf("wildcard %d %s", res.StatusCode, b)
	}
	res, b = do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Granted", "description": "stay", "grants": []string{"git"}, "net_allow": []string{"example.com"},
	}, "")
	if res.StatusCode != 201 {
		t.Fatalf("create granted %d %s", res.StatusCode, b)
	}
	decodeJSON(t, b, &bot)
	if strings.Join(bot.Grants, ",") != "git" || strings.Join(bot.NetAllow, ",") != "example.com" {
		t.Fatalf("create grants %#v", bot)
	}
	res, b = do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Bad", "description": "x", "grants": []string{"browser"}}, "")
	if res.StatusCode != 400 {
		t.Fatalf("create browser %d %s", res.StatusCode, b)
	}
}

func TestMetaToolsDoNotGrant(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Caller", "description": "tools"}, "")
	var caller store.Bot
	decodeJSON(t, b, &caller)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Target", "description": "stay", "grants": []string{"git"}}, "")
	if res.StatusCode != 201 {
		t.Fatalf("target %d %s", res.StatusCode, b)
	}
	var target store.Bot
	decodeJSON(t, b, &target)

	ctx := context.Background()
	if _, err := app.dispatchTool(ctx, caller, "update_bot", map[string]any{
		"id": target.ID, "label": "renamed", "grants": []any{"net"}, "net_allow": []any{"evil.test"},
		"server_tools": []any{"web_search"},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := app.st.GetBot(target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "renamed" || strings.Join(got.Grants, ",") != "git" || len(got.NetAllow) != 0 {
		t.Fatalf("update_bot changed grants %#v", got)
	}
	if got.ServerTools == nil || strings.Join(*got.ServerTools, ",") != "web_search" {
		t.Fatalf("update_bot server_tools %#v", got.ServerTools)
	}
	out, err := app.dispatchTool(ctx, caller, "create_bot", map[string]any{
		"name": "Spawn", "description": "stay", "grants": []any{"ssh"}, "ssh_allow": []any{"evil.test"},
		"server_tools": []any{"web_search"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Spawn") {
		t.Fatalf("create_bot result %s", out)
	}
	spawn, err := app.st.FindBot("Spawn")
	if err != nil {
		t.Fatal(err)
	}
	if len(spawn.Grants) != 0 || len(spawn.SSHAllow) != 0 {
		t.Fatalf("create_bot copied grants %#v", spawn)
	}
	if spawn.ServerTools == nil || strings.Join(*spawn.ServerTools, ",") != "web_search" {
		t.Fatalf("create_bot server_tools %#v", spawn.ServerTools)
	}
}

func TestMetaToolServerTools(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	caller, err := app.st.CreateBot("Caller", "tools", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := app.dispatchTool(ctx, caller, "create_bot", map[string]any{
		"name": "Inherit", "description": "stay",
	}); err != nil {
		t.Fatal(err)
	}
	inherit, err := app.st.FindBot("Inherit")
	if err != nil || inherit.ServerTools != nil {
		t.Fatalf("omit %#v %v", inherit.ServerTools, err)
	}
	if _, err := app.dispatchTool(ctx, caller, "create_bot", map[string]any{
		"name": "NullList", "description": "stay", "server_tools": nil,
	}); err != nil {
		t.Fatal(err)
	}
	nullList, err := app.st.FindBot("NullList")
	if err != nil || nullList.ServerTools != nil {
		t.Fatalf("null %#v %v", nullList.ServerTools, err)
	}
	if _, err := app.dispatchTool(ctx, caller, "create_bot", map[string]any{
		"name": "None", "description": "stay", "server_tools": []any{},
	}); err != nil {
		t.Fatal(err)
	}
	none, err := app.st.FindBot("None")
	if err != nil || none.ServerTools == nil || len(*none.ServerTools) != 0 {
		t.Fatalf("empty %#v %v", none.ServerTools, err)
	}
	if _, err := app.dispatchTool(ctx, caller, "create_bot", map[string]any{
		"name": "Listed", "description": "stay", "server_tools": []any{" Web_Search ", "x_search"},
	}); err != nil {
		t.Fatal(err)
	}
	listed, err := app.st.FindBot("Listed")
	if err != nil || listed.ServerTools == nil || strings.Join(*listed.ServerTools, ",") != "web_search,x_search" {
		t.Fatalf("list %#v %v", listed.ServerTools, err)
	}
	if _, err := app.dispatchTool(ctx, caller, "update_bot", map[string]any{
		"id": listed.ID, "label": "kept",
	}); err != nil {
		t.Fatal(err)
	}
	kept, err := app.st.GetBot(listed.ID)
	if err != nil || kept.Label != "kept" || kept.ServerTools == nil || strings.Join(*kept.ServerTools, ",") != "web_search,x_search" {
		t.Fatalf("omit update %#v %v", kept.ServerTools, err)
	}
	if _, err := app.dispatchTool(ctx, caller, "update_bot", map[string]any{
		"id": listed.ID, "server_tools": nil,
	}); err != nil {
		t.Fatal(err)
	}
	cleared, err := app.st.GetBot(listed.ID)
	if err != nil || cleared.ServerTools != nil {
		t.Fatalf("null update %#v %v", cleared.ServerTools, err)
	}
	if _, err := app.dispatchTool(ctx, caller, "update_bot", map[string]any{
		"id": listed.ID, "server_tools": []any{},
	}); err != nil {
		t.Fatal(err)
	}
	empty, err := app.st.GetBot(listed.ID)
	if err != nil || empty.ServerTools == nil || len(*empty.ServerTools) != 0 {
		t.Fatalf("empty update %#v %v", empty.ServerTools, err)
	}
	if _, err := app.dispatchTool(ctx, caller, "update_bot", map[string]any{
		"id": listed.ID, "server_tools": []any{"bad name"},
	}); err == nil || !strings.Contains(err.Error(), "invalid server_tools") || strings.Contains(err.Error(), "bad name") {
		t.Fatalf("bad %v", err)
	}
	stuck, err := app.st.GetBot(listed.ID)
	if err != nil || stuck.ServerTools == nil || len(*stuck.ServerTools) != 0 {
		t.Fatalf("bad write stuck %#v %v", stuck.ServerTools, err)
	}
}

func TestDuplicateOmitsGrants(t *testing.T) {
	src := string(web.IndexHTML)
	i := strings.Index(src, "async function duplicateBot")
	j := strings.Index(src, "function paintMarkPicker")
	if i < 0 || j < i {
		t.Fatal("duplicateBot missing")
	}
	body := src[i:j]
	if strings.Contains(body, "grants") || strings.Contains(body, "net_allow") || strings.Contains(body, "ssh_allow") {
		t.Fatalf("duplicate copies grants:\n%s", body)
	}
	if !strings.Contains(body, "server_tools") || !strings.Contains(body, "full.server_tools") {
		t.Fatalf("duplicate drops server_tools:\n%s", body)
	}
}

func TestProfileSaveKeepsServerTools(t *testing.T) {
	src := string(web.IndexHTML)
	if !strings.Contains(src, "Inherit from policy") || !strings.Contains(src, "Explicit list") || !strings.Contains(src, "allows none") {
		t.Fatal("profile does not distinguish inherit from an explicit list")
	}
	i := strings.Index(src, `$("#profile-form").addEventListener("submit"`)
	j := strings.Index(src, `$("#routine-add")`)
	if i < 0 || j < i {
		t.Fatal("profile save missing")
	}
	save := src[i:j]
	if !strings.Contains(save, "server_tools: serverToolsPayload()") {
		t.Fatal("profile save drops server_tools")
	}
	if !strings.Contains(src, "function serverToolsPayload()") || !strings.Contains(src, `value !== "explicit"`) {
		t.Fatal("inherit and explicit are not separate")
	}
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada", "description": "stay", "server_tools": []string{"x_search"},
	}, "")
	if res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{
		"name": "Ada", "label": "kept", "description": "stay", "model": nil,
		"grants": []string{}, "net_allow": []string{}, "ssh_allow": []string{},
		"server_tools": []string{"x_search"},
	}, "")
	if res.StatusCode != 200 {
		t.Fatalf("save %d %s", res.StatusCode, b)
	}
	decodeJSON(t, b, &bot)
	if bot.Label != "kept" || bot.ServerTools == nil || strings.Join(*bot.ServerTools, ",") != "x_search" {
		t.Fatalf("profile save %#v", bot.ServerTools)
	}
	res, b = do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada copy", "label": bot.Label, "description": bot.Description,
		"mark": bot.Mark, "model": bot.Model, "server_tools": bot.ServerTools,
	}, "")
	if res.StatusCode != 201 {
		t.Fatalf("duplicate %d %s", res.StatusCode, b)
	}
	var copy store.Bot
	decodeJSON(t, b, &copy)
	if copy.ID == bot.ID || len(copy.Grants) != 0 || copy.ServerTools == nil || strings.Join(*copy.ServerTools, ",") != "x_search" {
		t.Fatalf("copy %#v", copy)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"server_tools": []string{}}, "")
	if res.StatusCode != 200 {
		t.Fatalf("none %d %s", res.StatusCode, b)
	}
	decodeJSON(t, b, &bot)
	res, b = do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Ada none", "label": bot.Label, "description": bot.Description,
		"server_tools": bot.ServerTools,
	}, "")
	if res.StatusCode != 201 {
		t.Fatalf("duplicate none %d %s", res.StatusCode, b)
	}
	decodeJSON(t, b, &copy)
	if copy.ServerTools == nil || len(*copy.ServerTools) != 0 {
		t.Fatalf("none copy %#v", copy.ServerTools)
	}
}

func shellDial() (func(context.Context, string, string) (net.Conn, error), func() []string) {
	var mu sync.Mutex
	var got []string
	fn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		got = append(got, addr)
		mu.Unlock()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		go func() {
			c, err := ln.Accept()
			_ = ln.Close()
			if err != nil {
				return
			}
			defer c.Close()
			_, _ = io.WriteString(c, "SSH-2.0-fake\r\n")
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 1024)
			_, _ = c.Read(buf)
		}()
		return net.Dial("tcp", ln.Addr().String())
	}
	return fn, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string{}, got...)
	}
}

func logDetails(t *testing.T, base, kind string) []map[string]any {
	t.Helper()
	events := logKind(t, base, kind)
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		var m map[string]any
		decodeJSON(t, e.Detail, &m)
		out = append(out, m)
	}
	return out
}

func hasDetail(details []map[string]any, grant, host string) bool {
	for _, d := range details {
		g, _ := d["grant"].(string)
		h, _ := d["host"].(string)
		if (grant == "" || g == grant) && (host == "" || h == host) {
			return true
		}
	}
	return false
}

const daemonNetScript = `python3 - <<'PY'
import socket
def hit(host, port):
    try:
        s = socket.create_connection((host, port), 3)
        s.sendall(b"hi")
        s.close()
        print("open", host, port)
    except Exception as e:
        print("fail", host, port, type(e).__name__)
hit("allowed.test", 80)
hit("denied.test", 80)
PY`

func TestShellNetGrantLogged(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	dial, dialed := shellDial()
	app.shellDial = dial
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Net", "description": "stay"}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	ctx := context.Background()
	out, err := app.dispatchTool(ctx, bot, "run_shell", map[string]any{"command": daemonNetScript})
	if !strings.Contains(out, "fail allowed.test") && err == nil {
		t.Fatalf("ungranted network ran: %v\n%s", err, out)
	}
	denied := logDetails(t, srv.URL, "grant_denied")
	if !hasDetail(denied, "net", "allowed.test") {
		t.Fatalf("denial not logged: %#v\n%s", denied, out)
	}
	if len(dialed()) != 0 {
		t.Fatalf("dialed without net: %#v", dialed())
	}

	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{
		"grants": []string{"net"}, "net_allow": []string{"allowed.test"},
	}, "")
	if res.StatusCode != 200 {
		t.Fatalf("patch %d %s", res.StatusCode, b)
	}
	out, err = app.dispatchTool(ctx, bot, "run_shell", map[string]any{"command": daemonNetScript})
	if !strings.Contains(out, "open allowed.test 80") || strings.Contains(out, "open denied.test") {
		t.Fatalf("allowlist: %v\n%s", err, out)
	}
	used := logDetails(t, srv.URL, "grant_use")
	asked := logDetails(t, srv.URL, "net_request")
	if !hasDetail(used, "net", "allowed.test") || !hasDetail(asked, "net", "denied.test") {
		t.Fatalf("use %#v request %#v", used, asked)
	}
	if len(dialed()) != 1 || !strings.HasPrefix(dialed()[0], "allowed.test:") {
		t.Fatalf("dialed %#v", dialed())
	}
}

func TestShellGitAndSSHGrants(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	dial, dialed := shellDial()
	app.shellDial = dial
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Worker", "description": "stay"}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	ctx := context.Background()

	out, err := app.dispatchTool(ctx, bot, "run_shell", map[string]any{"command": "git push"})
	if err == nil || strings.Contains(out, "not sent") || !strings.Contains(out, "denied") {
		t.Fatalf("push without git: %v\n%s", err, out)
	}
	if !hasDetail(logDetails(t, srv.URL, "grant_denied"), "git", "") {
		t.Fatal("git denial not logged")
	}
	_, err = app.dispatchTool(ctx, bot, "write_file", map[string]any{"path": ".bashrc", "content": "echo pwn\n"})
	if err == nil {
		t.Fatal("write_file allowed .bashrc")
	}
	if len(logDetails(t, srv.URL, "sandbox_block")) == 0 {
		t.Fatal("write_file block was not logged")
	}

	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"grants": []string{"git"}}, "")
	if res.StatusCode != 200 {
		t.Fatalf("git grant %d %s", res.StatusCode, b)
	}
	out, err = app.dispatchTool(ctx, bot, "run_shell", map[string]any{"command": `set -e
git init
echo hello > readme.txt
git add readme.txt
git commit -m note
git push
echo PUSH_DONE
`})
	if err != nil || !strings.Contains(out, "not sent") || !strings.Contains(out, "PUSH_DONE") {
		t.Fatalf("git review: %v\n%s", err, out)
	}
	thread := botThread(t, srv.URL, bot.ID)
	if !hasMessage(thread, "system", "Notice: Git push held for review") {
		t.Fatalf("thread %#v", thread)
	}

	out, err = app.dispatchTool(ctx, bot, "run_shell", map[string]any{"command": "ssh -o ConnectTimeout=2 allowed.test true; echo ssh:$?"})
	if _, ok := findHost(logDetails(t, srv.URL, "grant_denied"), "ssh", "allowed.test"); !ok {
		t.Fatalf("ssh denial: %v\n%s", err, out)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{
		"grants": []string{"git", "ssh"}, "ssh_allow": []string{"allowed.test"},
	}, "")
	if res.StatusCode != 200 {
		t.Fatalf("ssh grant %d %s", res.StatusCode, b)
	}
	out, err = app.dispatchTool(ctx, bot, "run_shell", map[string]any{"command": `ssh -o ConnectTimeout=2 allowed.test true; echo allowed:$?
ssh -o ConnectTimeout=2 other.test true; echo other:$?`})
	if !strings.Contains(out, "other:") {
		t.Fatalf("ssh did not finish: %v\n%s", err, out)
	}
	used := logDetails(t, srv.URL, "grant_use")
	if _, ok := findHost(used, "ssh", "allowed.test"); !ok {
		t.Fatalf("ssh use %#v", used)
	}
	if _, ok := findHost(logDetails(t, srv.URL, "grant_denied"), "ssh", "other.test"); !ok {
		t.Fatal("ssh allowlist did not deny other.test")
	}
	if len(dialed()) != 1 || !strings.HasPrefix(dialed()[0], "allowed.test:") {
		t.Fatalf("dialed %#v", dialed())
	}
	thread = botThread(t, srv.URL, bot.ID)
	if !hasMessage(thread, "system", "Notice: SSH to allowed.test") {
		t.Fatalf("ssh notice missing %#v", thread)
	}
}

func findHost(details []map[string]any, grant, host string) (map[string]any, bool) {
	for _, d := range details {
		g, _ := d["grant"].(string)
		h, _ := d["host"].(string)
		if g == grant && h == host {
			return d, true
		}
	}
	return nil, false
}

func botThread(t *testing.T, base, id string) []store.Message {
	t.Helper()
	_, b := do(t, "GET", base+"/api/bots/"+id+"/thread", nil, "")
	var thread struct {
		Messages []store.Message `json:"messages"`
	}
	decodeJSON(t, b, &thread)
	return thread.Messages
}

func hasMessage(msgs []store.Message, role, content string) bool {
	for _, m := range msgs {
		if m.Role == role && m.Content == content {
			return true
		}
	}
	return false
}

func TestPushNoticeDoesNotStartTurn(t *testing.T) {
	var calls atomic.Int32
	app := newApp(t, "", fakeModel{fn: func(req model.ChatRequest) (model.ChatResponse, error) {
		if calls.Add(1) > 1 || req.Messages[len(req.Messages)-1].Role == "tool" {
			return model.ChatResponse{Content: "done"}, nil
		}
		return model.ChatResponse{ToolCalls: []model.ToolCall{{
			Name:      "run_shell",
			Arguments: map[string]any{"command": "git init && echo hello > readme.txt && git add readme.txt && git commit -m note && git push && echo PUSH_DONE"},
		}}}, nil
	}})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Pusher", "description": "stay"}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"grants": []string{"git"}}, "")
	if res.StatusCode != 200 {
		t.Fatalf("grant %d %s", res.StatusCode, b)
	}
	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "push"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	time.Sleep(250 * time.Millisecond)
	if calls.Load() != 2 {
		t.Fatalf("notice started another turn: calls=%d", calls.Load())
	}
	need, err := app.st.NeedsRun(bot.ID)
	if err != nil || need {
		t.Fatalf("NeedsRun after notice: %v %v", need, err)
	}
	if !hasMessage(botThread(t, srv.URL, bot.ID), "system", "Notice: Git push held for review") {
		t.Fatal("push notice missing from the thread")
	}
	res, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	decodeJSON(t, b, &bot)
	if bot.Hidden || bot.Status == "paused" {
		t.Fatalf("grant run changed hide or pause %#v", bot)
	}
}
