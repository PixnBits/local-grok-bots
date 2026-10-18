package daemon

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestServerToolsAPI(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Ada", "description": "stay"}, "")
	if res.StatusCode != 201 || !strings.Contains(string(b), `"server_tools":null`) {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	if bot.ServerTools != nil {
		t.Fatalf("inherit %#v", bot.ServerTools)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"server_tools": []string{" Web_Search ", "x_search"}}, "")
	if res.StatusCode != 200 {
		t.Fatalf("patch %d %s", res.StatusCode, b)
	}
	decodeJSON(t, b, &bot)
	if bot.ServerTools == nil || strings.Join(*bot.ServerTools, ",") != "web_search,x_search" {
		t.Fatalf("stored %#v", bot.ServerTools)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"label": "kept"}, "")
	if res.StatusCode != 200 {
		t.Fatalf("label %d %s", res.StatusCode, b)
	}
	decodeJSON(t, b, &bot)
	if bot.Label != "kept" || bot.ServerTools == nil || strings.Join(*bot.ServerTools, ",") != "web_search,x_search" {
		t.Fatalf("label cleared %#v", bot)
	}
	res, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/state", nil, "")
	if res.StatusCode != 200 || !strings.Contains(string(b), `"server_tools":["web_search","x_search"]`) {
		t.Fatalf("state %d %s", res.StatusCode, b)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"server_tools": []string{}}, "")
	if res.StatusCode != 200 || !strings.Contains(string(b), `"server_tools":[]`) {
		t.Fatalf("empty %d %s", res.StatusCode, b)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"server_tools": nil}, "")
	if res.StatusCode != 200 || !strings.Contains(string(b), `"server_tools":null`) {
		t.Fatalf("null %d %s", res.StatusCode, b)
	}
	res, b = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"server_tools": []string{"bad name"}}, "")
	if res.StatusCode != 400 || strings.Contains(string(b), "bad name") || !strings.Contains(string(b), "invalid server_tools") {
		t.Fatalf("bad patch %d %s", res.StatusCode, b)
	}
	res, b = do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Nope", "description": "stay", "server_tools": []string{"function"}}, "")
	if res.StatusCode != 400 || strings.Contains(string(b), "function") {
		t.Fatalf("function %d %s", res.StatusCode, b)
	}
	res, b = do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Listed", "description": "stay", "server_tools": []string{"x_search"},
	}, "")
	if res.StatusCode != 201 || !strings.Contains(string(b), `"server_tools":["x_search"]`) {
		t.Fatalf("create list %d %s", res.StatusCode, b)
	}
}

func TestServerToolsForPrecedence(t *testing.T) {
	t.Setenv("MANAGED_POLICY", "")
	dir := t.TempDir()
	local := filepath.Join(dir, "policy.toml")
	body := "[backend]\nbackend = \"claude\"\n[cli]\nserver_tools = [\"web_search\", \"x_search\"]\n"
	if err := os.WriteFile(local, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	app := newCLIApp(t, dir, local)
	allow, src := app.serverToolsFor("missing-bot")
	if len(allow) != 0 || src != "default" {
		t.Fatalf("missing bot %#v %s", allow, src)
	}
	list := []string{"x_search"}
	bot, err := app.st.InsertBot(store.BotDraft{Name: "Ada", Description: "stay", ServerTools: &list}, "user")
	if err != nil {
		t.Fatal(err)
	}
	allow, src = app.serverToolsFor(bot.ID)
	if strings.Join(allow, ",") != "x_search" || src != "bot" {
		t.Fatalf("bot narrow %#v %s", allow, src)
	}
	wide := []string{"web_search", "x_search", "code_interpreter"}
	if _, err := app.st.UpdateBot(bot.ID, store.BotPatch{ServerToolsSet: true, ServerTools: &wide}); err != nil {
		t.Fatal(err)
	}
	allow, src = app.serverToolsFor(bot.ID)
	if strings.Join(allow, ",") != "web_search,x_search" || src != "local" {
		t.Fatalf("bot widen %#v %s", allow, src)
	}

	managed := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(managed, []byte(`{"cli":{"server_tools":[]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MANAGED_POLICY", managed)
	allow, src = app.serverToolsFor(bot.ID)
	if len(allow) != 0 || src != "managed" {
		t.Fatalf("managed deny %#v %s", allow, src)
	}

	gone := newCLIApp(t, t.TempDir(), filepath.Join(dir, "missing.toml"))
	allow, src = gone.serverToolsFor(bot.ID)
	if len(allow) != 0 || src != "default" {
		t.Fatalf("unreadable %#v %s", allow, src)
	}
}

func TestGrokProxyStripsWithPolicy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("MANAGED_POLICY", "")
	real := filepath.Join(home, ".grok", "auth.json")
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	const marker = "unit-real-marker-value"
	login := `{"https://auth.x.ai::x":{"key":"` + marker + `","expires_at":"2099-01-01T00:00:00Z"}}`
	if err := os.WriteFile(real, []byte(login), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.toml")
	body := "[backend]\nbackend = \"claude\"\n[timers]\nenabled = true\n[cli]\nserver_tools = [\"web_search\", \"x_search\"]\n"
	if err := os.WriteFile(policyPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	app := newCLIApp(t, dir, policyPath)
	app.noGrokProxy = false
	auditPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	var mu sync.Mutex
	var ups []string
	app.grokTrip = captureTrip(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		ups = append(ups, string(b))
		mu.Unlock()
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	tools := []string{"web_search"}
	bot, err := app.st.InsertBot(store.BotDraft{
		Name: "Ada", Description: "stay", Grants: []string{"net"}, ServerTools: &tools,
	}, "user")
	if err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	iso, err := app.cliIsolation(bot, "grok", ws, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if iso.ReleaseGate != nil {
		t.Cleanup(iso.ReleaseGate)
	}
	noNet := bot
	noNet.Grants = nil
	iso2, err := app.cliIsolation(noNet, "grok", ws, "run-2")
	if err != nil {
		t.Fatal(err)
	}
	if iso2.ReleaseGate != nil {
		t.Cleanup(iso2.ReleaseGate)
	}
	origin1 := strings.TrimSuffix(envValue(iso.Env, "GROK_CLI_CHAT_PROXY_BASE_URL"), "/v1")
	origin2 := strings.TrimSuffix(envValue(iso2.Env, "GROK_CLI_CHAT_PROXY_BASE_URL"), "/v1")
	key1 := envValue(iso.Env, "XAI_API_KEY")
	key2 := envValue(iso2.Env, "XAI_API_KEY")
	client := &http.Client{Timeout: 2 * time.Second}
	payload := `{"input":"planted-phrase","tools":[{"type":"function","name":"read_file","description":"do-not-audit-this-payload"},{"type":"web_search"},{"type":"x_search"}]}`
	code := proxyPost(t, client, origin1+"/v1/responses", "Bearer "+key1, payload)
	if code != http.StatusNoContent {
		t.Fatalf("net status %d", code)
	}
	code = proxyPost(t, client, origin2+"/v1/responses", "Bearer "+key2, payload)
	if code != http.StatusNoContent {
		t.Fatalf("no-net status %d", code)
	}
	code = proxyPost(t, client, origin1+"/v1/responses", "Bearer "+key1, `{"input":"planted-phrase","tools":`)
	if code != http.StatusForbidden {
		t.Fatalf("unparsed %d", code)
	}
	mu.Lock()
	got := append([]string(nil), ups...)
	mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("upstream %d", len(got))
	}
	if !strings.Contains(got[0], "web_search") || strings.Contains(got[0], "x_search") || !strings.Contains(got[0], "do-not-audit-this-payload") {
		t.Fatalf("net body %s", got[0])
	}
	if strings.Contains(got[1], "web_search") || strings.Contains(got[1], "x_search") || !strings.Contains(got[1], "read_file") {
		t.Fatalf("no-net body %s", got[1])
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "planted-phrase") || strings.Contains(text, "do-not-audit-this-payload") || strings.Contains(text, marker) {
		t.Fatalf("audit carried a body or credential: %s", text)
	}
	if strings.Count(text, "cli_proxy_stripped") != 2 || strings.Count(text, `"source":"bot"`) != 1 || strings.Count(text, `"source":"no_net"`) != 1 {
		t.Fatalf("audit %s", text)
	}
	if !strings.Contains(text, `"removed":["x_search"]`) || !strings.Contains(text, `"removed":["web_search","x_search"]`) {
		t.Fatalf("removed %s", text)
	}
	if !strings.Contains(text, `"bot_id":"`+bot.ID+`"`) || !strings.Contains(text, `"run_id":"run-1"`) || !strings.Contains(text, `"run_id":"run-2"`) || !strings.Contains(text, `"path":"/v1/responses"`) {
		t.Fatalf("route %s", text)
	}
	if !strings.Contains(text, "cli_proxy_refused") || !strings.Contains(text, `"reason":"unparsed"`) {
		t.Fatalf("refuse %s", text)
	}
}

func proxyPost(t *testing.T, client *http.Client, url, auth, body string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(got), "planted-phrase") || strings.Contains(string(got), "do-not-audit-this-payload") {
		t.Fatalf("response %s", got)
	}
	return resp.StatusCode
}
