package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/permbroker"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

const resumeAdminToken = "lgbr_admintesttokenvalue"

type resumeCard struct {
	ID     string `json:"id"`
	RunID  string `json:"run_id"`
	Level  string `json:"level"`
	Origin string `json:"origin"`
	Cwd    string `json:"cwd"`
	Tool   string `json:"tool"`
}

type resumeRig struct {
	t      *testing.T
	app    *App
	srv    *httptest.Server
	token  string
	bot    store.Bot
	calls  *atomic.Int32
	bodies *[]string
	mu     *sync.Mutex
	dir    string
}

// ollamaAskServer returns a tool call on the first request and plain text after that.
// The first request is the only one that may name the shell command.
func ollamaAskServer(t *testing.T, command, follow string, calls *atomic.Int32, bodies *[]string, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			http.NotFound(w, r)
			return
		}
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		mu.Lock()
		*bodies = append(*bodies, string(b))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-ndjson")
		if calls.Add(1) == 1 {
			_, _ = fmt.Fprintf(w, "{\"message\":{\"role\":\"assistant\",\"content\":\"\",\"tool_calls\":[{\"function\":{\"name\":\"run_shell\",\"arguments\":{\"command\":%q}}}]},\"done\":true}\n", command)
			return
		}
		_, _ = fmt.Fprintf(w, "{\"message\":{\"role\":\"assistant\",\"content\":%q},\"done\":true}\n", follow)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newResumeRig(t *testing.T, dir, command, follow string, risks []permbroker.RiskEntry) (*resumeRig, *httptest.Server) {
	t.Helper()
	var calls atomic.Int32
	var bodies []string
	var mu sync.Mutex
	modelSrv := ollamaAskServer(t, command, follow, &calls, &bodies, &mu)
	app := newApp(t, dir, model.NewOllama(modelSrv.URL))
	app.editPol(func(p *policy.Policy) {
		p.Broker = "hook"
		if len(risks) > 0 {
			p.BrokerRisks = append([]permbroker.RiskEntry(nil), risks...)
		}
	})
	app.cfg.AuthToken = resumeAdminToken
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "IO", "instructions": "shell"}, resumeAdminToken)
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	return &resumeRig{
		t: t, app: app, srv: srv, token: resumeAdminToken, bot: bot,
		calls: &calls, bodies: &bodies, mu: &mu, dir: app.cfg.DataDir,
	}, modelSrv
}

func (r *resumeRig) post(content string) {
	r.t.Helper()
	res, b := do(r.t, "POST", r.srv.URL+"/api/bots/"+r.bot.ID+"/thread/messages", map[string]string{"content": content}, r.token)
	if res.StatusCode != 200 {
		r.t.Fatalf("post %d %s", res.StatusCode, b)
	}
}

func (r *resumeRig) waitCard() resumeCard {
	r.t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		res, b := do(r.t, "GET", r.srv.URL+"/api/permbroker/pending", nil, r.token)
		if res.StatusCode != 200 {
			r.t.Fatalf("pending %d %s", res.StatusCode, b)
		}
		var doc struct {
			Pending []resumeCard `json:"pending"`
		}
		decodeJSON(r.t, b, &doc)
		if len(doc.Pending) > 0 {
			return doc.Pending[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.t.Fatal("run did not ask")
	return resumeCard{}
}

func (r *resumeRig) decide(id, decision, scope string) (*http.Response, []byte) {
	r.t.Helper()
	body := map[string]string{"decision": decision}
	if scope != "" {
		body["scope"] = scope
	}
	return do(r.t, "POST", r.srv.URL+"/api/permbroker/pending/"+id, body, r.token)
}

func (r *resumeRig) httpBot() store.Bot {
	r.t.Helper()
	res, b := do(r.t, "GET", r.srv.URL+"/api/bots/"+r.bot.ID, nil, r.token)
	if res.StatusCode != 200 {
		r.t.Fatalf("bot %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(r.t, b, &bot)
	return bot
}

func (r *resumeRig) modelCalls() int32 {
	return r.calls.Load()
}

func (r *resumeRig) joinedBodies() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(*r.bodies, "\n")
}

func (r *resumeRig) toolContents() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, raw := range *r.bodies {
		var doc struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if json.Unmarshal([]byte(raw), &doc) != nil {
			continue
		}
		for _, m := range doc.Messages {
			if m.Role == "tool" {
				out = append(out, m.Content)
			}
		}
	}
	return out
}

func shellOKCount(t *testing.T, app *App, botID string) int {
	t.Helper()
	return shellEventCount(t, app, botID, "tool_end", true)
}

func shellStartCount(t *testing.T, app *App, botID string) int {
	t.Helper()
	return shellEventCount(t, app, botID, "tool_start", false)
}

func shellEventCount(t *testing.T, app *App, botID, kind string, okOnly bool) int {
	t.Helper()
	ev, err := app.st.ListLog(botID, kind, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ev {
		var d struct {
			Name string `json:"name"`
			OK   bool   `json:"ok"`
		}
		if json.Unmarshal(e.Detail, &d) != nil || d.Name != "run_shell" {
			continue
		}
		if okOnly && !d.OK {
			continue
		}
		n++
	}
	return n
}

func shellOnceArmed(app *App, botID string) bool {
	if app == nil || botID == "" {
		return false
	}
	app.shellCwdMu.Lock()
	defer app.shellCwdMu.Unlock()
	_, ok := app.shellOnce[botID]
	return ok
}

// waitSavedShellStarts waits until run_shell starts reach before+want, then
// pauses so another saved call started with the first would also be counted.
func waitSavedShellStarts(t *testing.T, app *App, botID string, before, want int) int {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if shellStartCount(t, app, botID) >= before+want {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(400 * time.Millisecond)
	return shellStartCount(t, app, botID) - before
}

func shellEndDetail(t *testing.T, app *App, botID string) string {
	t.Helper()
	ev, err := app.st.ListLog(botID, "tool_end", "", 20)
	if err != nil {
		return err.Error()
	}
	var b strings.Builder
	for _, e := range ev {
		b.Write(e.Detail)
		b.WriteByte('\n')
	}
	return b.String()
}

func auditRows(t *testing.T, dir string) []permbroker.AuditRow {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "permbroker", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []permbroker.AuditRow
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var row permbroker.AuditRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("audit: %v", err)
		}
		rows = append(rows, row)
	}
	return rows
}

func auditCount(rows []permbroker.AuditRow, decision, scope string) int {
	n := 0
	for _, row := range rows {
		if row.Decision == decision && (scope == "" || row.Scope == scope) {
			n++
		}
	}
	return n
}

func waitRunStatus(t *testing.T, app *App, botID, want string) store.Bot {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var last store.Bot
	for time.Now().Before(deadline) {
		got, err := app.st.GetBot(botID)
		if err != nil {
			t.Fatal(err)
		}
		last = got
		if got.LastRunStatus == want {
			return got
		}
		if want == "done" && (got.LastRunStatus == "error" || got.LastRunStatus == "cancelled") {
			t.Fatalf("run %s %q\n%s", got.LastRunStatus, got.LastRunError, shellEndDetail(t, app, botID))
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("run stayed %s %q", last.LastRunStatus, last.LastRunError)
	return last
}

// TestGolden_AskSuspendsApproveResumesOnce fails if the ask is handed back
// to the model, if approve does not run the command, or if a second approve runs it again.
func TestGolden_AskSuspendsApproveResumesOnce(t *testing.T) {
	const cmd = "echo RAN_ONCE"
	r, _ := newResumeRig(t, "", cmd, "continued after approve", nil)
	r.post("go")
	card := r.waitCard()
	if card.RunID == "" || card.Origin != permbroker.OriginNative || card.Tool != "shell" {
		t.Fatalf("card %+v", card)
	}
	bot := r.httpBot()
	if bot.LastRunStatus != "waiting" || bot.WaitingTool != "run_shell" {
		t.Fatalf("waiting status %s tool %q", bot.LastRunStatus, bot.WaitingTool)
	}
	if r.modelCalls() != 1 {
		t.Fatalf("model calls %d", r.modelCalls())
	}
	time.Sleep(200 * time.Millisecond)
	if r.modelCalls() != 1 {
		t.Fatalf("model was called again while waiting: %d", r.modelCalls())
	}
	if strings.Contains(r.joinedBodies(), "pending approval") {
		t.Fatal("pending approval text was sent to the model")
	}
	ck, kind := r.app.readCheckpoint(card.ID)
	if kind != "" || ck.State != ckOpen || ck.RunID != card.RunID || ck.ToolName != "run_shell" {
		t.Fatalf("checkpoint %s %+v", kind, ck.State)
	}
	res, b := r.decide(card.ID, "approve", "once")
	if res.StatusCode != 200 {
		t.Fatalf("approve %d %s", res.StatusCode, b)
	}
	waitIdle(t, r.srv.URL, r.bot.ID, r.token)
	got := waitRunStatus(t, r.app, r.bot.ID, "done")
	if got.LastRunStatus != "done" {
		t.Fatalf("run %s", got.LastRunStatus)
	}
	run, err := r.app.st.GetRun(card.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "done" || run.ID != card.RunID {
		t.Fatalf("same run %s %s", run.ID, run.Status)
	}
	if shellOKCount(t, r.app, r.bot.ID) != 1 {
		t.Fatalf("shell ok %d\n%s", shellOKCount(t, r.app, r.bot.ID), shellEndDetail(t, r.app, r.bot.ID))
	}
	saw := false
	for _, c := range r.toolContents() {
		if c == "denied by user" || strings.Contains(c, "pending approval") {
			t.Fatalf("tool result %q", c)
		}
		if strings.Contains(c, "RAN_ONCE") {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("continuation missing RAN_ONCE: %q", r.toolContents())
	}
	if strings.Contains(r.joinedBodies(), "pending approval") {
		t.Fatal("pending approval text was sent to the model")
	}
	res, b = r.decide(card.ID, "approve", "once")
	if res.StatusCode == 200 {
		t.Fatalf("second approve ran %s", b)
	}
	time.Sleep(400 * time.Millisecond)
	if shellOKCount(t, r.app, r.bot.ID) != 1 {
		t.Fatalf("second approve re-ran the shell\n%s", shellEndDetail(t, r.app, r.bot.ID))
	}
	after, kind := r.app.readCheckpoint(card.ID)
	if kind != "" && kind != "missing" {
		t.Fatalf("checkpoint after approve %s", kind)
	}
	if kind == "" && after.State == ckOpen {
		t.Fatal("checkpoint still open after approve")
	}
	rows := auditRows(t, r.dir)
	if auditCount(rows, "suspend", "") != 1 || auditCount(rows, "resume", "approve") != 1 {
		t.Fatalf("audit suspend/resume missing")
	}
}

// TestGolden_DenyResumesWithDeniedByUser fails if the continuation does not
// see exactly "denied by user", or if the command runs.
func TestGolden_DenyResumesWithDeniedByUser(t *testing.T) {
	r, _ := newResumeRig(t, "", "echo DENY_MARKER", "continued after deny", nil)
	r.post("go")
	card := r.waitCard()
	res, b := r.decide(card.ID, "deny", "")
	if res.StatusCode != 200 {
		t.Fatalf("deny %d %s", res.StatusCode, b)
	}
	waitIdle(t, r.srv.URL, r.bot.ID, r.token)
	waitRunStatus(t, r.app, r.bot.ID, "done")
	if shellOKCount(t, r.app, r.bot.ID) != 0 {
		t.Fatalf("deny executed the command\n%s", shellEndDetail(t, r.app, r.bot.ID))
	}
	exact := 0
	for _, c := range r.toolContents() {
		if c == "denied by user" {
			exact++
		}
		if strings.Contains(c, "pending approval") || strings.Contains(c, "DENY_MARKER") {
			t.Fatalf("tool result %q", c)
		}
	}
	if exact != 1 {
		t.Fatalf("denied-by-user count %d in %q", exact, r.toolContents())
	}
	rows := auditRows(t, r.dir)
	if auditCount(rows, "resume", "deny") != 1 {
		t.Fatal("resume deny was not audited")
	}
}

// TestGolden_RestartThenApproveResumes fails if a new process over the same
// data directory drops the checkpoint or does not run the call after approve.
func TestGolden_RestartThenApproveResumes(t *testing.T) {
	const cmd = "echo RAN_AFTER_RESTART"
	dir := t.TempDir()
	r, modelSrv := newResumeRig(t, dir, cmd, "continued after restart", nil)
	r.post("go")
	card := r.waitCard()
	if r.modelCalls() != 1 {
		t.Fatalf("calls before shutdown %d", r.modelCalls())
	}
	runID := card.RunID
	r.app.Shutdown()
	// Do not publish policy again. SetRisks buries a restored pending item
	// even when the raises did not change. Boot loads checkpoints after setPol.
	app2 := newApp(t, dir, model.NewOllama(modelSrv.URL))
	app2.cfg.AuthToken = resumeAdminToken
	srv2 := serve(t, app2)
	res, b := do(t, "GET", srv2.URL+"/api/permbroker/pending", nil, resumeAdminToken)
	if res.StatusCode != 200 {
		t.Fatalf("pending %d %s", res.StatusCode, b)
	}
	var doc struct {
		Pending []resumeCard `json:"pending"`
	}
	decodeJSON(t, b, &doc)
	if len(doc.Pending) != 1 || doc.Pending[0].ID != card.ID {
		t.Fatalf("restored %+v", doc.Pending)
	}
	if r.modelCalls() != 1 {
		t.Fatalf("restart called the model: %d", r.modelCalls())
	}
	res, b = do(t, "POST", srv2.URL+"/api/permbroker/pending/"+card.ID, map[string]string{"decision": "approve", "scope": "once"}, resumeAdminToken)
	if res.StatusCode != 200 {
		t.Fatalf("approve %d %s", res.StatusCode, b)
	}
	got := waitRunStatus(t, app2, r.bot.ID, "done")
	if got.LastRunStatus != "done" {
		t.Fatalf("run %s %q", got.LastRunStatus, got.LastRunError)
	}
	run, err := app2.st.GetRun(runID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "done" {
		t.Fatalf("same run status %s", run.Status)
	}
	if shellOKCount(t, app2, r.bot.ID) != 1 {
		t.Fatalf("shell ok %d\n%s", shellOKCount(t, app2, r.bot.ID), shellEndDetail(t, app2, r.bot.ID))
	}
	if strings.Contains(r.joinedBodies(), "pending approval") {
		t.Fatal("pending approval text was sent to the model")
	}
}

// TestGolden_PolicyChangeBeforeApproveRefuses fails if resumeApproved treats
// a non-allow re-eval as permission to run. HTTP Decide on a ruleset bump
// returns stale and refuseOpen writes the same audit, so this test calls
// resumeApproved while the checkpoint is still open. The deny rule matches
// the suspended command. The ask's tool_start is the only shell entry;
// sandbox.Run is reached only from a later execTool.
func TestGolden_PolicyChangeBeforeApproveRefuses(t *testing.T) {
	const cmd = "git status"
	r, _ := newResumeRig(t, "", cmd, "should not continue", nil)
	r.post("go")
	card := r.waitCard()
	starts := shellStartCount(t, r.app, r.bot.ID)
	if starts != 1 {
		t.Fatalf("ask starts %d", starts)
	}
	if _, err := r.app.broker.SaveRule(permbroker.Rule{
		Effect: permbroker.EffectDeny, Argv: []string{"git", "status"},
		Tool: permbroker.ToolShell, Scope: permbroker.ScopeBot, BotID: r.bot.ID,
	}); err != nil {
		t.Fatal(err)
	}
	ck, kind := r.app.readCheckpoint(card.ID)
	if kind != "" || ck.State != ckOpen || shellCommandOf(ck.ToolArgs) != cmd {
		t.Fatalf("checkpoint %s %s %q", kind, ck.State, shellCommandOf(ck.ToolArgs))
	}
	if auditCount(auditRows(t, r.dir), "resume_refused", "policy") != 0 {
		t.Fatal("policy row before resume")
	}
	r.app.resumeApproved(ck)
	time.Sleep(400 * time.Millisecond)
	rows := auditRows(t, r.dir)
	if auditCount(rows, "resume_refused", "policy") != 1 || auditCount(rows, "resume", "approve") != 0 {
		t.Fatalf("audit resume_refused/policy=%d resume/approve=%d", auditCount(rows, "resume_refused", "policy"), auditCount(rows, "resume", "approve"))
	}
	wrote := false
	for _, row := range rows {
		if row.Decision == "resume_refused" && row.Scope == "policy" && row.PendingID == card.ID && row.Actor == "daemon" {
			wrote = true
		}
	}
	if !wrote {
		t.Fatal("resumeApproved did not write resume_refused/policy")
	}
	got, kind := r.app.readCheckpoint(card.ID)
	if kind != "" || got.State != ckRefused {
		t.Fatalf("checkpoint %s %s", kind, got.State)
	}
	if shellOnceArmed(r.app, r.bot.ID) {
		t.Fatal("shell-once slot armed after policy refusal")
	}
	if shellStartCount(t, r.app, r.bot.ID) != starts || shellOKCount(t, r.app, r.bot.ID) != 0 {
		t.Fatalf("sandbox invoked\n%s", shellEndDetail(t, r.app, r.bot.ID))
	}
	run, err := r.app.st.GetRun(card.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "error" {
		t.Fatalf("run %s", run.Status)
	}
}

// TestGolden_TamperedCheckpointRefuses fails if a flipped MAC is still executed.
// The audit uses the in-memory snapshot taken before Decide, not the file body.
func TestGolden_TamperedCheckpointRefuses(t *testing.T) {
	r, _ := newResumeRig(t, "", "echo TAMPER_MARKER", "should not continue", nil)
	r.post("go")
	card := r.waitCard()
	path := filepath.Join(r.dir, "permbroker", "checkpoints", card.ID+".json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte(`"mac":"`)
	i := strings.Index(string(body), string(key))
	if i < 0 || i+len(key) >= len(body) {
		t.Fatalf("mac missing in %s", body)
	}
	pos := i + len(key)
	if body[pos] == 'a' {
		body[pos] = 'b'
	} else {
		body[pos] = 'a'
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	res, b := r.decide(card.ID, "approve", "once")
	if res.StatusCode != 200 {
		t.Fatalf("decide %d %s", res.StatusCode, b)
	}
	if shellOKCount(t, r.app, r.bot.ID) != 0 {
		t.Fatalf("tampered checkpoint ran\n%s", shellEndDetail(t, r.app, r.bot.ID))
	}
	if auditCount(auditRows(t, r.dir), "resume_refused", "tamper") != 1 {
		t.Fatal("tamper was not audited")
	}
	if strings.Contains(r.joinedBodies(), "TAMPER_MARKER") && r.modelCalls() > 1 {
		t.Fatal("tampered payload was sent onward")
	}
}

// TestGolden_NewUserMessageCancelsCheckpoint fails if the checkpoint stays
// open, or if a later approve runs the shell. The model tool-calls only on
// the first request, so a second run cannot execute the command by itself.
func TestGolden_NewUserMessageCancelsCheckpoint(t *testing.T) {
	r, _ := newResumeRig(t, "", "echo CANCEL_MARKER", "noted", nil)
	r.post("go")
	card := r.waitCard()
	r.post("a new request")
	ck, kind := r.app.readCheckpoint(card.ID)
	if kind != "" || ck.State != ckCancelled {
		t.Fatalf("checkpoint %s %s", kind, ck.State)
	}
	res, b := r.decide(card.ID, "approve", "once")
	if res.StatusCode == 200 {
		t.Fatalf("approve of a cancelled checkpoint %s", b)
	}
	waitIdle(t, r.srv.URL, r.bot.ID, r.token)
	if shellStartCount(t, r.app, r.bot.ID) != 1 || shellOKCount(t, r.app, r.bot.ID) != 0 {
		t.Fatalf("starts %d ok %d\n%s", shellStartCount(t, r.app, r.bot.ID), shellOKCount(t, r.app, r.bot.ID), shellEndDetail(t, r.app, r.bot.ID))
	}
	again, kind := r.app.readCheckpoint(card.ID)
	if kind != "" || again.State != ckCancelled {
		t.Fatalf("checkpoint after approve %s %s", kind, again.State)
	}
	if auditCount(auditRows(t, r.dir), "cancel", "message") != 1 {
		t.Fatal("cancel was not audited")
	}
}

// TestGolden_CwdRecheckRefuses fails if approve runs after the stored
// directory is gone, or if that refusal is not audited as cwd.
func TestGolden_CwdRecheckRefuses(t *testing.T) {
	r, _ := newResumeRig(t, "", "echo CWD_MARKER", "should not continue", nil)
	sub := filepath.Join(r.app.botWorkspace(r.bot.ID), "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	r.app.shellCwdMu.Lock()
	if r.app.shellCwd == nil {
		r.app.shellCwd = map[string]string{}
	}
	r.app.shellCwd[r.bot.ID] = sub
	r.app.shellCwdMu.Unlock()
	r.post("go")
	card := r.waitCard()
	if card.Cwd != sub && !strings.HasSuffix(card.Cwd, string(filepath.Separator)+"sub") {
		t.Fatalf("ask cwd %s", card.Cwd)
	}
	if err := os.Remove(sub); err != nil {
		t.Fatal(err)
	}
	res, b := r.decide(card.ID, "approve", "once")
	if res.StatusCode != 200 {
		t.Fatalf("approve %d %s", res.StatusCode, b)
	}
	if shellOKCount(t, r.app, r.bot.ID) != 0 {
		t.Fatalf("cwd failure still ran\n%s", shellEndDetail(t, r.app, r.bot.ID))
	}
	if auditCount(auditRows(t, r.dir), "resume_refused", "cwd") != 1 {
		t.Fatal("cwd refusal was not audited")
	}
}

// TestGolden_HookDecisionPostsNoteOnce fails if a hook decision posts more
// than once, posts for a different task, or tells a critical hook item to run.
func TestGolden_HookDecisionPostsNoteOnce(t *testing.T) {
	var calls atomic.Int32
	modelSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		calls.Add(1)
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = io.WriteString(w, "{\"message\":{\"role\":\"assistant\",\"content\":\"hook noted\"},\"done\":true}\n")
	}))
	t.Cleanup(modelSrv.Close)
	app := newApp(t, "", model.NewOllama(modelSrv.URL))
	app.editPol(func(p *policy.Policy) {
		p.Broker = "hook"
		p.BrokerRisks = []permbroker.RiskEntry{{
			Tool: "shell", Argv: []string{"echo", "CRIT_HOOK"}, Level: permbroker.LevelCritical,
		}}
	})
	app.cfg.AuthToken = resumeAdminToken
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "Hook", "instructions": "shell"}, resumeAdminToken)
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	const task = "task-keep"
	app.broker.NoteUserText(bot.ID, task, "do the thing")
	ws := t.TempDir()

	ask := func(command, taskID string) permbroker.PendingSnapshot {
		t.Helper()
		raw, err := json.Marshal(map[string]string{"command": command})
		if err != nil {
			t.Fatal(err)
		}
		d := app.broker.Evaluate(context.Background(), permbroker.Request{
			BotID: bot.ID, SessionID: "cli:" + bot.ID, TaskID: taskID,
			Cwd: ws, Workspace: ws, ToolName: "run_shell", ToolInput: raw,
			Origin: permbroker.OriginHook,
		})
		if d.PendingID == "" || d.Verdict == permbroker.VerdictAllow {
			t.Fatalf("evaluate %s %+v", command, d)
		}
		snap, ok := app.broker.SnapshotPending(d.PendingID)
		if !ok {
			t.Fatal("missing snapshot")
		}
		return snap
	}
	notes := func() []string {
		t.Helper()
		msgs, err := app.st.ListMessages(bot.ID, "user", "", 40)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, m := range msgs {
			if strings.HasPrefix(m.Content, hookNoteMarker) {
				out = append(out, m.Content)
			}
		}
		return out
	}

	miss := ask("echo MISMATCH", "other-task")
	res, b = do(t, "POST", srv.URL+"/api/permbroker/pending/"+miss.ID, map[string]string{"decision": "approve", "scope": "once"}, resumeAdminToken)
	if res.StatusCode != 200 {
		t.Fatalf("mismatch decide %d %s", res.StatusCode, b)
	}
	if len(notes()) != 0 || auditCount(auditRows(t, app.cfg.DataDir), "cli_notify", "") != 0 {
		t.Fatalf("mismatched task posted %v", notes())
	}

	okSnap := ask("echo HOOK_OK", task)
	if okSnap.Level == permbroker.LevelCritical {
		t.Fatalf("non-critical item level %s", okSnap.Level)
	}
	res, b = do(t, "POST", srv.URL+"/api/permbroker/pending/"+okSnap.ID, map[string]string{"decision": "approve", "scope": "once"}, resumeAdminToken)
	if res.StatusCode != 200 {
		t.Fatalf("approve %d %s", res.StatusCode, b)
	}
	want := hookNoteMarker + "Notice: request " + okSnap.ID + " was approved; the command shown below as data: " + hookCommandData("echo HOOK_OK")
	gotNotes := notes()
	if len(gotNotes) != 1 || gotNotes[0] != want {
		t.Fatalf("note %q", gotNotes)
	}
	mapped := mapHist(store.Message{Role: "system", Content: gotNotes[0]}, nil)
	if mapped.Role != "system" || strings.Contains(mapped.Content, hookNoteMarker) || strings.Contains(mapped.Content, "\n") {
		t.Fatalf("mapHist %+v", mapped)
	}
	if !strings.Contains(mapped.Content, "shown below as data:") || !strings.Contains(mapped.Content, hookCommandData("echo HOOK_OK")) {
		t.Fatalf("mapHist %+v", mapped)
	}
	app.notifyHook(okSnap, "approve")
	if again := notes(); len(again) != 1 || again[0] != want {
		t.Fatalf("second post %q", again)
	}
	if auditCount(auditRows(t, app.cfg.DataDir), "cli_notify", "approve") != 1 {
		t.Fatal("cli_notify approve count")
	}

	denySnap := ask("echo HOOK_DENY", task)
	res, b = do(t, "POST", srv.URL+"/api/permbroker/pending/"+denySnap.ID, map[string]string{"decision": "deny"}, resumeAdminToken)
	if res.StatusCode != 200 {
		t.Fatalf("deny %d %s", res.StatusCode, b)
	}
	denyWant := hookNoteMarker + "Notice: request " + denySnap.ID + " was denied."
	gotNotes = notes()
	if len(gotNotes) != 2 || gotNotes[0] != want || gotNotes[1] != denyWant {
		t.Fatalf("notes %q", gotNotes)
	}
	app.notifyHook(denySnap, "deny")
	if again := notes(); len(again) != 2 {
		t.Fatalf("second deny post %q", again)
	}

	crit := ask("echo CRIT_HOOK", task)
	if crit.Level != permbroker.LevelCritical || crit.Origin != permbroker.OriginHook {
		t.Fatalf("critical hook %+v", crit)
	}
	app.notifyHook(crit, "approve")
	res, b = do(t, "POST", srv.URL+"/api/permbroker/pending/"+crit.ID, map[string]string{"decision": "approve", "scope": "once"}, resumeAdminToken)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("critical approve %d %s", res.StatusCode, b)
	}
	for _, n := range notes() {
		if strings.Contains(n, "shown below as data") && strings.Contains(n, crit.ID) {
			t.Fatalf("critical hook note %q", n)
		}
		if strings.Contains(n, "CRIT_HOOK") {
			t.Fatalf("critical hook note %q", n)
		}
	}
}

// TestGolden_CriticalApprovalIsBoundNotAToken fails if a critical native
// approve does not run, or if that approval is a reusable once-token.
// A non-critical card would also consume a token and then not allow a later
// Evaluate, so the level assertion is part of the guard.
func TestGolden_CriticalApprovalIsBoundNotAToken(t *testing.T) {
	const cmd = "echo CRIT_ONCE"
	risks := []permbroker.RiskEntry{{
		Tool: "shell", Argv: []string{"echo", "CRIT_ONCE"}, Level: permbroker.LevelCritical,
	}}
	r, _ := newResumeRig(t, "", cmd, "continued after critical", risks)
	r.post("go")
	card := r.waitCard()
	if card.Level != string(permbroker.LevelCritical) || card.Origin != permbroker.OriginNative {
		t.Fatalf("card level %s origin %s", card.Level, card.Origin)
	}
	res, b := r.decide(card.ID, "approve", "once")
	if res.StatusCode != 200 {
		t.Fatalf("approve %d %s", res.StatusCode, b)
	}
	waitIdle(t, r.srv.URL, r.bot.ID, r.token)
	waitRunStatus(t, r.app, r.bot.ID, "done")
	if shellOKCount(t, r.app, r.bot.ID) != 1 {
		t.Fatalf("critical command did not run once\n%s", shellEndDetail(t, r.app, r.bot.ID))
	}
	raw, err := json.Marshal(map[string]string{"command": cmd})
	if err != nil {
		t.Fatal(err)
	}
	d := r.app.broker.Evaluate(context.Background(), permbroker.Request{
		BotID: r.bot.ID, SessionID: "shell:" + r.bot.ID, Cwd: card.Cwd,
		Workspace: r.app.botWorkspace(r.bot.ID), ToolName: "run_shell",
		ToolInput: raw, Origin: permbroker.OriginNative,
	})
	if d.Verdict == permbroker.VerdictAllow {
		t.Fatal("once-token accepted a critical command")
	}
	if shellOKCount(t, r.app, r.bot.ID) != 1 {
		t.Fatalf("later evaluate ran the shell\n%s", shellEndDetail(t, r.app, r.bot.ID))
	}
}

// openAllowedResume suspends on git status, then stores an allow rule so
// every ResumeEval allows. A once-token would be spent by the first
// re-eval, and the second call would never reach markConsumed.
func openAllowedResume(t *testing.T) (*resumeRig, resumeCard, checkpoint) {
	t.Helper()
	const cmd = "git status"
	r, _ := newResumeRig(t, "", cmd, "continued once", nil)
	r.post("go")
	card := r.waitCard()
	if _, err := r.app.broker.SaveRule(permbroker.Rule{
		Effect: permbroker.EffectAllow, Argv: []string{"git", "status"},
		Tool: permbroker.ToolShell, Scope: permbroker.ScopeBot, BotID: r.bot.ID,
	}); err != nil {
		t.Fatal(err)
	}
	ck, kind := r.app.readCheckpoint(card.ID)
	if kind != "" || ck.State != ckOpen || ck.PendingID != card.ID {
		t.Fatalf("checkpoint %s %s", kind, ck.State)
	}
	return r, card, ck
}

func assertSavedCallOnce(t *testing.T, r *resumeRig, card resumeCard, before int) {
	t.Helper()
	if delta := waitSavedShellStarts(t, r.app, r.bot.ID, before, 1); delta != 1 {
		t.Fatalf("saved call ran %d times\n%s", delta, shellEndDetail(t, r.app, r.bot.ID))
	}
	got, kind := r.app.readCheckpoint(card.ID)
	if kind != "" || got.State != ckConsumed {
		t.Fatalf("checkpoint %s %s", kind, got.State)
	}
	waitRunStatus(t, r.app, r.bot.ID, "done")
}

// TestGolden_ResumeApprovedExecutesOnce fails if markConsumed accepts a
// checkpoint that is already consumed. A second HTTP approve is rejected
// before afterBrokerDecision, so the test drives resumeApproved itself.
// The allow rule makes both re-evals allow; the state check is the gate.
func TestGolden_ResumeApprovedExecutesOnce(t *testing.T) {
	t.Run("twice", func(t *testing.T) {
		r, card, ck := openAllowedResume(t)
		before := shellStartCount(t, r.app, r.bot.ID)
		r.app.afterBrokerDecision(ck.PendingID, "approve", ck.Pending)
		r.app.resumeApproved(ck)
		assertSavedCallOnce(t, r, card, before)
	})
	t.Run("concurrent", func(t *testing.T) {
		r, card, ck := openAllowedResume(t)
		before := shellStartCount(t, r.app, r.bot.ID)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		for i := 0; i < 2; i++ {
			go func() {
				defer wg.Done()
				<-start
				r.app.resumeApproved(ck)
			}()
		}
		close(start)
		wg.Wait()
		assertSavedCallOnce(t, r, card, before)
	})
}

func approveDoesNotRun(t *testing.T, r *resumeRig, card resumeCard, starts int) {
	t.Helper()
	res, b := r.decide(card.ID, "approve", "once")
	time.Sleep(400 * time.Millisecond)
	if shellStartCount(t, r.app, r.bot.ID) != starts || shellOKCount(t, r.app, r.bot.ID) != 0 {
		t.Fatalf("approve after cancel ran (%d %s)\n%s", res.StatusCode, b, shellEndDetail(t, r.app, r.bot.ID))
	}
	got, kind := r.app.readCheckpoint(card.ID)
	if kind != "" || got.State != ckCancelled {
		t.Fatalf("checkpoint after approve %s %s", kind, got.State)
	}
}

// TestGolden_StopCancelsWaitingRun fails if POST cancel leaves the
// checkpoint open, leaves the run row waiting, or a later approve runs.
func TestGolden_StopCancelsWaitingRun(t *testing.T) {
	r, _ := newResumeRig(t, "", "echo STOP_MARKER", "should not run", nil)
	r.post("go")
	card := r.waitCard()
	starts := shellStartCount(t, r.app, r.bot.ID)
	res, b := do(t, "POST", r.srv.URL+"/api/bots/"+r.bot.ID+"/runs/"+card.RunID+"/cancel", nil, r.token)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("cancel %d %s", res.StatusCode, b)
	}
	var body map[string]string
	decodeJSON(t, b, &body)
	if body["status"] != "cancelled" {
		t.Fatalf("cancel body %s", b)
	}
	ck, kind := r.app.readCheckpoint(card.ID)
	if kind != "" || ck.State != ckCancelled {
		t.Fatalf("checkpoint %s %s", kind, ck.State)
	}
	run, err := r.app.st.GetRun(card.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "cancelled" {
		t.Fatalf("stored run status %s", run.Status)
	}
	if auditCount(auditRows(t, r.dir), "cancel", "stop") != 1 {
		t.Fatal("stop was not audited")
	}
	approveDoesNotRun(t, r, card, starts)
}

// TestGolden_DeleteBotCancelsCheckpoint fails if deletion leaves the
// checkpoint open or a later approve runs the saved call.
func TestGolden_DeleteBotCancelsCheckpoint(t *testing.T) {
	r, _ := newResumeRig(t, "", "echo DELETE_MARKER", "should not run", nil)
	r.post("go")
	card := r.waitCard()
	starts := shellStartCount(t, r.app, r.bot.ID)
	res, b := do(t, http.MethodDelete, r.srv.URL+"/api/bots/"+r.bot.ID, nil, r.token)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete %d %s", res.StatusCode, b)
	}
	ck, kind := r.app.readCheckpoint(card.ID)
	if kind != "" || ck.State != ckCancelled {
		t.Fatalf("checkpoint %s %s", kind, ck.State)
	}
	if auditCount(auditRows(t, r.dir), "cancel", "delete") != 1 {
		t.Fatal("delete was not audited")
	}
	approveDoesNotRun(t, r, card, starts)
}
