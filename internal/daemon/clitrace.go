package daemon

import (
	"encoding/json"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// cliTrace stores a CLI turn's intermediate text and tool calls in run_tools,
// the same records an Ollama turn writes, so the reply's tool summary
// survives a reload. Text streamed before a tool call is a text record; text
// after the last call is the reply and is not stored here.
type cliTrace struct {
	a       *App
	botID   string
	runID   string
	buf     strings.Builder
	all     strings.Builder
	pending []pendingCall
	wrote   bool
}

type pendingCall struct {
	name string
	args json.RawMessage
}

func (t *cliTrace) token(s string) {
	t.buf.WriteString(s)
	t.all.WriteString(s)
}

func (t *cliTrace) flushText() {
	text := strings.TrimSpace(t.buf.String())
	t.buf.Reset()
	if text == "" {
		return
	}
	t.add(store.ToolRecord{Kind: "text", OK: true, Result: clip(text, maxReplyBytes)})
}

// tool records the text before it and holds the call until its result.
func (t *cliTrace) tool(name string, redacted any) {
	t.flushText()
	raw, err := json.Marshal(redacted)
	if err != nil {
		raw = []byte(`{}`)
	}
	t.pending = append(t.pending, pendingCall{name: name, args: raw})
}

// toolEvent stores one CLI tool result and returns the body and ok for the
// live stream. A refused call is stored by deny, not as an ordinary result.
func (t *cliTrace) toolEvent(name, body string, failed, denied bool) (string, bool) {
	if denied {
		if strings.TrimSpace(body) == "" {
			body = toolDeniedMarker
		}
		t.deny(name)
		return body, false
	}
	ok := !failed
	t.result(name, body, ok)
	return body, ok
}

// deny stores one refused call as the fixed marker and empty arguments.
// The live event text stays on the bus; it is not the stored result.
func (t *cliTrace) deny(name string) {
	callName := name
	if len(t.pending) > 0 {
		if t.pending[0].name != "" {
			callName = t.pending[0].name
		}
		t.pending = t.pending[1:]
	}
	t.add(deniedToolRecord(callName))
}

// result pairs with the oldest open call. Claude names a result by its
// tool_use_id, not the tool, so order is what pairs them.
func (t *cliTrace) result(name, body string, ok bool) {
	call := pendingCall{name: name, args: json.RawMessage(`{}`)}
	if len(t.pending) > 0 {
		call = t.pending[0]
		t.pending = t.pending[1:]
	}
	if !ok && strings.TrimSpace(body) == "" {
		body = "error"
	}
	t.add(store.ToolRecord{Name: call.name, Arguments: call.args, OK: ok, Result: clip(audit.RedactText(body), 4000)})
}

// finish stores calls that never got a result, as not ok.
func (t *cliTrace) finish() {
	for _, c := range t.pending {
		t.add(store.ToolRecord{Name: c.name, Arguments: c.args, OK: false, Result: "no result"})
	}
	t.pending = nil
}

// reply is the thread message for the turn. When the CLI's final text is
// every token of the turn (no separate result text), only the part after the
// last tool call is the reply; the rest is already stored as text records.
func (t *cliTrace) reply(final string) string {
	if !t.wrote {
		return final
	}
	if strings.TrimSpace(final) == strings.TrimSpace(t.all.String()) {
		// The buffer is the reply. Keep its interior whitespace.
		return t.buf.String()
	}
	return final
}

// tail is the text streamed after the last tool call. A failed turn has no
// final result text, so this is the partial reply kept in the thread.
func (t *cliTrace) tail() string {
	return strings.TrimSpace(t.buf.String())
}

func (t *cliTrace) add(rec store.ToolRecord) {
	t.wrote = true
	_ = t.a.st.AddRunTool(t.runID, t.botID, rec)
}

// runPerms is one run's stored decisions: request ids, tool_use_ids, and a
// count per tool+arguments for reports that carry no id.
type runPerms struct {
	ids     map[string]bool
	useIDs  map[string]bool
	byShape map[string]int
	byTool  map[string]int
}

func permShape(tool string, redactedArgs []byte) string {
	return tool + "\x00" + string(redactedArgs)
}

// notePermLocked registers a decision and reports whether it is new.
func (a *App) notePermLocked(runID, reqID, useID, shape string) bool {
	if a.permSeen == nil {
		a.permSeen = map[string]*runPerms{}
	}
	rp := a.permSeen[runID]
	if rp == nil {
		rp = &runPerms{ids: map[string]bool{}, useIDs: map[string]bool{}, byShape: map[string]int{}, byTool: map[string]int{}}
		a.permSeen[runID] = rp
	}
	if reqID != "" && rp.ids[reqID] {
		return false
	}
	if reqID != "" {
		rp.ids[reqID] = true
	}
	if useID != "" {
		rp.useIDs[useID] = true
	}
	rp.byShape[shape]++
	rp.byTool[toolOf(shape)]++
	return true
}

func toolOf(shape string) string {
	tool, _, _ := strings.Cut(shape, "\x00")
	return tool
}

// claimEcho reports whether a CLI-side denial matches a decision already
// stored for the run, by tool_use_id, else by tool and arguments. A matched
// shape is consumed, so a repeated identical call still gets its own record.
func (a *App) claimEcho(runID, useID, shape string) bool {
	a.seenMu.Lock()
	defer a.seenMu.Unlock()
	rp := a.permSeen[runID]
	if rp == nil {
		return false
	}
	consume := func() {
		if rp.byShape[shape] > 0 {
			rp.byShape[shape]--
		}
		if rp.byTool[toolOf(shape)] > 0 {
			rp.byTool[toolOf(shape)]--
		}
	}
	if useID != "" && rp.useIDs[useID] {
		delete(rp.useIDs, useID)
		consume()
		return true
	}
	if rp.byShape[shape] > 0 {
		consume()
		return true
	}
	// A permission_denied event may name only the tool.
	if strings.HasSuffix(shape, "\x00{}") && rp.byTool[toolOf(shape)] > 0 {
		rp.byTool[toolOf(shape)]--
		return true
	}
	return false
}

// forgetRunPerms drops a finished run's dedupe state.
func (a *App) forgetRunPerms(runID string) {
	a.seenMu.Lock()
	delete(a.permSeen, runID)
	a.seenMu.Unlock()
}

// recordPermission stores a broker decision with the run's tool records,
// once per request id. Arguments are already redacted by the broker.
func (a *App) recordPermission(payload any) {
	m, ok := payload.(map[string]any)
	if !ok {
		return
	}
	runID, _ := m["run_id"].(string)
	botID, _ := m["bot_id"].(string)
	tool, _ := m["tool"].(string)
	decision, _ := m["decision"].(string)
	reqID, _ := m["id"].(string)
	useID, _ := m["tool_use_id"].(string)
	if runID == "" || botID == "" {
		return
	}
	args, err := json.Marshal(m["arguments"])
	if err != nil || string(args) == "null" {
		args = []byte(`{}`)
	}
	a.seenMu.Lock()
	fresh := a.notePermLocked(runID, reqID, useID, permShape(tool, args))
	a.seenMu.Unlock()
	if !fresh {
		return
	}
	// The broker reports a UI allow as allow_once or allow_session, not allow.
	// An answered question is allow on the wire and decision "answer" here.
	allowed := decision == permission.Allow || decision == permission.AllowOnce || decision == permission.AllowSession || decision == permission.Answer
	detail := map[string]any{"decision": decision, "allowed": allowed, "source": m["source"]}
	if r, _ := m["rule"].(string); r != "" {
		detail["rule"] = r
	}
	if tr, _ := m["transport"].(string); tr != "" {
		detail["transport"] = tr
	}
	if kind, _ := m["kind"].(string); kind != "" {
		detail["kind"] = kind
		if n, ok := answeredCount(m["answered"]); ok {
			detail["answered"] = n
		}
	}
	if id, _ := m["rule_id"].(string); id != "" {
		detail["rule_id"] = id
	}
	if c, _ := m["classification"].(string); c != "" {
		detail["classification"] = c
	}
	if sens, _ := m["sensitivity"].(string); sens != "" {
		detail["sensitivity"] = sens
	}
	if risk, _ := m["risk"].(string); risk != "" {
		detail["risk"] = risk
	}
	body, _ := json.Marshal(detail)
	_ = a.st.AddRunTool(runID, botID, store.ToolRecord{
		Kind: "permission", Name: tool, Arguments: args, OK: allowed, Result: string(body),
	})
	a.noteAutoSuggest(botID)
}

func answeredCount(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}
