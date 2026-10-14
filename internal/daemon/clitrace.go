package daemon

import (
	"encoding/json"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/audit"
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

// result pairs with the oldest open call. Claude names a result by its
// tool_use_id, not the tool, so order is what pairs them.
func (t *cliTrace) result(name, body string) {
	call := pendingCall{name: name, args: json.RawMessage(`{}`)}
	if len(t.pending) > 0 {
		call = t.pending[0]
		t.pending = t.pending[1:]
	}
	t.add(store.ToolRecord{Name: call.name, Arguments: call.args, OK: true, Result: clip(audit.RedactText(body), 4000)})
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
		return strings.TrimSpace(t.buf.String())
	}
	return final
}

func (t *cliTrace) add(rec store.ToolRecord) {
	t.wrote = true
	_ = t.a.st.AddRunTool(t.runID, t.botID, rec)
}

// recordPermission stores a broker decision with the run's tool records.
// Arguments are already redacted by the broker.
func (a *App) recordPermission(payload any) {
	m, ok := payload.(map[string]any)
	if !ok {
		return
	}
	runID, _ := m["run_id"].(string)
	botID, _ := m["bot_id"].(string)
	tool, _ := m["tool"].(string)
	decision, _ := m["decision"].(string)
	if runID == "" || botID == "" {
		return
	}
	args, err := json.Marshal(m["arguments"])
	if err != nil || string(args) == "null" {
		args = []byte(`{}`)
	}
	detail := map[string]any{"decision": decision, "source": m["source"]}
	if r, _ := m["rule"].(string); r != "" {
		detail["rule"] = r
	}
	if tr, _ := m["transport"].(string); tr != "" {
		detail["transport"] = tr
	}
	body, _ := json.Marshal(detail)
	_ = a.st.AddRunTool(runID, botID, store.ToolRecord{
		Kind: "permission", Name: tool, Arguments: args, OK: decision == "allow", Result: string(body),
	})
}
