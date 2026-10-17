package clisession

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// ACPAsk is one session/request_permission tool call.
// SessionID is the id Grok returned for this session. The broker stores a
// session grant under that id so a later turn, which loads the same id, matches.
type ACPAsk struct {
	SessionID string
	Tool      string
	ToolUseID string
	Args      map[string]any
}

// ACPDecision is the broker's answer. Allow is sent as allow-once.
// A deny is sent as reject-once. The host never selects allow_always.
type ACPDecision struct {
	Allow bool
}

// ACPHooks connect a Grok ACP session to the permission broker.
// A nil Decide fails the turn closed.
type ACPHooks struct {
	Decide func(ctx context.Context, ask ACPAsk) (ACPDecision, error)
	// Fail records a host failure. The turn also returns an error.
	Fail func(tool string, args map[string]any, reason string)
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type acpReply struct {
	raw map[string]any
}

type acpSession struct {
	turn    context.Context
	cmd     *exec.Cmd
	w       io.WriteCloser
	hooks   ACPHooks
	onEvent func(Event)
	ws      string

	mu        sync.Mutex
	wmu       sync.Mutex
	wg        sync.WaitGroup
	closed    bool
	nextID    int
	pending   map[string]chan acpReply
	promptID  string
	sessionID string
	cancels   []context.CancelFunc
	sawFinal  bool
	fatal     error
	failOnce  sync.Once
	res       Result
	tools     map[string]string
	results   map[string]bool
	exited    chan struct{}
}

func runACPSession(ctx context.Context, cmd *exec.Cmd, stdout io.Reader, stdin io.WriteCloser, spec Spec, onEvent func(Event)) (Result, error) {
	var hooks ACPHooks
	if spec.ACP != nil {
		hooks = *spec.ACP
	}
	s := &acpSession{
		turn:    ctx,
		cmd:     cmd,
		w:       stdin,
		hooks:   hooks,
		onEvent: onEvent,
		ws:      spec.Workspace,
		pending: map[string]chan acpReply{},
		tools:   map[string]string{},
		results: map[string]bool{},
		exited:  make(chan struct{}),
	}
	go s.read(stdout)
	if spec.ACP == nil || spec.ACP.Decide == nil {
		s.hostFail("no permission broker", "", nil)
		s.stop()
		return s.snapshot(), s.fatalErr()
	}
	if _, err := s.call(ctx, "initialize", map[string]any{
		"protocolVersion": 1,
		"clientCapabilities": map[string]any{
			"fs":       map[string]bool{"readTextFile": false, "writeTextFile": false},
			"terminal": false,
		},
	}); err != nil {
		return s.failCall(ctx, "initialize", err)
	}
	method, params, err := acpStart(spec)
	if err != nil {
		s.hostFail(err.Error(), "", nil)
		s.stop()
		return s.snapshot(), s.fatalErr()
	}
	result, err := s.call(ctx, method, params)
	if err != nil {
		return s.failCall(ctx, method, err)
	}
	sid := strOf(result, "sessionId", "session_id")
	if sid == "" {
		s.hostFail(method+" returned no session", "", nil)
		s.stop()
		return s.snapshot(), s.fatalErr()
	}
	s.mu.Lock()
	s.sessionID = sid
	s.mu.Unlock()
	if _, err := s.writePrompt(spec.Prompt, sid); err != nil {
		s.hostFail("session/prompt was not written", "", nil)
		s.stop()
		return s.snapshot(), s.fatalErr()
	}
	<-s.exited
	res := s.snapshot()
	if err := s.fatalErr(); err != nil {
		return res, err
	}
	if !s.saw() {
		s.hostFail("stream ended without a result", "", nil)
		return s.snapshot(), s.fatalErr()
	}
	return res, nil
}

// acpStart is session/new for a fresh turn and session/load for a later one.
// The object has no yoloMode, autoMode, or permission bypass.
func acpStart(spec Spec) (string, map[string]any, error) {
	cwd := strings.TrimSpace(spec.Workspace)
	if cwd == "" {
		return "", nil, fmt.Errorf("workspace is not available")
	}
	params := map[string]any{"cwd": cwd, "mcpServers": []any{}}
	if !spec.Fresh && strings.TrimSpace(spec.SessionID) != "" {
		params["sessionId"] = spec.SessionID
		return "session/load", params, nil
	}
	return "session/new", params, nil
}

func (s *acpSession) failCall(ctx context.Context, method string, err error) (Result, error) {
	if ctx.Err() != nil {
		s.hostFail("protocol timeout during "+method, "", nil)
		s.stop()
		return s.snapshot(), s.fatalErr()
	}
	s.hostFail(method+": "+err.Error(), "", nil)
	s.stop()
	return s.snapshot(), s.fatalErr()
}

func (s *acpSession) call(ctx context.Context, method string, params any) (map[string]any, error) {
	id := s.allocID()
	key := strconv.Itoa(id)
	ch := make(chan acpReply, 1)
	s.mu.Lock()
	s.pending[key] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, key)
		s.mu.Unlock()
	}()
	if err := s.writeJSON(rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params}); err != nil {
		return nil, err
	}
	select {
	case rep := <-ch:
		if rep.raw["error"] != nil {
			return nil, fmt.Errorf("%s", acpErrText(rep.raw["error"]))
		}
		result := asMap(rep.raw["result"])
		if result == nil {
			return map[string]any{}, nil
		}
		return result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.exited:
		return nil, fmt.Errorf("process exited during %s", method)
	}
}

func (s *acpSession) writePrompt(prompt, sid string) (string, error) {
	id := s.allocID()
	key := strconv.Itoa(id)
	// Store the id before the write. A fast agent can answer on the same
	// line, and the reader must already know which id ends the turn.
	s.mu.Lock()
	s.promptID = key
	s.mu.Unlock()
	err := s.writeJSON(rpcRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "session/prompt",
		Params: map[string]any{
			"sessionId": sid,
			"prompt":    []any{map[string]any{"type": "text", "text": prompt}},
		},
	})
	if err != nil {
		s.mu.Lock()
		if s.promptID == key {
			s.promptID = ""
		}
		s.mu.Unlock()
	}
	return key, err
}

func (s *acpSession) allocID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	return s.nextID
}

func (s *acpSession) read(r io.Reader) {
	var st streamAcc
	defer func() {
		s.cancelAsks()
		s.wg.Wait()
		s.mu.Lock()
		if s.sessionID != "" {
			st.out.SessionID = s.sessionID
		}
		st.out.Interrupted = false
		s.res = st.out
		s.mu.Unlock()
		close(s.exited)
	}()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if err := s.dispatch(sc.Text(), &st); err != nil {
			return
		}
	}
	if err := sc.Err(); err != nil && !s.failed() {
		s.hostFail("cli stream: "+err.Error(), "", nil)
	}
}

func (s *acpSession) dispatch(line string, st *streamAcc) error {
	line = strings.TrimSpace(line)
	if line == "" || line[0] != '{' {
		return nil
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil || raw == nil {
		s.hostFail("malformed acp message", "", nil)
		return s.fatalErr()
	}
	method, _ := raw["method"].(string)
	_, hasID := raw["id"]
	switch {
	case method == "session/update":
		s.onUpdate(raw, st)
		return nil
	case method == "session/request_permission":
		if !hasID {
			s.hostFail("permission request has no id", "", nil)
			return s.fatalErr()
		}
		ctx, cancel := context.WithCancel(s.turn)
		s.trackCancel(cancel)
		s.spawn(func() {
			defer cancel()
			s.onPermission(ctx, raw)
		})
		return nil
	case method != "" && hasID:
		_ = s.writeJSON(map[string]any{
			"jsonrpc": "2.0",
			"id":      raw["id"],
			"error":   map[string]any{"code": -32601, "message": "method not supported"},
		})
		return nil
	case method == "" && hasID:
		s.deliver(raw["id"], raw, st)
		return nil
	default:
		ev, ok := Parse(line)
		if !ok {
			return nil
		}
		if ev.Kind == "permission" {
			s.hostFail("permission request was not answered", "", nil)
			return s.fatalErr()
		}
		s.feed(st, ev)
		return nil
	}
}

func (s *acpSession) onUpdate(raw map[string]any, st *streamAcc) {
	params := asMap(raw["params"])
	if params == nil {
		return
	}
	upd := asMap(params["update"])
	if upd == nil {
		return
	}
	sid := s.currentSession()
	switch strOf(upd, "sessionUpdate") {
	case "agent_message_chunk":
		text := chunkText(upd["content"])
		if text == "" {
			return
		}
		s.feed(st, Event{Kind: "token", Text: text, SessionID: sid})
	case "tool_call":
		s.emitTool(st, upd, sid)
	case "tool_call_update":
		s.emitToolResult(st, upd, sid)
	}
}

func (s *acpSession) emitTool(st *streamAcc, upd map[string]any, sid string) {
	id := strOf(upd, "toolCallId", "tool_call_id")
	s.mu.Lock()
	if id != "" {
		if _, ok := s.tools[id]; ok {
			s.mu.Unlock()
			return
		}
	}
	s.mu.Unlock()
	name, args, _, err := mapACPTool(upd)
	if err != nil || name == "" {
		name = strOf(upd, "title", "kind")
		if name == "" {
			name = "tool"
		}
		if args == nil {
			args = map[string]any{}
		}
	}
	s.mu.Lock()
	if id != "" {
		s.tools[id] = name
	}
	s.mu.Unlock()
	s.feed(st, Event{Kind: "tool", ToolName: name, ToolArgs: args, SessionID: sid})
}

func (s *acpSession) emitToolResult(st *streamAcc, upd map[string]any, sid string) {
	status := strings.ToLower(strOf(upd, "status"))
	if status != "completed" && status != "failed" {
		return
	}
	id := strOf(upd, "toolCallId", "tool_call_id")
	s.mu.Lock()
	if id != "" && s.results[id] {
		s.mu.Unlock()
		return
	}
	if id != "" {
		s.results[id] = true
	}
	name := s.tools[id]
	s.mu.Unlock()
	if name == "" {
		name, _, _, _ = mapACPTool(upd)
	}
	if name == "" {
		name = "tool"
	}
	s.feed(st, Event{Kind: "tool_result", ToolName: name, Text: outputText(upd), SessionID: sid})
}

func (s *acpSession) deliver(id any, raw map[string]any, st *streamAcc) {
	key := idKey(id)
	s.mu.Lock()
	ch := s.pending[key]
	prompt := key != "" && key == s.promptID
	s.mu.Unlock()
	if prompt {
		s.finishPrompt(raw, st)
	}
	if ch == nil {
		return
	}
	select {
	case ch <- acpReply{raw: raw}:
	default:
	}
}

func (s *acpSession) finishPrompt(raw map[string]any, st *streamAcc) {
	if raw["error"] != nil {
		s.hostFail("session/prompt: "+acpErrText(raw["error"]), "", nil)
		return
	}
	stop := "end_turn"
	if result := asMap(raw["result"]); result != nil {
		if s := strOf(result, "stopReason", "stop_reason"); s != "" {
			stop = s
		}
	}
	text := st.b.String()
	s.feed(st, Event{
		Kind: "end", SessionID: s.currentSession(), StopReason: stop,
		Text: text, Final: strings.TrimSpace(text) != "",
	})
}

func (s *acpSession) onPermission(ctx context.Context, raw map[string]any) {
	params := asMap(raw["params"])
	if params == nil {
		s.hostFail("malformed permission request", "", nil)
		return
	}
	call := asMap(params["toolCall"])
	if call == nil {
		s.hostFail("malformed permission request", "", nil)
		return
	}
	tool, args, useID, err := mapACPTool(call)
	if err != nil {
		s.hostFail(err.Error(), "", nil)
		return
	}
	if s.hooks.Decide == nil {
		s.hostFail("no permission broker", tool, args)
		return
	}
	dec, err := s.hooks.Decide(ctx, ACPAsk{
		SessionID: s.currentSession(), Tool: tool, ToolUseID: useID, Args: args,
	})
	if s.failed() {
		return
	}
	if err != nil {
		s.hostFail(err.Error(), tool, args)
		return
	}
	opt, err := selectACPOption(acpOptions(params["options"]), dec.Allow)
	if err != nil {
		s.hostFail(err.Error(), tool, args)
		return
	}
	if err := s.writeJSON(map[string]any{
		"jsonrpc": "2.0",
		"id":      raw["id"],
		"result": map[string]any{
			"outcome": map[string]any{"outcome": "selected", "optionId": opt},
		},
	}); err != nil && !s.failed() && s.turn.Err() == nil {
		s.hostFail("permission response was not written", tool, args)
	}
}

func (s *acpSession) spawn(fn func()) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		fn()
	}()
}

func (s *acpSession) feed(st *streamAcc, ev Event) {
	if ev.Kind == "end" {
		s.mu.Lock()
		s.sawFinal = true
		s.mu.Unlock()
		// A legacy end line has no result text. The accumulated tokens are
		// the final text, so the reply tail matches a streaming-json fixture.
		if strings.TrimSpace(ev.Text) == "" && st.sawDelta {
			ev.Text = st.b.String()
			ev.Final = strings.TrimSpace(ev.Text) != ""
		}
	}
	_ = st.apply(ev, s.onEvent, false)
}

func (s *acpSession) trackCancel(cancel context.CancelFunc) {
	s.mu.Lock()
	s.cancels = append(s.cancels, cancel)
	s.mu.Unlock()
}

func (s *acpSession) cancelAsks() {
	s.mu.Lock()
	fns := s.cancels
	s.cancels = nil
	s.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

func (s *acpSession) hostFail(reason, tool string, args map[string]any) {
	s.failOnce.Do(func() {
		reason = strings.TrimSpace(reason)
		if reason == "" {
			reason = "acp host failed"
		}
		s.mu.Lock()
		s.fatal = fmt.Errorf("acp host: %s", reason)
		hooks := s.hooks
		s.mu.Unlock()
		if hooks.Fail != nil {
			if strings.TrimSpace(tool) == "" {
				tool = "acp"
			}
			if args == nil {
				args = map[string]any{}
			}
			hooks.Fail(tool, args, reason)
		}
		s.closeIn()
		if s.cmd != nil && s.cmd.Process != nil {
			killGroup(s.cmd.Process)
		}
	})
}

func (s *acpSession) failed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fatal != nil
}

func (s *acpSession) fatalErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fatal
}

func (s *acpSession) saw() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sawFinal
}

func (s *acpSession) currentSession() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionID
}

func (s *acpSession) snapshot() Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.res
}

func (s *acpSession) stop() {
	s.closeIn()
	if s.cmd != nil && s.cmd.Process != nil {
		killGroup(s.cmd.Process)
	}
	<-s.exited
}

func (s *acpSession) closeIn() {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.w != nil {
		_ = s.w.Close()
	}
}

func (s *acpSession) writeJSON(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed || s.w == nil {
		return fmt.Errorf("stdin closed")
	}
	_, err = s.w.Write(b)
	return err
}

func chunkText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	m := asMap(v)
	if m == nil {
		return ""
	}
	return strOf(m, "text")
}

func outputText(upd map[string]any) string {
	if raw := asMap(upd["rawOutput"]); raw != nil {
		if s := strOf(raw, "output_for_prompt", "output", "text"); s != "" {
			return s
		}
	}
	if s := strOf(upd, "text", "result"); s != "" {
		return s
	}
	switch c := upd["content"].(type) {
	case string:
		return c
	case map[string]any:
		if s := strOf(c, "text"); s != "" {
			return s
		}
	case []any:
		var b strings.Builder
		for _, item := range c {
			if s, ok := item.(string); ok {
				b.WriteString(s)
				continue
			}
			if m := asMap(item); m != nil {
				b.WriteString(strOf(m, "text"))
			}
		}
		return b.String()
	}
	return ""
}

func idKey(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

func acpErrText(v any) string {
	if m := asMap(v); m != nil {
		if s := strOf(m, "message", "error"); s != "" {
			return s
		}
	}
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return "request failed"
}
