package clisession

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
)

// ControlAsk is one can_use_tool request from Claude.
// RawInput is the original input object, unchanged, for updatedInput.
type ControlAsk struct {
	RequestID string
	Tool      string
	ToolUseID string
	Args      map[string]any
	RawInput  json.RawMessage
}

// ControlDecision is the broker's answer.
// Silent means the CLI cancelled the ask: write no control_response.
type ControlDecision struct {
	Behavior string
	Message  string
	RawInput json.RawMessage
	Silent   bool
}

// ControlHooks connect the stream-json session to the permission broker.
// Wire shapes match claude-agent-sdk 0.2.167: _internal/query.py
// (_send_control_request, initialize, _handle_control_request) and the
// user message in _internal/client.py.
type ControlHooks struct {
	// Decide runs the broker. A cancelled ctx is a control_cancel_request
	// that arrived before the ask was registered.
	Decide func(ctx context.Context, ask ControlAsk) ControlDecision
	// Deny records a deny that did not go through Decide.
	Deny func(tool string, args map[string]any, rule string)
}

type controlSession struct {
	turn    context.Context
	w       io.WriteCloser
	hooks   ControlHooks
	onEvent func(Event)
	res     Result

	mu      sync.Mutex
	closed  bool
	initID  string
	initCh  chan initOutcome
	pending map[string]context.CancelFunc
	early   map[string]struct{}
	wg      sync.WaitGroup
	exited  chan struct{}
}

type initOutcome struct {
	fail string
}

func (o initOutcome) err() error {
	if o.fail == "" {
		return nil
	}
	return fmt.Errorf("claude control initialize: %s", o.fail)
}

func runControlSession(ctx context.Context, cmd *exec.Cmd, stdout io.Reader, stdin io.WriteCloser, spec Spec, onEvent func(Event)) (Result, error) {
	var hooks ControlHooks
	if spec.Control != nil {
		hooks = *spec.Control
	}
	s := &controlSession{
		turn:    ctx,
		w:       stdin,
		hooks:   hooks,
		onEvent: onEvent,
		pending: map[string]context.CancelFunc{},
		early:   map[string]struct{}{},
		exited:  make(chan struct{}),
	}
	readErr := make(chan error, 1)
	go func() {
		res, err := s.read(stdout)
		s.mu.Lock()
		s.res = res
		s.mu.Unlock()
		close(s.exited)
		readErr <- err
	}()
	if err := s.handshake(ctx); err != nil {
		s.stop(cmd)
		return Result{}, err
	}
	if err := s.writePrompt(spec.Prompt); err != nil {
		s.stop(cmd)
		return Result{}, err
	}
	<-s.exited
	err := <-readErr
	s.closeIn()
	s.mu.Lock()
	res := s.res
	s.mu.Unlock()
	return res, err
}

func (s *controlSession) stop(cmd *exec.Cmd) {
	s.closeIn()
	if cmd != nil && cmd.Process != nil {
		killGroup(cmd.Process)
	}
	<-s.exited
}

func (s *controlSession) handshake(ctx context.Context) error {
	id := newControlID(1)
	ch := make(chan initOutcome, 1)
	s.mu.Lock()
	s.initID = id
	s.initCh = ch
	s.mu.Unlock()
	if err := s.writeJSON(controlRequest{
		Type:      "control_request",
		RequestID: id,
		Request:   initBody{Subtype: "initialize", Hooks: nil},
	}); err != nil {
		return err
	}
	return s.waitInit(ctx, ch)
}

func (s *controlSession) waitInit(ctx context.Context, ch <-chan initOutcome) error {
	select {
	case out := <-ch:
		return out.err()
	case <-ctx.Done():
		select {
		case out := <-ch:
			return out.err()
		default:
			return ctx.Err()
		}
	case <-s.exited:
		select {
		case out := <-ch:
			return out.err()
		default:
			return fmt.Errorf("claude control initialize: no response")
		}
	}
}

func (s *controlSession) writePrompt(prompt string) error {
	return s.writeJSON(userLine{
		Type:      "user",
		SessionID: "",
		Message:   userBody{Role: "user", Content: prompt},
	})
}

func (s *controlSession) read(r io.Reader) (Result, error) {
	defer func() {
		s.cancelAll()
		s.wg.Wait()
	}()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var st streamAcc
	for sc.Scan() {
		s.dispatch(sc.Text(), &st)
	}
	return st.finish(sc.Err())
}

func (s *controlSession) dispatch(line string, st *streamAcc) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil || raw == nil {
		s.audit("control", nil, "malformed control message")
		return
	}
	typ, _ := raw["type"].(string)
	switch typ {
	case "control_response":
		s.deliverInit([]byte(line))
	case "control_request":
		s.onRequest([]byte(line))
	case "control_cancel_request":
		s.onCancel([]byte(line))
	default:
		if typ == "result" || typ == "end" {
			s.closeIn()
		}
		ev, ok := Parse(line)
		if !ok {
			return
		}
		_ = st.apply(ev, s.onEvent, false)
	}
}

func (s *controlSession) deliverInit(line []byte) {
	var msg struct {
		Response struct {
			Subtype   string `json:"subtype"`
			RequestID string `json:"request_id"`
			Error     string `json:"error"`
		} `json:"response"`
	}
	if err := json.Unmarshal(line, &msg); err != nil {
		s.audit("control", nil, "malformed control message")
		return
	}
	id := msg.Response.RequestID
	s.mu.Lock()
	match := s.initCh != nil && id != "" && id == s.initID
	ch := s.initCh
	if match {
		s.initCh = nil
	}
	s.mu.Unlock()
	if !match {
		if id == "" {
			s.audit("control", nil, "malformed control message")
		}
		return
	}
	switch msg.Response.Subtype {
	case "success":
		ch <- initOutcome{}
	case "error":
		fail := strings.TrimSpace(msg.Response.Error)
		if fail == "" {
			fail = "error"
		}
		ch <- initOutcome{fail: fail}
	default:
		ch <- initOutcome{fail: "malformed response"}
	}
}

func (s *controlSession) onRequest(line []byte) {
	var env struct {
		RequestID string          `json:"request_id"`
		Request   json.RawMessage `json:"request"`
	}
	if err := json.Unmarshal(line, &env); err != nil {
		s.audit("control", nil, "malformed control message")
		return
	}
	id := strings.TrimSpace(env.RequestID)
	if id == "" {
		s.audit("control", nil, "malformed control message")
		return
	}
	body := bytes.TrimSpace(env.Request)
	if len(body) == 0 || body[0] != '{' {
		s.replyError(id, "malformed control request")
		s.audit("control", nil, "malformed control request")
		return
	}
	var req struct {
		Subtype   string          `json:"subtype"`
		ToolName  string          `json:"tool_name"`
		Input     json.RawMessage `json:"input"`
		ToolUseID string          `json:"tool_use_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.replyError(id, "malformed control request")
		s.audit("control", nil, "malformed control request")
		return
	}
	switch req.Subtype {
	case "can_use_tool":
		s.ask(id, req.ToolName, req.ToolUseID, req.Input)
	default:
		msg := "malformed control request"
		tool := "control"
		if strings.TrimSpace(req.Subtype) != "" {
			// Same text as claude-agent-sdk 0.2.167 query.py
			// _handle_control_request: Unsupported control request subtype.
			msg = "Unsupported control request subtype: " + req.Subtype
			tool = req.Subtype
		}
		s.replyError(id, msg)
		s.audit(tool, nil, msg)
	}
}

func (s *controlSession) ask(id, tool, useID string, input json.RawMessage) {
	tool = strings.TrimSpace(tool)
	if tool == "" {
		s.replyError(id, "malformed control request")
		s.audit("control", nil, "malformed control request")
		return
	}
	args, exact, ok := inputObject(input)
	if !ok {
		s.replyError(id, "malformed control request")
		s.audit(tool, nil, "malformed control request")
		return
	}
	ask := ControlAsk{RequestID: id, Tool: tool, ToolUseID: useID, Args: args, RawInput: exact}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx, cancel := context.WithCancel(s.turn)
		defer cancel()
		if !s.track(id, cancel) {
			cancel()
			if s.hooks.Decide != nil {
				_ = s.hooks.Decide(ctx, ask)
			} else {
				s.audit(tool, args, "cancel")
			}
			return
		}
		dec := ControlDecision{Behavior: "deny", Message: "denied"}
		if s.hooks.Decide != nil {
			dec = s.hooks.Decide(ctx, ask)
		}
		if !s.claim(id) || dec.Silent || ctx.Err() != nil {
			return
		}
		if dec.Behavior == "allow" {
			raw := dec.RawInput
			if len(bytes.TrimSpace(raw)) == 0 {
				raw = ask.RawInput
			}
			if len(bytes.TrimSpace(raw)) == 0 {
				raw = json.RawMessage(`{}`)
			}
			body, err := marshalJSON(allowBody{Behavior: "allow", UpdatedInput: raw})
			if err != nil {
				return
			}
			_ = s.writeJSON(controlResponse{
				Type: "control_response",
				Response: responseBody{
					Subtype:   "success",
					RequestID: id,
					Response:  body,
				},
			})
			return
		}
		msg := dec.Message
		if msg == "" {
			msg = "denied"
		}
		body, err := marshalJSON(denyBody{Behavior: "deny", Message: msg})
		if err != nil {
			return
		}
		_ = s.writeJSON(controlResponse{
			Type: "control_response",
			Response: responseBody{
				Subtype:   "success",
				RequestID: id,
				Response:  body,
			},
		})
	}()
}

func inputObject(raw json.RawMessage) (map[string]any, json.RawMessage, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return map[string]any{}, json.RawMessage(`{}`), true
	}
	if trimmed[0] != '{' {
		return nil, nil, false
	}
	var args map[string]any
	if err := json.Unmarshal(trimmed, &args); err != nil || args == nil {
		return nil, nil, false
	}
	exact := make(json.RawMessage, len(trimmed))
	copy(exact, trimmed)
	return args, exact, true
}

func (s *controlSession) onCancel(line []byte) {
	var msg struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(line, &msg); err != nil {
		s.audit("control", nil, "malformed control message")
		return
	}
	id := strings.TrimSpace(msg.RequestID)
	if id == "" {
		s.audit("control", nil, "malformed control message")
		return
	}
	s.mu.Lock()
	cancel, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
	} else {
		s.early[id] = struct{}{}
	}
	s.mu.Unlock()
	if ok && cancel != nil {
		cancel()
	}
}

func (s *controlSession) track(id string, cancel context.CancelFunc) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, pre := s.early[id]; pre {
		delete(s.early, id)
		return false
	}
	s.pending[id] = cancel
	return true
}

func (s *controlSession) claim(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pending[id]; !ok {
		return false
	}
	delete(s.pending, id)
	return true
}

func (s *controlSession) cancelAll() {
	s.mu.Lock()
	pending := s.pending
	s.pending = map[string]context.CancelFunc{}
	s.mu.Unlock()
	for _, cancel := range pending {
		if cancel != nil {
			cancel()
		}
	}
}

func (s *controlSession) replyError(id, message string) {
	_ = s.writeJSON(controlResponse{
		Type: "control_response",
		Response: responseBody{
			Subtype:   "error",
			RequestID: id,
			Error:     message,
		},
	})
}

func (s *controlSession) audit(tool string, args map[string]any, rule string) {
	if s.hooks.Deny == nil {
		return
	}
	if tool == "" {
		tool = "control"
	}
	if args == nil {
		args = map[string]any{}
	}
	s.hooks.Deny(tool, args, rule)
}

func (s *controlSession) writeJSON(v any) error {
	b, err := marshalJSON(v)
	if err != nil {
		return err
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		b = append(b, '\n')
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.w == nil {
		return io.ErrClosedPipe
	}
	_, err = s.w.Write(b)
	return err
}

func (s *controlSession) closeIn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.w != nil {
		_ = s.w.Close()
	}
}

func newControlID(n int) string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("req_%d_00000000", n)
	}
	return fmt.Sprintf("req_%d_%s", n, hex.EncodeToString(b[:]))
}

func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

type controlRequest struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Request   any    `json:"request"`
}

type initBody struct {
	Subtype string `json:"subtype"`
	Hooks   any    `json:"hooks"`
}

type userLine struct {
	Type            string   `json:"type"`
	SessionID       string   `json:"session_id"`
	Message         userBody `json:"message"`
	ParentToolUseID *string  `json:"parent_tool_use_id"`
}

type userBody struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type controlResponse struct {
	Type     string       `json:"type"`
	Response responseBody `json:"response"`
}

type responseBody struct {
	Subtype   string          `json:"subtype"`
	RequestID string          `json:"request_id"`
	Response  json.RawMessage `json:"response,omitempty"`
	Error     string          `json:"error,omitempty"`
}

type allowBody struct {
	Behavior     string          `json:"behavior"`
	UpdatedInput json.RawMessage `json:"updatedInput"`
}

type denyBody struct {
	Behavior string `json:"behavior"`
	Message  string `json:"message"`
}
