package permbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// evaluateTimeout is how long one socket evaluate may run.
// The deadline is a deny, including when the engine would have allowed.
const evaluateTimeout = 2 * time.Second

// Listener is one bot's evaluate socket. The directory is 0700 and the
// socket is 0600. Identity is the socket plus SO_PEERCRED, not a bot id
// in the request.
type Listener struct {
	bot string
	ln  net.Listener
	eng *Engine
	wg  sync.WaitGroup
}

// Listen replaces a stale socket at path and accepts one JSON request
// per connection. Unknown operations are denied and do not change state.
func (e *Engine) Listen(botID, sockPath string) (*Listener, error) {
	if e == nil {
		return nil, errors.New("no broker")
	}
	if botID == "" || !filepath.IsAbs(sockPath) {
		return nil, errors.New("socket path")
	}
	dir := filepath.Dir(sockPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if st, err := os.Lstat(sockPath); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("socket path is not a socket")
		}
		_ = os.Remove(sockPath)
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	l := &Listener{bot: botID, ln: ln, eng: e}
	l.wg.Add(1)
	go l.loop()
	return l, nil
}

func (l *Listener) loop() {
	defer l.wg.Done()
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return
		}
		go l.serve(c)
	}
}

// Close stops accept and waits for the accept loop. Connections already
// running finish on their own.
func (l *Listener) Close() error {
	if l == nil || l.ln == nil {
		return nil
	}
	err := l.ln.Close()
	l.wg.Wait()
	return err
}

// Path is the host socket path.
func (l *Listener) Path() string {
	if l == nil || l.ln == nil {
		return ""
	}
	return l.ln.Addr().String()
}

func (l *Listener) serve(c net.Conn) {
	defer c.Close()
	uid, pid, err := peerCred(c)
	if err != nil || uid != os.Getuid() {
		l.reply(c, wireReply{Verdict: VerdictDeny, Reason: "denied"})
		l.eng.auditPeer(l.bot, uid, pid)
		return
	}
	body, err := io.ReadAll(io.LimitReader(c, MaxRequest+1))
	if err != nil || len(body) == 0 || len(body) > MaxRequest {
		l.reply(c, wireReply{Verdict: VerdictDeny, Reason: "denied"})
		return
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	var msg wireRequest
	if err := dec.Decode(&msg); err != nil {
		l.reply(c, wireReply{Verdict: VerdictDeny, Reason: "denied"})
		return
	}
	if dec.More() {
		l.reply(c, wireReply{Verdict: VerdictDeny, Reason: "denied"})
		return
	}
	if msg.Op != "evaluate" {
		l.reply(c, wireReply{Verdict: VerdictDeny, Reason: "denied"})
		return
	}
	if msg.HookEvent != "" && msg.HookEvent != "PreToolUse" {
		l.reply(c, wireReply{Verdict: VerdictDeny, Reason: "denied"})
		return
	}
	turn := l.eng.Active(l.bot)
	if turn.Session == "" {
		l.reply(c, wireReply{Verdict: VerdictDeny, Reason: "denied"})
		l.eng.auditPeer(l.bot, uid, pid)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), evaluateTimeout)
	defer cancel()
	done := make(chan Decision, 1)
	go func() {
		done <- l.eng.Evaluate(ctx, waitRequest(l.bot, turn, msg, uid, pid))
	}()
	var d Decision
	select {
	case d = <-done:
	case <-ctx.Done():
		l.reply(c, wireReply{Verdict: VerdictDeny, Reason: "denied"})
		return
	}
	if ctx.Err() != nil {
		l.reply(c, wireReply{Verdict: VerdictDeny, Reason: "denied"})
		return
	}
	reason := d.Reason
	if reason == "" {
		reason = "denied"
	}
	l.reply(c, wireReply{Verdict: d.Verdict, Reason: reason})
}

func waitRequest(bot string, turn Turn, msg wireRequest, uid, pid int) Request {
	return Request{
		BotID: bot, SessionID: turn.Session, RunID: turn.Run, TaskID: turn.Task,
		Cwd: msg.Cwd, ToolName: msg.ToolName, ToolInput: msg.ToolInput,
		ToolUseID: msg.ToolUseID, PeerUID: uid, PeerPID: pid,
	}
}

func (l *Listener) reply(c net.Conn, rep wireReply) {
	b, err := json.Marshal(rep)
	if err != nil || len(b) > MaxReply {
		b = []byte(`{"verdict":"deny","reason":"denied"}`)
	}
	_, _ = c.Write(b)
}

func (e *Engine) auditPeer(bot string, uid, pid int) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.auditDecision(Request{BotID: bot, PeerUID: uid, PeerPID: pid}, inspected{ClassNote: "none"}, VerdictDeny, "denied", "", "fail-closed", "", "")
}

// wireRequest matches cmd/lgb-permhook. Keep the JSON keys aligned.
type wireRequest struct {
	Op        string          `json:"op"`
	HookEvent string          `json:"hook_event_name"`
	SessionID string          `json:"session_id"`
	Cwd       string          `json:"cwd"`
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	ToolUseID string          `json:"tool_use_id"`
}

type wireReply struct {
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
}
