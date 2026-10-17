package clisession

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

// ErrTruncated means the stream ended without a final result.
// The caller keeps whatever text was captured and marks the run interrupted.
var ErrTruncated = errors.New("interrupted")

// Runner executes one headless CLI turn.
type Runner interface {
	Run(ctx context.Context, spec Spec, onEvent func(Event)) (Result, error)
}

// ExecRunner runs the real grok or claude binary.
// On Linux, Grok is started in a daemon pid jail. Nested Grok sandbox
// cannot create a user namespace on a host that restricts that.
type ExecRunner struct {
	Policy policy.Policy
	// PinLog receives a pin result when that backend is pinned.
	PinLog func(backend, path, result string)
	// HasTTY overrides controlling-terminal detection. Nil opens /dev/tty.
	// Tests set it so a developer terminal does not change the result.
	HasTTY func() bool
}

func (e ExecRunner) Run(ctx context.Context, spec Spec, onEvent func(Event)) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if strings.EqualFold(spec.Backend, "grok") && SlashPrompt(spec.Prompt) {
		if spec.ACP != nil && spec.ACP.Fail != nil {
			spec.ACP.Fail("acp", map[string]any{}, ErrSlash.Error())
		}
		return Result{}, ErrSlash
	}
	argv, err := Args(spec)
	if err != nil {
		return Result{}, err
	}
	path := argv[0]
	if !strings.Contains(path, "/") {
		looked, lookErr := exec.LookPath(path)
		if lookErr != nil {
			return Result{}, fmt.Errorf("%s not on PATH", path)
		}
		path = looked
	}
	if strings.EqualFold(spec.Backend, "grok") {
		if err := checkGrokVersion(ctx, path); err != nil {
			return Result{}, err
		}
	}
	if err := e.notePin(ctx, spec.Backend, path); err != nil {
		return Result{}, err
	}
	var cmd *exec.Cmd
	wrapped := grokHostJail() && strings.EqualFold(spec.Backend, "grok") && spec.Isolate != nil
	if wrapped {
		cmd, err = wrapGrokJail(ctx, path, argv[1:], spec)
		if err != nil {
			return Result{}, err
		}
	} else {
		cmd = exec.CommandContext(ctx, path, argv[1:]...)
	}
	if spec.Workspace != "" {
		cmd.Dir = spec.Workspace
	}
	if spec.Isolate != nil && !wrapped {
		// Nothing is inherited; an empty list still means an empty environment.
		cmd.Env = append([]string{}, spec.Isolate.Env...)
	}
	// Linux kills this process group. macOS uses the same group signal,
	// with a leader-only fallback if the group signal is rejected.
	prepareProc(cmd)
	// The marker is how boot recognizes this child. It is not inherited.
	applySessionMarker(cmd, spec.Marker)
	cmd.Cancel = func() error {
		killGroup(cmd.Process)
		return nil
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, err
	}
	grokACP := strings.EqualFold(spec.Backend, "grok")
	var stdin io.WriteCloser
	if spec.StreamControl || grokACP {
		stdin, err = cmd.StdinPipe()
		if err != nil {
			return Result{}, err
		}
	}
	// Empty permission_mode lets the CLI prompt. With no controlling terminal,
	// a prompt fails the turn. An explicit mode is passed through and is not
	// treated as a prompt, even if the stream mentions one.
	// Stream control and the Grok ACP host are themselves the permission host,
	// so a permission line is not a headless prompt failure.
	failPrompt := !spec.StreamControl && !grokACP && strings.TrimSpace(spec.PermissionMode) == "" && !e.interactive()
	if !spec.StreamControl && !grokACP && e.interactive() && strings.TrimSpace(spec.PermissionMode) == "" {
		cmd.Stdin = os.Stdin
	}
	var stderr bytes.Buffer
	promptCh := make(chan struct{}, 1)
	if failPrompt {
		watch := &lineWatch{onLine: func(string) {
			select {
			case promptCh <- struct{}{}:
			default:
			}
		}}
		cmd.Stderr = io.MultiWriter(&stderr, watch)
	} else {
		cmd.Stderr = &stderr
	}
	if err := cmd.Start(); err != nil {
		if stdin != nil {
			_ = stdin.Close()
		}
		return Result{}, err
	}
	if spec.OnStart != nil && cmd.Process != nil {
		spec.OnStart(cmd.Process.Pid)
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			killGroup(cmd.Process)
		case <-done:
		}
	}()
	var res Result
	var parseErr error
	if spec.StreamControl {
		res, parseErr = runControlSession(ctx, cmd, stdout, stdin, spec, onEvent)
	} else if grokACP {
		res, parseErr = runACPSession(ctx, cmd, stdout, stdin, spec, onEvent)
	} else {
		res, parseErr = readTurn(stdout, onEvent, failPrompt, promptCh, cmd)
	}
	waitErr := cmd.Wait()
	if grokACP && parseErr == nil && res.StopReason != "" {
		// The prompt was answered. The host closes stdin and stops a lingering
		// agent, so its exit status says nothing about the turn.
		waitErr = nil
	}
	if errors.Is(parseErr, ErrPermissionPrompt) {
		return res, ErrPermissionPrompt
	}
	if ctx.Err() != nil {
		res.Interrupted = true
		return res, ctx.Err()
	}
	if parseErr != nil {
		return res, parseErr
	}
	if res.Interrupted {
		return res, ErrTruncated
	}
	if waitErr != nil && strings.TrimSpace(res.Text) == "" {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = waitErr.Error()
		}
		// Redact before clipping so a key is not cut in half and then kept.
		return res, fmt.Errorf("%s: %s", argv[0], clip(audit.RedactText(msg), 2000))
	}
	return res, nil
}

// applySessionMarker sets LGB_SESSION_MARKER on the child and drops any
// inherited value. An invalid marker leaves the environment unchanged.
func applySessionMarker(cmd *exec.Cmd, marker string) {
	if cmd == nil || !validMarker(marker) {
		return
	}
	base := cmd.Env
	if base == nil {
		base = os.Environ()
	}
	prefix := SessionMarkerEnv + "="
	out := make([]string, 0, len(base)+1)
	for _, kv := range base {
		if strings.HasPrefix(kv, prefix) {
			continue
		}
		out = append(out, kv)
	}
	cmd.Env = append(out, prefix+marker)
}

func (e ExecRunner) notePin(ctx context.Context, backend, path string) error {
	if _, ok := e.Policy.CLIPinFor(backend); !ok {
		return nil
	}
	err := verifyPin(ctx, e.Policy, backend, path)
	result := "ok"
	if err != nil {
		result = err.Error()
	}
	if e.PinLog != nil {
		e.PinLog(backend, path, result)
	}
	return err
}

func readTurn(stdout io.Reader, onEvent func(Event), failPrompt bool, promptCh <-chan struct{}, cmd *exec.Cmd) (Result, error) {
	if !failPrompt {
		return readEvents(stdout, onEvent, false)
	}
	type readOut struct {
		res Result
		err error
	}
	readCh := make(chan readOut, 1)
	go func() {
		res, err := readEvents(stdout, onEvent, true)
		readCh <- readOut{res, err}
	}()
	select {
	case <-promptCh:
		killGroup(cmd.Process)
		out := <-readCh
		return out.res, ErrPermissionPrompt
	case out := <-readCh:
		err := out.err
		select {
		case <-promptCh:
			err = ErrPermissionPrompt
		default:
		}
		if errors.Is(err, ErrPermissionPrompt) {
			killGroup(cmd.Process)
		}
		return out.res, err
	}
}

func readEvents(r io.Reader, onEvent func(Event), failPrompt bool) (Result, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var st streamAcc
	for sc.Scan() {
		line := sc.Text()
		if failPrompt && permissionText(line) {
			if ev, ok := Parse(line); ok && ev.SessionID != "" {
				st.out.SessionID = ev.SessionID
			}
			return st.out, ErrPermissionPrompt
		}
		ev, ok := Parse(line)
		if !ok {
			continue
		}
		if err := st.apply(ev, onEvent, failPrompt); err != nil {
			return st.out, err
		}
	}
	return st.finish(sc.Err())
}

// streamAcc is the text and session captured from one CLI stdout stream.
type streamAcc struct {
	b        strings.Builder
	sawDelta bool
	sawFinal bool
	out      Result
	errMsg   string
}

func (st *streamAcc) apply(ev Event, onEvent func(Event), failPrompt bool) error {
	if ev.SessionID != "" {
		st.out.SessionID = ev.SessionID
	}
	switch ev.Kind {
	case "token":
		st.sawDelta = true
		st.b.WriteString(ev.Text)
		if onEvent != nil {
			onEvent(ev)
		}
	case "tool", "tool_result", "permission_decision":
		if onEvent != nil {
			onEvent(ev)
		}
	case "end":
		st.sawFinal = true
		if ev.StopReason != "" {
			st.out.StopReason = ev.StopReason
		}
		if ev.NeedsInput {
			st.out.NeedsInput = true
		}
		if ev.Final && strings.TrimSpace(ev.Text) != "" {
			st.out.Text = ev.Text
		}
		if onEvent != nil {
			onEvent(ev)
		}
	case "permission":
		if failPrompt {
			return ErrPermissionPrompt
		}
	case "error":
		st.errMsg = ev.Text
		if onEvent != nil {
			onEvent(ev)
		}
	}
	return nil
}

func (st *streamAcc) finish(scanErr error) (Result, error) {
	if scanErr != nil {
		st.out.Interrupted = true
		if st.sawDelta && strings.TrimSpace(st.out.Text) == "" {
			st.out.Text = st.b.String()
		}
		return st.out, fmt.Errorf("cli stream: %w", scanErr)
	}
	if !st.sawFinal {
		st.out.Interrupted = true
		if st.sawDelta {
			st.out.Text = st.b.String()
		}
		return st.out, nil
	}
	if strings.TrimSpace(st.out.Text) == "" && st.sawDelta {
		st.out.Text = st.b.String()
	}
	if st.errMsg != "" && strings.TrimSpace(st.out.Text) == "" {
		msg := st.errMsg
		if msg == "" {
			msg = "cli error"
		}
		return st.out, fmt.Errorf("%s", msg)
	}
	return st.out, nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
