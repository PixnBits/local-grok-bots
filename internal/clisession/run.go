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
// It does not put the process in the daemon jail. The CLI sandbox is the boundary.
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
	if err := e.notePin(ctx, spec.Backend, path); err != nil {
		return Result{}, err
	}
	cmd := exec.CommandContext(ctx, path, argv[1:]...)
	if spec.Workspace != "" {
		cmd.Dir = spec.Workspace
	}
	// Linux kills this process group. macOS uses the same group signal,
	// with a leader-only fallback if the group signal is rejected.
	prepareProc(cmd)
	cmd.Cancel = func() error {
		killGroup(cmd.Process)
		return nil
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, err
	}
	// Empty permission_mode lets the CLI prompt. With no controlling terminal,
	// a prompt fails the turn. An explicit mode is passed through and is not
	// treated as a prompt, even if the stream mentions one.
	failPrompt := strings.TrimSpace(spec.PermissionMode) == "" && !e.interactive()
	if e.interactive() && strings.TrimSpace(spec.PermissionMode) == "" {
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
	res, parseErr := readTurn(stdout, onEvent, failPrompt, promptCh, cmd)
	waitErr := cmd.Wait()
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
		return res, fmt.Errorf("%s: %s", argv[0], clip(msg, 2000))
	}
	return res, nil
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
	var b strings.Builder
	var sawDelta bool
	var sawFinal bool
	var out Result
	var errMsg string
	for sc.Scan() {
		line := sc.Text()
		if failPrompt && permissionText(line) {
			if ev, ok := Parse(line); ok && ev.SessionID != "" {
				out.SessionID = ev.SessionID
			}
			return out, ErrPermissionPrompt
		}
		ev, ok := Parse(line)
		if !ok {
			continue
		}
		if ev.SessionID != "" {
			out.SessionID = ev.SessionID
		}
		switch ev.Kind {
		case "token":
			sawDelta = true
			b.WriteString(ev.Text)
			if onEvent != nil {
				onEvent(ev)
			}
		case "tool", "tool_result", "permission_decision":
			if onEvent != nil {
				onEvent(ev)
			}
		case "end":
			sawFinal = true
			if ev.StopReason != "" {
				out.StopReason = ev.StopReason
			}
			if ev.NeedsInput {
				out.NeedsInput = true
			}
			if ev.Final && strings.TrimSpace(ev.Text) != "" {
				out.Text = ev.Text
			}
			if onEvent != nil {
				onEvent(ev)
			}
		case "permission":
			if failPrompt {
				return out, ErrPermissionPrompt
			}
		case "error":
			errMsg = ev.Text
			if onEvent != nil {
				onEvent(ev)
			}
		}
	}
	if err := sc.Err(); err != nil {
		out.Interrupted = true
		if sawDelta && strings.TrimSpace(out.Text) == "" {
			out.Text = b.String()
		}
		return out, fmt.Errorf("cli stream: %w", err)
	}
	if !sawFinal {
		out.Interrupted = true
		if sawDelta {
			out.Text = b.String()
		}
		return out, nil
	}
	if strings.TrimSpace(out.Text) == "" && sawDelta {
		out.Text = b.String()
	}
	if errMsg != "" && strings.TrimSpace(out.Text) == "" {
		if errMsg == "" {
			errMsg = "cli error"
		}
		return out, fmt.Errorf("%s", errMsg)
	}
	return out, nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
