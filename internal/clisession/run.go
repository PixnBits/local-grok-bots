package clisession

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

// Runner executes one headless CLI turn.
type Runner interface {
	Run(ctx context.Context, spec Spec, onEvent func(Event)) (Result, error)
}

// ExecRunner runs the real grok or claude binary. Auth stays in the CLI.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, spec Spec, onEvent func(Event)) (Result, error) {
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
	cmd, cleanup, err := confinedCommand(path, argv[1:], spec.Workspace)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return Result{}, err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
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
	res, parseErr := readEvents(stdout, onEvent)
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	if parseErr != nil {
		return res, parseErr
	}
	if waitErr != nil && strings.TrimSpace(res.Text) == "" {
		msg := strings.TrimSpace(sandbox.StripSeatbeltWarning(stderr.String()))
		if msg == "" {
			msg = waitErr.Error()
		}
		return res, fmt.Errorf("%s: %s", argv[0], clip(msg, 2000))
	}
	return res, nil
}

func readEvents(r io.Reader, onEvent func(Event)) (Result, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var b strings.Builder
	var sawDelta bool
	var sawFinal bool
	var out Result
	var errMsg string
	for sc.Scan() {
		ev, ok := Parse(sc.Text())
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
		case "tool":
			if onEvent != nil {
				onEvent(ev)
			}
		case "end":
			if ev.StopReason != "" {
				out.StopReason = ev.StopReason
			}
			if ev.NeedsInput {
				out.NeedsInput = true
			}
			// The final object is what we persist. Deltas are only the live view.
			if ev.Final && strings.TrimSpace(ev.Text) != "" {
				out.Text = ev.Text
				sawFinal = true
			}
			if onEvent != nil {
				onEvent(ev)
			}
		case "error":
			errMsg = ev.Text
			if onEvent != nil {
				onEvent(ev)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("cli stream: %w", err)
	}
	if !sawFinal && sawDelta {
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

func killGroup(p *os.Process) {
	if p == nil {
		return
	}
	_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
	_ = p.Kill()
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
