package coi

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

const (
	// StatusOK means the CLI process was started.
	StatusOK = "ok"
	// StatusDenied is a policy, auth, or prompt refusal.
	StatusDenied = "denied"
	// StatusError is a timeout or a failure while the process was running.
	StatusError = "error"
)

// Call is one brokered CLI invocation.
type Call struct {
	Tool      policy.CLITool
	Args      []string
	Workspace string
	BaseEnv   []string
	// Paths are redacted in addition to the resolved credential home.
	Paths []string
	// OnPrompt is called when the CLI asks for a permission.
	// It must return without waiting on this process. The call is still denied.
	OnPrompt func(ctx context.Context)
}

// Result is the broker's decision. Output is set only when Status is ok.
type Result struct {
	Code   int
	Output string
	Status string
	Err    string
}

// Prepare checks the binary and the credential home and returns the tool with
// those paths resolved. The credential home must be a readable directory
// outside the workspace.
func Prepare(tool policy.CLITool, workspace string) (policy.CLITool, error) {
	ws := filepath.Clean(workspace)
	st, err := os.Stat(ws)
	if err != nil || !st.IsDir() || !filepath.IsAbs(ws) {
		return policy.CLITool{}, errors.New("workspace is not available")
	}
	if tool.Timeout <= 0 || tool.MaxOutput <= 0 {
		return policy.CLITool{}, errors.New("cli limits are not available")
	}
	bin, err := readyFile(tool.Path, ws, true)
	if err != nil {
		return policy.CLITool{}, errors.New("cli binary is not available")
	}
	home, err := readyFile(tool.CredentialHome, ws, false)
	if err != nil {
		return policy.CLITool{}, errors.New("credential home is not available")
	}
	tool.Path = bin
	tool.CredentialHome = home
	return tool, nil
}

func readyFile(path, workspace string, executable bool) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || Overlaps(workspace, clean) {
		return "", errors.New("bad path")
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", err
	}
	resolved = filepath.Clean(resolved)
	if Overlaps(workspace, resolved) {
		return "", errors.New("bad path")
	}
	st, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if executable {
		if !st.Mode().IsRegular() || st.Mode()&0o111 == 0 {
			return "", errors.New("not executable")
		}
		return resolved, nil
	}
	if !st.IsDir() {
		return "", errors.New("not a directory")
	}
	f, err := os.Open(resolved)
	if err != nil {
		return "", err
	}
	_ = f.Close()
	return resolved, nil
}

// Run executes the CLI with stdin closed, a scrubbed environment, and a cap
// on time and output. A permission prompt denies the call.
func Run(ctx context.Context, c Call) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	tool, err := Prepare(c.Tool, c.Workspace)
	if err != nil {
		return Result{Code: 1, Status: StatusDenied, Err: err.Error()}
	}
	for _, home := range []string{c.Tool.CredentialHome, tool.CredentialHome} {
		if err := CheckArgs(tool.AllowedArgs, c.Args, c.Workspace, home, tool.ValueFlags); err != nil {
			return Result{Code: 1, Status: StatusDenied, Err: err.Error()}
		}
	}
	secrets, err := ReadSecrets(tool.CredentialHome)
	if err != nil {
		return Result{Code: 1, Status: StatusDenied, Err: "credential home is not available"}
	}
	paths := append([]string{}, c.Paths...)
	paths = append(paths, c.Tool.CredentialHome, tool.CredentialHome)
	env, err := ScrubEnv(c.BaseEnv, tool.CredentialHome, c.Workspace)
	if err != nil {
		return Result{Code: 1, Status: StatusDenied, Err: "credential home is not available"}
	}
	runCtx, cancel := context.WithTimeout(ctx, tool.Timeout)
	defer cancel()
	cmd := exec.Command(tool.Path, c.Args...)
	cmd.Dir = c.Workspace
	cmd.Env = env
	cmd.Stdin = nil
	detach(cmd)
	capBuf := newCapture(int(tool.MaxOutput))
	capBuf.onLimit = func() { killTree(cmd) }
	capBuf.onPrompt = func() {
		if c.OnPrompt != nil {
			c.OnPrompt(runCtx)
		}
		killTree(cmd)
	}
	cmd.Stdout = capBuf
	cmd.Stderr = capBuf
	if err := cmd.Start(); err != nil {
		return Result{Code: 1, Status: StatusDenied, Err: "cli binary is not available"}
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-runCtx.Done():
			killTree(cmd)
		case <-done:
		}
	}()
	waitErr := cmd.Wait()
	close(done)
	text := capBuf.String()
	redacted := RedactOutput(text, paths, secrets)
	if capBuf.prompted() {
		return Result{Code: 1, Status: StatusDenied, Err: "permission prompt denied"}
	}
	if runCtx.Err() == context.DeadlineExceeded || ctx.Err() != nil {
		return Result{Code: 1, Status: StatusError, Err: "timed out"}
	}
	if capBuf.over() {
		redacted = strings.TrimRight(redacted, "\n") + "\n[output truncated]\n"
		return Result{Code: 0, Output: redacted, Status: StatusOK}
	}
	code := 0
	if waitErr != nil {
		var exit *exec.ExitError
		if errors.As(waitErr, &exit) {
			code = exit.ExitCode()
		} else {
			return Result{Code: 1, Status: StatusError, Err: "cli failed"}
		}
	}
	if code < 0 || code > 125 {
		code = 1
	}
	return Result{Code: code, Output: redacted, Status: StatusOK}
}

type capture struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	tail     bytes.Buffer
	n, max   int
	hitOver  bool
	hitAsk   bool
	onLimit  func()
	onPrompt func()
}

func newCapture(max int) *capture {
	if max < 1 {
		max = 1
	}
	return &capture{max: max}
}

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.tail.Write(p)
	if c.tail.Len() > 8192 {
		b := append([]byte(nil), c.tail.Bytes()[c.tail.Len()-4096:]...)
		c.tail.Reset()
		c.tail.Write(b)
	}
	ask := !c.hitAsk && clisession.PermissionPrompt(c.tail.String())
	if ask {
		c.hitAsk = true
	}
	room := c.max - c.n
	take := p
	over := false
	if room <= 0 {
		over = !c.hitOver
		c.hitOver = true
		take = nil
	} else if len(take) > room {
		take = take[:room]
		over = !c.hitOver
		c.hitOver = true
	}
	_, _ = c.buf.Write(take)
	c.n += len(take)
	limit := c.onLimit
	prompt := c.onPrompt
	c.mu.Unlock()
	if ask && prompt != nil {
		prompt()
	}
	if over && limit != nil && !ask {
		limit()
	}
	return len(p), nil
}

func (c *capture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func (c *capture) prompted() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hitAsk
}

func (c *capture) over() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hitOver
}
