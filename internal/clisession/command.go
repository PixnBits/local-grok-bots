package clisession

import (
	"fmt"
	"strings"
)

// Spec is one headless CLI turn. Fresh sessions are created with --session-id.
// Later turns pass --resume. The CLI keeps the transcript on disk.
type Spec struct {
	Backend   string
	SessionID string
	Fresh     bool
	Prompt    string
	Workspace string
	Model     string
	// Bin overrides the executable (tests). Empty uses "grok" or "claude".
	Bin string
	// OnStart is called with the child process after a successful Start.
	OnStart func(pid int)
}

// Event is one parsed CLI output line.
type Event struct {
	Kind       string // token, tool, end, error
	Text       string
	SessionID  string
	ToolName   string
	StopReason string
	NeedsInput bool
	// Final means Text is the whole reply, not a delta.
	Final bool
}

// Result is the captured end of a turn.
type Result struct {
	SessionID  string
	Text       string
	StopReason string
	NeedsInput bool
}

// Args builds the argv for a headless turn, including argv0.
func Args(spec Spec) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(spec.Backend)) {
	case "grok":
		bin := spec.Bin
		if bin == "" {
			bin = "grok"
		}
		return append([]string{bin}, grokFlags(spec)...), nil
	case "claude":
		return nil, fmt.Errorf("claude backend is not implemented yet")
	default:
		return nil, fmt.Errorf("unknown cli backend %q", spec.Backend)
	}
}

// grokFlags matches the experiment plan. The first turn uses --session-id
// because --resume only continues a session that already exists.
func grokFlags(spec Spec) []string {
	var args []string
	if spec.Model != "" {
		args = append(args, "-m", spec.Model)
	}
	if !spec.Fresh && spec.SessionID != "" {
		args = append(args, "--resume", spec.SessionID)
	} else if spec.SessionID != "" {
		args = append(args, "--session-id", spec.SessionID)
	}
	args = append(args,
		"-p", spec.Prompt,
		"--sandbox", "workspace",
		"--cwd", spec.Workspace,
		"--output-format", "streaming-json",
		"--always-approve",
		"--no-auto-update",
	)
	return args
}
