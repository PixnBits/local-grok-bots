package clisession

import (
	"fmt"
	"strings"
)

// Spec is one headless CLI turn. A fresh session is created with --session-id.
// Later turns pass --resume. The CLI keeps its own transcript. The daemon does
// not read that transcript back.
type Spec struct {
	Backend   string
	SessionID string
	Fresh     bool
	Prompt    string
	Workspace string
	Model     string
	// PermissionMode is the policy value. Empty means do not pass a mode flag:
	// the CLI prompts the user, the same as interactive use.
	PermissionMode string
	// Bin overrides the executable. Empty uses "grok" or "claude".
	Bin string
	// OnStart is called with the child pid after Start.
	OnStart func(pid int)
}

// Event is one parsed stream record.
type Event struct {
	Kind       string // token, tool, tool_result, end, error, meta
	Text       string
	SessionID  string
	ToolName   string
	ToolArgs   map[string]any
	StopReason string
	NeedsInput bool
	Final      bool
}

// Result is the captured end of a turn.
type Result struct {
	SessionID   string
	Text        string
	StopReason  string
	NeedsInput  bool
	Interrupted bool
}

// Args builds argv for a headless turn, including argv0.
// The daemon does not wrap this command in another jail.
func Args(spec Spec) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(spec.Backend)) {
	case "grok":
		bin := spec.Bin
		if bin == "" {
			bin = "grok"
		}
		return append([]string{bin}, grokFlags(spec)...), nil
	case "claude":
		bin := spec.Bin
		if bin == "" {
			bin = "claude"
		}
		return append([]string{bin}, claudeFlags(spec)...), nil
	default:
		return nil, fmt.Errorf("unknown cli backend %q", spec.Backend)
	}
}

func grokFlags(spec Spec) []string {
	var args []string
	if spec.Model != "" {
		args = append(args, "-m", spec.Model)
	}
	args = append(args, sessionFlags(spec)...)
	args = append(args,
		"-p", spec.Prompt,
		"--sandbox", "workspace",
		"--cwd", spec.Workspace,
		"--output-format", "streaming-json",
		"--no-auto-update",
	)
	// --always-approve is an explicit always-allow policy, never a default.
	if alwaysAllow(spec.PermissionMode) {
		args = append(args, "--always-approve")
	}
	return args
}

func claudeFlags(spec Spec) []string {
	var args []string
	if spec.Model != "" {
		args = append(args, "--model", spec.Model)
	}
	args = append(args, sessionFlags(spec)...)
	args = append(args,
		"-p", spec.Prompt,
		"--output-format", "stream-json",
		"--verbose",
		"--include-partial-messages",
	)
	if strings.TrimSpace(spec.PermissionMode) != "" {
		args = append(args, "--permission-mode", spec.PermissionMode)
	}
	return args
}

func sessionFlags(spec Spec) []string {
	if spec.SessionID == "" {
		return nil
	}
	if spec.Fresh {
		return []string{"--session-id", spec.SessionID}
	}
	return []string{"--resume", spec.SessionID}
}

func alwaysAllow(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "always", "always-allow", "always_allow", "bypasspermissions", "bypass", "dontask":
		return true
	default:
		return false
	}
}
