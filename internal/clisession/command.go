package clisession

import (
	"fmt"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/policy"
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
	// An always-allow mode is passed through only when the caller already
	// checked that managed policy set it.
	PermissionMode string
	// AllowRules and DenyRules are Claude-style patterns such as "Bash(git *)".
	AllowRules []string
	DenyRules  []string
	// MCPConfig is inline JSON for Claude's --mcp-config. When set, and
	// PermissionPrompts is not "none", the permission prompt tool is passed too.
	MCPConfig string
	// PermissionTool is the MCP tool name, mcp__<server>__approve.
	PermissionTool string
	// PermissionPrompts is Claude's --permission-prompts value. "none" denies
	// residual asks instead of sending them to a host. Empty omits the flag.
	PermissionPrompts string
	// StreamControl speaks the stream-json control protocol on stdin.
	// The prompt is a user message, not -p, and no MCP config is attached.
	StreamControl bool
	// Control is the broker hook for a stream-json turn. Nil denies every ask.
	Control *ControlHooks
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
	// Denials are permission_denials on a result event. They do not fail the turn.
	Denials []Denial
}

// Denial is one tool call the CLI refused.
type Denial struct {
	Tool  string
	Args  map[string]any
	UseID string
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
	for _, rule := range spec.AllowRules {
		args = append(args, "--allow", rule)
	}
	for _, rule := range spec.DenyRules {
		args = append(args, "--deny", rule)
	}
	// --always-approve is an explicit always-allow policy, never a default.
	// Other modes are passed through. Grok does not speak the Claude mode names.
	if alwaysAllow(spec.PermissionMode) {
		args = append(args, "--always-approve")
	} else if strings.TrimSpace(spec.PermissionMode) != "" {
		args = append(args, "--permission-mode", spec.PermissionMode)
	}
	return args
}

func claudeFlags(spec Spec) []string {
	if spec.StreamControl {
		return claudeStreamFlags(spec)
	}
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
	for _, rule := range spec.AllowRules {
		args = append(args, "--allowedTools", rule)
	}
	for _, rule := range spec.DenyRules {
		args = append(args, "--disallowedTools", rule)
	}
	prompts := strings.TrimSpace(spec.PermissionPrompts)
	if prompts != "" {
		args = append(args, "--permission-prompts", prompts)
	}
	// "none" means nobody can answer. Do not attach a prompt tool: Claude
	// would wait for that MCP server before the turn.
	if prompts != "none" && strings.TrimSpace(spec.MCPConfig) != "" {
		tool := spec.PermissionTool
		if tool == "" {
			tool = "mcp__lgbperm__approve"
		}
		args = append(args, "--mcp-config", spec.MCPConfig, "--permission-prompt-tool", tool)
	}
	return args
}

// claudeStreamFlags is the stream-json control transport.
// The prompt is written to stdin. There is no -p and no --mcp-config.
// Model, session, permission mode, and allow/deny rules stay as on the -p path.
func claudeStreamFlags(spec Spec) []string {
	var args []string
	if spec.Model != "" {
		args = append(args, "--model", spec.Model)
	}
	args = append(args, sessionFlags(spec)...)
	args = append(args,
		"--input-format", "stream-json",
		"--output-format", "stream-json",
		"--verbose",
		"--permission-prompt-tool", "stdio",
	)
	if strings.TrimSpace(spec.PermissionMode) != "" {
		args = append(args, "--permission-mode", spec.PermissionMode)
	}
	for _, rule := range spec.AllowRules {
		args = append(args, "--allowedTools", rule)
	}
	for _, rule := range spec.DenyRules {
		args = append(args, "--disallowedTools", rule)
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
	return policy.IsBypassMode(mode)
}
