package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/dlp"
	"github.com/PixnBits/local-grok-bots/internal/id"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func (a *App) executeCLI(ctx context.Context, bot store.Bot, runID string) {
	backend := a.policy.EffectiveBackend()
	a.takePending(runID)
	a.dropResume(bot.ID)
	defer a.clearCLIPID(bot.ID, runID)
	if !a.policy.AllowsBackend(backend) {
		a.failCLI(bot.ID, runID, backend, fmt.Errorf("cli backend %q is not allowed by policy", backend))
		return
	}
	// Empty is mcp. An unknown value is the same config error Load fail-closes on.
	transport, err := policy.NormClaudeTransport(a.policy.ClaudeTransport)
	if err != nil {
		a.failCLI(bot.ID, runID, backend, err)
		return
	}
	inputs, err := a.st.TurnInputs(bot.ID, runID)
	if err != nil {
		a.failCLI(bot.ID, runID, backend, err)
		return
	}
	fresh := strings.TrimSpace(bot.SessionID) == ""
	sessionID := bot.SessionID
	if fresh {
		sessionID = id.New()
		if err := a.st.SetBotSession(bot.ID, sessionID); err != nil {
			a.failCLI(bot.ID, runID, backend, err)
			return
		}
	}
	prompt, err := a.cliPrompt(bot, fresh, inputs)
	if err != nil {
		if fresh {
			_ = a.st.SetBotSession(bot.ID, "")
		}
		a.failCLI(bot.ID, runID, backend, err)
		return
	}
	if err := a.screenDLP(ctx, bot.ID, runID, backend, prompt); err != nil {
		if fresh {
			_ = a.st.SetBotSession(bot.ID, "")
		}
		return
	}
	ws, err := cliWorkspace(a.ws, bot.ID)
	if err != nil {
		if fresh {
			_ = a.st.SetBotSession(bot.ID, "")
		}
		a.failCLI(bot.ID, runID, backend, err)
		return
	}
	turnCtx := ctx
	if a.policy.TurnTimeout > 0 {
		var cancel context.CancelFunc
		turnCtx, cancel = context.WithTimeout(ctx, a.policy.TurnTimeout)
		defer cancel()
	}
	a.bus.Publish(runID, "status", map[string]any{"state": "working", "text": "working"})
	var runner clisession.Runner = clisession.ExecRunner{
		Policy: a.policy,
		HasTTY: a.cliTTY,
		PinLog: func(backend, path, result string) {
			a.log(bot.ID, "cli_pin", map[string]any{"backend": backend, "path": path, "result": result})
		},
	}
	if a.runner != nil {
		runner = a.runner
	}
	var streamed bool
	var pid int
	mode := a.policy.PermissionMode
	if policy.IsBypassMode(mode) && !a.policy.ManagedBypass {
		mode = ""
	}
	spec := clisession.Spec{
		Backend: backend, SessionID: sessionID, Fresh: fresh,
		Prompt: prompt, Workspace: ws, PermissionMode: mode,
		AllowRules: append([]string(nil), a.policy.ToolAllow...),
		DenyRules:  append([]string(nil), a.policy.ToolDeny...),
		OnStart: func(child int) {
			if child <= 0 {
				return
			}
			pid = child
			a.setCLIPID(bot.ID, child)
			a.auditCLI("cli_start", backend, sessionID, child, "")
		},
	}
	if bot.Model != nil {
		spec.Model = strings.TrimSpace(*bot.Model)
	}
	// mcp attaches the HTTP prompt tool only when a UI is allowed and the
	// daemon has an HTTP base. stream_control is the host on stdin even
	// when that UI is absent; the broker still denies residual asks.
	// none, and mcp with no host, pass --permission-prompts none.
	cliDenySource := "cli"
	eventTransport := ""
	host := strings.TrimSpace(a.permBase) != ""
	switch {
	case !strings.EqualFold(backend, "claude"):
	case transport == policy.TransportStreamControl:
		eventTransport = policy.TransportStreamControl
		spec.StreamControl = true
		botID := bot.ID
		spec.Control = &clisession.ControlHooks{
			Decide: func(ctx context.Context, ask clisession.ControlAsk) clisession.ControlDecision {
				return a.decideStreamControl(ctx, botID, runID, sessionID, ask)
			},
			Deny: func(tool string, args map[string]any, rule string) {
				a.recordControlDeny(botID, runID, tool, args, rule)
			},
		}
	case transport == policy.TransportNone:
		spec.PermissionPrompts = "none"
		eventTransport = policy.TransportNone
		cliDenySource = cliNoHostSource(a.policy.UIPrompts)
	case a.policy.UIPrompts && host:
		tok := a.registerPerm(bot.ID, runID, sessionID)
		defer a.unregisterPerm(tok)
		spec.MCPConfig = permissionMCPConfig(a.permBase, tok)
		spec.PermissionTool = permissionToolName
		eventTransport = policy.TransportMCP
	default:
		spec.PermissionPrompts = "none"
		eventTransport = policy.TransportNone
		cliDenySource = cliNoHostSource(a.policy.UIPrompts)
	}
	res, err := runner.Run(turnCtx, spec, func(ev clisession.Event) {
		switch ev.Kind {
		case "token":
			if ev.Text == "" {
				return
			}
			streamed = true
			a.bus.Publish(runID, "token", map[string]string{"text": ev.Text})
		case "tool":
			name := ev.ToolName
			if name == "" {
				name = "tool"
			}
			args := ev.ToolArgs
			if args == nil {
				args = map[string]any{}
			}
			redacted := redactValue(args)
			a.bus.Publish(runID, "status", map[string]any{"state": name, "text": name})
			a.bus.Publish(runID, "tool_call", map[string]any{"name": name, "arguments": redacted})
			a.log(bot.ID, "tool_start", map[string]any{"name": name, "arguments": redacted})
		case "tool_result":
			name := ev.ToolName
			if name == "" {
				name = "tool"
			}
			body := clip(audit.RedactText(ev.Text), 4000)
			a.bus.Publish(runID, "tool_result", map[string]any{"name": name, "ok": true, "result_or_error": body})
			a.log(bot.ID, "tool_end", map[string]any{"name": name, "ok": true})
		case "permission_decision":
			a.noteCLIPermission(bot.ID, runID, ev.ToolName, ev.ToolArgs, cliDenySource, eventTransport)
		case "end":
			for _, d := range ev.Denials {
				a.noteCLIPermission(bot.ID, runID, d.Tool, d.Args, cliDenySource, eventTransport)
			}
		}
	})
	if pid > 0 {
		result := "ok"
		if err != nil {
			result = "error"
			a.rtMu.Lock()
			idle := a.loops[bot.ID] != nil && a.loops[bot.ID].idleKill
			a.rtMu.Unlock()
			if idle || ctx.Err() != nil || turnCtx.Err() != nil {
				result = "interrupted"
			}
		}
		a.auditCLI("cli_stop", backend, sessionID, pid, result)
	}
	if res.SessionID != "" && res.SessionID != sessionID {
		_ = a.st.SetBotSession(bot.ID, res.SessionID)
		sessionID = res.SessionID
	}
	text := strings.TrimSpace(res.Text)
	if text != "" && !streamed {
		a.bus.Publish(runID, "token", map[string]string{"text": text})
	}
	a.log(bot.ID, "model_call", map[string]any{"model": backend, "ok": err == nil, "session_id": sessionID})
	switch {
	case a.consumeIdleKill(bot.ID):
		a.finishCLIInterrupted(bot.ID, runID, text)
	case a.policy.TurnTimeout > 0 && turnCtx.Err() != nil && ctx.Err() == nil && errors.Is(turnCtx.Err(), context.DeadlineExceeded):
		if text != "" {
			a.persistBotText(bot.ID, runID, text)
		}
		_, _ = a.st.FinishRun(runID, "error", "turn_timeout")
		a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": "turn_timeout"})
	case ctx.Err() != nil:
		if a.ctx.Err() != nil {
			a.finishCLIInterrupted(bot.ID, runID, text)
			break
		}
		if text != "" {
			a.persistBotText(bot.ID, runID, text)
		}
		a.finishInterrupted(bot.ID, runID, ctx)
	case errors.Is(err, clisession.ErrTruncated) || res.Interrupted:
		a.finishCLIInterrupted(bot.ID, runID, text)
	case err != nil:
		if fresh && strings.TrimSpace(res.SessionID) == "" {
			_ = a.st.SetBotSession(bot.ID, "")
		}
		a.failCLI(bot.ID, runID, backend, err)
	default:
		if text != "" {
			a.persistBotText(bot.ID, runID, text)
		}
		_, _ = a.st.FinishRun(runID, "done", "")
		a.bus.Publish(runID, "done", map[string]any{"run_id": runID})
	}
}

func (a *App) finishCLIInterrupted(botID, runID, text string) {
	if strings.TrimSpace(text) != "" {
		a.persistBotText(botID, runID, text)
	}
	_, _ = a.st.FinishRun(runID, "error", "interrupted")
	a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": "interrupted"})
}

// cliWorkspace is the CLI process cwd. It is not a jail.
func cliWorkspace(root, botID string) (string, error) {
	if strings.TrimSpace(botID) == "" || strings.Contains(botID, "/") || strings.Contains(botID, `\`) || strings.Contains(botID, "..") {
		return "", fmt.Errorf("invalid bot id")
	}
	dir := filepath.Join(root, "bots", botID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Abs(dir)
}

func (a *App) screenDLP(ctx context.Context, botID, runID, backend, content string) error {
	err := dlp.Scan(ctx, a.policy, content)
	if err == nil {
		return nil
	}
	a.log(botID, "dlp_denied", map[string]any{"error": err.Error()})
	if a.audit != nil && a.audit.Enabled() {
		a.audit.Write(map[string]any{"event": "dlp", "action": "deny", "detail": err.Error()})
	}
	a.failCLI(botID, runID, backend, err)
	return err
}

func cliNoHostSource(ui bool) string {
	if !ui {
		return "no_ui"
	}
	return "policy"
}

func (a *App) decideStreamControl(ctx context.Context, botID, runID, sessionID string, ask clisession.ControlAsk) clisession.ControlDecision {
	req := permission.Request{
		RunID: runID, BotID: botID, SessionID: sessionID,
		Tool: ask.Tool, Args: ask.Args, ToolUseID: ask.ToolUseID,
		Transport: policy.TransportStreamControl,
	}
	if a.perm == nil {
		return clisession.ControlDecision{Behavior: permission.Deny, Message: "denied"}
	}
	// A cancel that won before the ask was registered must not open a card.
	if ctx.Err() != nil {
		a.perm.Record(req, permission.Deny, "cancel", "")
		return clisession.ControlDecision{Silent: true}
	}
	out := a.perm.Evaluate(ctx, a.policy.Permission(), req)
	if out.Source == "cancel" {
		return clisession.ControlDecision{Silent: true}
	}
	if out.Behavior == permission.Allow {
		return clisession.ControlDecision{Behavior: permission.Allow, RawInput: ask.RawInput}
	}
	msg := out.Message
	if msg == "" {
		msg = "denied"
	}
	return clisession.ControlDecision{Behavior: permission.Deny, Message: msg}
}

func (a *App) recordControlDeny(botID, runID, tool string, args map[string]any, rule string) {
	if a.perm == nil {
		return
	}
	if args == nil {
		args = map[string]any{}
	}
	a.perm.Record(permission.Request{
		RunID: runID, BotID: botID, Tool: tool, Args: args,
		Transport: policy.TransportStreamControl,
	}, permission.Deny, "cli", rule)
}

func (a *App) noteCLIPermission(botID, runID, tool string, args map[string]any, source, transport string) {
	if a.perm == nil {
		return
	}
	if source == "" {
		source = "cli"
	}
	a.perm.Record(permission.Request{
		RunID: runID, BotID: botID, Tool: tool, Args: args, Transport: transport,
	}, permission.Deny, source, "")
}

func (a *App) auditCLI(event, backend, sessionID string, pid int, result string) {
	if a.audit == nil || !a.audit.Enabled() {
		return
	}
	fields := map[string]any{
		"event":      event,
		"pid":        pid,
		"backend":    backend,
		"session_id": sessionID,
	}
	if result != "" {
		fields["result"] = result
	}
	a.audit.Write(fields)
}

func (a *App) failCLI(botID, runID, backend string, err error) {
	a.log(botID, "model_call", map[string]any{"model": backend, "ok": false, "error": err.Error()})
	_, _ = a.st.FinishRun(runID, "error", err.Error())
	a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": err.Error()})
}

func (a *App) cliPrompt(bot store.Bot, fresh bool, inputs []store.Message) (string, error) {
	var b strings.Builder
	if fresh {
		if err := a.writeCLIPreamble(&b, bot); err != nil {
			return "", err
		}
	}
	names, err := a.st.BotNames()
	if err != nil {
		return "", err
	}
	if len(inputs) == 0 {
		b.WriteString("Continue.\n")
		return b.String(), nil
	}
	for i, m := range inputs {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(mapHist(m, names).Content)
	}
	return b.String(), nil
}

func (a *App) writeCLIPreamble(b *strings.Builder, bot store.Bot) error {
	mem, err := a.st.ListMemory(bot.ID)
	if err != nil {
		return err
	}
	b.WriteString("You are ")
	b.WriteString(bot.Name)
	b.WriteString(", a bot running on a local daemon.\n\nDescription:\n")
	if strings.TrimSpace(bot.Description) == "" {
		b.WriteString("(none)\n")
	} else {
		b.WriteString(bot.Description)
		b.WriteString("\n")
	}
	b.WriteString("\nMemory:\n")
	if len(mem) == 0 {
		b.WriteString("(none)\n")
	}
	for _, m := range mem {
		b.WriteString("- ")
		b.WriteString(m.Key)
		b.WriteString(": ")
		b.WriteString(m.Value)
		b.WriteString("\n")
	}
	b.WriteString("\nUse your own tools. This process is not wrapped in the daemon jail; your own sandbox is the boundary.\n")
	b.WriteString("Scheduled prompts are prefixed with [scheduled]. Direct messages from other bots are prefixed with [DM from Name].\n\n")
	return nil
}
