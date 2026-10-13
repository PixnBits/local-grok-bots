package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/id"
	"github.com/PixnBits/local-grok-bots/internal/notify"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func (a *App) resolvedBackend(bot store.Bot) string {
	b := strings.ToLower(strings.TrimSpace(bot.CLIBackend))
	if b == "" {
		b = strings.ToLower(strings.TrimSpace(a.cfg.CLIBackend))
	}
	switch b {
	case "grok", "claude":
		return b
	default:
		return ""
	}
}

func (a *App) executeCLI(ctx context.Context, bot store.Bot, runID, backend string) {
	if !a.policy.AllowsBackend(backend) {
		a.takePending(runID)
		a.dropResume(bot.ID)
		a.failCLI(bot.ID, runID, backend, fmt.Errorf("cli backend %q is not allowed by policy", backend))
		return
	}
	a.takePending(runID)
	a.dropResume(bot.ID)
	a.touchActivity(bot.ID)
	defer a.clearCLIPID(bot.ID, runID)

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
		a.failCLI(bot.ID, runID, backend, err)
		return
	}
	ws, err := cliWorkspace(a.ws, bot.ID)
	if err != nil {
		a.failCLI(bot.ID, runID, backend, err)
		return
	}
	a.bus.Publish(runID, "status", map[string]any{"state": "working", "text": "working"})
	runner := a.runner
	if runner == nil {
		runner = clisession.ExecRunner{Policy: a.policy, Dial: a.shellDial}
	}
	var lastText string
	var needsInput bool
	var sawStream bool
	for round := 0; round < maxToolRounds; round++ {
		if ctx.Err() != nil {
			a.finishInterrupted(bot.ID, runID, ctx)
			return
		}
		spec := clisession.Spec{
			Backend: backend, SessionID: sessionID, Fresh: fresh,
			Prompt: prompt, Workspace: ws,
		}
		if bot.Model != nil {
			spec.Model = strings.TrimSpace(*bot.Model)
		}
		spec.OnStart = func(pid int) {
			if pid > 0 {
				a.setCLIPID(bot.ID, pid)
			}
		}
		res, streamed, err := a.runCLISpec(ctx, bot.ID, runID, runner, spec)
		if err != nil {
			if ctx.Err() != nil {
				a.finishInterrupted(bot.ID, runID, ctx)
				return
			}
			if fresh && strings.TrimSpace(res.SessionID) == "" {
				_ = a.st.SetBotSession(bot.ID, "")
			}
			a.failCLI(bot.ID, runID, backend, err)
			return
		}
		if res.SessionID != "" && res.SessionID != sessionID {
			_ = a.st.SetBotSession(bot.ID, res.SessionID)
			sessionID = res.SessionID
		}
		fresh = false
		a.log(bot.ID, "model_call", map[string]any{
			"model": backend, "ok": true, "session_id": sessionID,
		})
		if streamed {
			sawStream = true
		}
		visible, actions := extractActions(res.Text)
		lastText = visible
		needsInput = res.NeedsInput
		if len(actions) == 0 {
			break
		}
		follow, anyErr, anyQuery := a.runCLIActions(ctx, bot, runID, actions)
		if !anyErr && !anyQuery && strings.TrimSpace(visible) != "" {
			break
		}
		if round == maxToolRounds-1 {
			msg := "tool round limit"
			_, _ = a.st.FinishRun(runID, "error", msg)
			a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": msg})
			a.notifyTurn(bot.Name, msg, false)
			return
		}
		prompt = follow
	}
	if strings.TrimSpace(lastText) != "" {
		if !sawStream {
			a.bus.Publish(runID, "token", map[string]string{"text": lastText})
		}
		a.persistBotText(bot.ID, runID, lastText)
	}
	_, _ = a.st.FinishRun(runID, "done", "")
	a.bus.Publish(runID, "done", map[string]any{"run_id": runID})
	a.notifyTurn(bot.Name, lastText, needsInput)
}

func (a *App) runCLISpec(ctx context.Context, botID, runID string, runner clisession.Runner, spec clisession.Spec) (clisession.Result, bool, error) {
	var streamed bool
	res, err := runner.Run(ctx, spec, func(ev clisession.Event) {
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
			a.bus.Publish(runID, "tool_call", map[string]any{
				"name": name, "arguments": redacted,
			})
			a.log(botID, "tool_start", map[string]any{"name": name, "arguments": redacted})
		}
	})
	return res, streamed, err
}

func (a *App) runCLIActions(ctx context.Context, bot store.Bot, runID string, actions []cliAction) (string, bool, bool) {
	var lines []string
	var anyErr, anyQuery bool
	for _, act := range actions {
		if ctx.Err() != nil {
			break
		}
		a.bus.Publish(runID, "status", map[string]any{"state": act.Name, "text": act.Name})
		a.bus.Publish(runID, "tool_call", map[string]any{"name": act.Name, "arguments": redactValue(act.Args)})
		var body string
		var terr error
		if !allowedCLIAction(act.Name) {
			terr = errNotDaemonAction(act.Name)
		} else {
			body, terr = a.execTool(ctx, bot, act.Name, act.Args)
		}
		payload := map[string]any{"name": act.Name, "ok": terr == nil}
		line := act.Name + ": " + body
		if terr != nil {
			anyErr = true
			line = act.Name + " error: " + terr.Error()
			payload["ok"] = false
			body = terr.Error()
		}
		if act.Name == "list_bots" || act.Name == "read_bot" {
			anyQuery = true
		}
		payload["result_or_error"] = clip(body, 4000)
		lines = append(lines, line)
		a.bus.Publish(runID, "tool_result", payload)
	}
	return formatActionResults(lines), anyErr, anyQuery
}

// cliWorkspace is the CLI process cwd. Ollama file and shell tools stay on a.ws.
func cliWorkspace(root, botID string) (string, error) {
	if strings.TrimSpace(botID) == "" || strings.Contains(botID, "/") || strings.Contains(botID, `\`) || strings.Contains(botID, "..") {
		return "", fmt.Errorf("invalid bot id")
	}
	dir := filepath.Join(root, "bots", botID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Abs(dir)
}

func (a *App) notifyTurn(name, text string, needsInput bool) {
	title := name
	body := strings.TrimSpace(text)
	if needsInput {
		title = name + " needs input"
		if body == "" {
			body = "Waiting for you"
		}
	}
	if body == "" {
		body = "Finished"
	}
	body = clip(redactText(body), 180)
	if a.notifyFn != nil {
		a.notifyFn(title, body)
		return
	}
	notify.Send(title, body)
}

func (a *App) failCLI(botID, runID, backend string, err error) {
	a.log(botID, "model_call", map[string]any{"model": backend, "ok": false, "error": err.Error()})
	_, _ = a.st.FinishRun(runID, "error", err.Error())
	a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": err.Error()})
	if b, getErr := a.st.GetBot(botID); getErr == nil {
		a.notifyTurn(b.Name, err.Error(), false)
	}
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
	names, err := a.st.BotNames()
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
	b.WriteString("\nOther bots:\n")
	anyOther := false
	for id, name := range names {
		if id == bot.ID {
			continue
		}
		anyOther = true
		b.WriteString("- ")
		b.WriteString(name)
		b.WriteString("\n")
	}
	if !anyOther {
		b.WriteString("(none)\n")
	}
	b.WriteString("\nUse your own file, shell, and search tools. Your working directory is private to this bot. Do not create a worktree outside it.\n")
	b.WriteString("Scheduled prompts are prefixed with [scheduled]. Direct messages from other bots are prefixed with [DM from Name].\n")
	b.WriteString("\nDaemon actions are not shell commands. When you need one, put a fenced JSON block in the reply. The fence is removed before the user sees it.\n\n")
	b.WriteString("```action\n{\"tool\":\"write_memory\",\"key\":\"note\",\"value\":\"hello\"}\n```\n\n")
	b.WriteString("Allowed tools: write_memory (key, value), delete_memory (key), clear_timer (id), list_bots, read_bot (name). Creating a bot, updating a bot, sending a DM, and setting a timer are done by the user from the page. A bot cannot do those. Do not use the shell to do them either.\n\n")
	return nil
}
