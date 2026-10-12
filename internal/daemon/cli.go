package daemon

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/id"
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
	a.takePending(runID)
	a.dropResume(bot.ID)

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
	ws := a.ws
	if abs, absErr := filepath.Abs(ws); absErr == nil {
		ws = abs
	}
	a.bus.Publish(runID, "status", map[string]any{"state": "working", "text": "working"})
	runner := a.runner
	if runner == nil {
		runner = clisession.ExecRunner{}
	}
	spec := clisession.Spec{
		Backend: backend, SessionID: sessionID, Fresh: fresh,
		Prompt: prompt, Workspace: ws,
	}
	if bot.Model != nil {
		spec.Model = strings.TrimSpace(*bot.Model)
	}
	res, err := runner.Run(ctx, spec, nil)
	if err != nil {
		if ctx.Err() != nil {
			a.finishInterrupted(bot.ID, runID, ctx)
			return
		}
		// A fresh id was stored before the process started. Drop it when the
		// CLI never confirmed a session, so the next turn can create one.
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
	a.log(bot.ID, "model_call", map[string]any{
		"model": backend, "ok": true, "session_id": sessionID,
	})
	if strings.TrimSpace(res.Text) != "" {
		a.persistBotText(bot.ID, runID, res.Text)
	}
	_, _ = a.st.FinishRun(runID, "done", "")
	a.bus.Publish(runID, "done", map[string]any{"run_id": runID})
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
	b.WriteString("\nUse your own file, shell, and search tools. The workspace is shared by every bot. Do not create a private worktree.\n")
	b.WriteString("Scheduled prompts are prefixed with [scheduled]. Direct messages from other bots are prefixed with [DM from Name].\n\n")
	return nil
}
