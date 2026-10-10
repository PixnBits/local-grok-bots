package daemon

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

const (
	maxToolRounds = 8
	modelTimeout  = 3 * time.Minute
	runTimeout    = 10 * time.Minute
	maxReplyBytes = 64 * 1024
)

func (a *App) execute(botID, runID string) {
	ctx, cancel := context.WithTimeout(a.ctx, runTimeout)
	a.rtMu.Lock()
	if st := a.loops[botID]; st != nil {
		st.cancel = cancel
		st.runID = runID
	}
	a.rtMu.Unlock()
	defer cancel()

	bot, err := a.st.GetBot(botID)
	if err != nil {
		_, _ = a.st.FinishRun(runID, "error", err.Error())
		a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": err.Error()})
		return
	}
	msgs, err := a.buildMessages(bot)
	if err != nil {
		_, _ = a.st.FinishRun(runID, "error", err.Error())
		a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": err.Error()})
		return
	}
	modelName := a.cfg.Model
	if bot.Model != nil && *bot.Model != "" {
		modelName = *bot.Model
	}

	for round := 0; round < maxToolRounds; round++ {
		if ctx.Err() != nil {
			a.finishInterrupted(bot.ID, runID, ctx)
			return
		}
		mctx, mcancel := context.WithTimeout(ctx, modelTimeout)
		resp, err := a.model.Chat(mctx, model.ChatRequest{
			Model:    modelName,
			Messages: msgs,
			Tools:    toolDefs(),
		}, func(tok string) {
			a.bus.Publish(runID, "token", map[string]string{"text": tok})
		})
		mcancel()
		if err != nil {
			if ctx.Err() != nil {
				a.finishInterrupted(bot.ID, runID, ctx)
				return
			}
			a.log(bot.ID, "model_call", map[string]any{"model": modelName, "ok": false, "error": err.Error()})
			_, _ = a.st.FinishRun(runID, "error", err.Error())
			a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": err.Error()})
			return
		}
		a.log(bot.ID, "model_call", map[string]any{
			"model": modelName, "ok": true, "tokens": resp.PromptTokens + resp.OutputTokens,
		})
		if len(resp.ToolCalls) == 0 {
			if strings.TrimSpace(resp.Content) != "" {
				a.persistBotText(bot.ID, runID, resp.Content)
			}
			_, _ = a.st.FinishRun(runID, "done", "")
			a.bus.Publish(runID, "done", map[string]any{"run_id": runID})
			return
		}
		if strings.TrimSpace(resp.Content) != "" {
			a.persistBotText(bot.ID, runID, resp.Content)
		}
		msgs = append(msgs, model.Message{Role: "assistant", Content: resp.Content, ToolCalls: resp.ToolCalls})
		for _, tc := range resp.ToolCalls {
			if ctx.Err() != nil {
				a.finishInterrupted(bot.ID, runID, ctx)
				return
			}
			a.bus.Publish(runID, "tool_call", map[string]any{
				"name": tc.Name, "arguments": redactValue(tc.Arguments),
			})
			result, terr := a.execTool(ctx, bot, tc.Name, tc.Arguments)
			payload := map[string]any{"name": tc.Name, "ok": terr == nil}
			body := result
			if terr != nil {
				body = terr.Error()
				payload["ok"] = false
			}
			payload["result_or_error"] = clip(body, 4000)
			msgs = append(msgs, model.Message{Role: "tool", ToolName: tc.Name, Content: body})
			a.bus.Publish(runID, "tool_result", payload)
		}
	}
	msg := "tool round limit"
	_, _ = a.st.FinishRun(runID, "error", msg)
	a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": msg})
}

func (a *App) finishInterrupted(botID, runID string, ctx context.Context) {
	status := "cancelled"
	errText := ""
	if a.ctx.Err() != nil {
		status = "error"
		errText = "shutdown"
	} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		status = "error"
		errText = "timed out"
	}
	_, _ = a.st.FinishRun(runID, status, errText)
	if status == "cancelled" {
		a.bus.Publish(runID, "done", map[string]any{"run_id": runID, "status": "cancelled"})
		return
	}
	a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": errText})
}

func (a *App) persistBotText(botID, runID, content string) {
	content = clip(content, maxReplyBytes)
	m, err := a.st.AddMessage(store.Message{
		BotID: botID, Thread: "user", Role: "bot", Content: content, RunID: &runID,
	})
	if err != nil {
		return
	}
	a.log(botID, "bot_message", map[string]any{"message_id": m.ID, "run_id": runID})
}

func (a *App) buildMessages(bot store.Bot) ([]model.Message, error) {
	mem, err := a.st.ListMemory(bot.ID)
	if err != nil {
		return nil, err
	}
	names, err := a.st.BotNames()
	if err != nil {
		return nil, err
	}
	hist, err := a.st.RecentContext(bot.ID, 40)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("You are ")
	b.WriteString(bot.Name)
	b.WriteString(", a bot running on a local daemon.\n\nInstructions:\n")
	if strings.TrimSpace(bot.Instructions) == "" {
		b.WriteString("(none)\n")
	} else {
		b.WriteString(bot.Instructions)
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
	b.WriteString("\nTools let you list and update bots, send a direct message, keep memory, set timers, and use files and shell inside the workspace only. Paths outside the workspace are rejected. After tools, send a short reply to the user. Direct messages from other bots appear as user messages prefixed with [DM from Name]. Scheduled prompts are prefixed with [scheduled].\n")
	out := []model.Message{{Role: "system", Content: b.String()}}
	for _, m := range hist {
		out = append(out, mapHist(m, names))
	}
	return out, nil
}

func mapHist(m store.Message, names map[string]string) model.Message {
	if strings.HasPrefix(m.Thread, "dm:") {
		other := strings.TrimPrefix(m.Thread, "dm:")
		name := names[other]
		if name == "" {
			name = other
		}
		if m.Role == "bot" {
			return model.Message{Role: "assistant", Content: "[DM to " + name + "] " + m.Content}
		}
		return model.Message{Role: "user", Content: "[DM from " + name + "] " + m.Content}
	}
	switch m.Role {
	case "bot":
		return model.Message{Role: "assistant", Content: m.Content}
	case "system":
		return model.Message{Role: "user", Content: "[scheduled] " + m.Content}
	default:
		return model.Message{Role: "user", Content: m.Content}
	}
}
