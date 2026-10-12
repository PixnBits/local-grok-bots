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
	bot, err := a.st.GetBot(botID)
	if err != nil {
		a.takePending(runID)
		a.dropResume(botID)
		_, _ = a.st.FinishRun(runID, "error", err.Error())
		a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": err.Error()})
		return
	}
	var ctx context.Context
	var cancel context.CancelFunc
	if a.resolvedBackend(bot) != "" {
		// A CLI turn is capped by the idle kill and by shutdown, not by the
		// shorter Ollama round timeout.
		ctx, cancel = context.WithCancel(a.ctx)
	} else {
		ctx, cancel = context.WithTimeout(a.ctx, runTimeout)
	}
	a.rtMu.Lock()
	if st := a.loops[botID]; st != nil {
		st.cancel = cancel
		st.runID = runID
	}
	a.rtMu.Unlock()
	defer cancel()

	if backend := a.resolvedBackend(bot); backend != "" {
		a.executeCLI(ctx, bot, runID, backend)
		return
	}
	// A continuation already holds the transcript, including tool results.
	// Any other run drops the offer so a timer or DM does not keep it.
	msgs, ok := a.takePending(runID)
	if !ok {
		a.dropResume(botID)
		msgs, err = a.buildMessages(bot)
		if err != nil {
			_, _ = a.st.FinishRun(runID, "error", err.Error())
			a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": err.Error()})
			return
		}
	}
	modelName := a.cfg.Model
	if bot.Model != nil && *bot.Model != "" {
		modelName = *bot.Model
	}

	a.bus.Publish(runID, "status", map[string]any{"state": "working", "text": "working"})
	for round := 0; round < maxToolRounds; round++ {
		if ctx.Err() != nil {
			a.finishInterrupted(bot.ID, runID, ctx)
			return
		}
		a.bus.Publish(runID, "status", map[string]any{"state": "working", "text": "working"})
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
		// This text is on the live stream and in this run's transcript.
		// It is not a thread message: stored announcements teach the next
		// turn to stop after "Let me check" without calling a tool.
		msgs = append(msgs, model.Message{Role: "assistant", Content: resp.Content, ToolCalls: resp.ToolCalls})
		for _, tc := range resp.ToolCalls {
			if ctx.Err() != nil {
				a.finishInterrupted(bot.ID, runID, ctx)
				return
			}
			a.bus.Publish(runID, "status", map[string]any{"state": tc.Name, "text": tc.Name})
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
	a.holdResume(bot.ID, runID, msgs)
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
	b.WriteString("\nYou can call tools. create_bot creates a bot: pass name and description. description is the standing prompt the new bot is given. instructions is an old name for that same field and still works. Do not use the shell to create a bot. update_bot changes a bot. list_bots and read_bot inspect bots. send_dm sends a direct message. write_memory and delete_memory keep notes. set_timer and clear_timer schedule prompts. read_file, write_file, and run_shell stay inside the workspace; paths outside it are rejected. go, gofmt, and other tools installed under /usr are on PATH. Network, git push, and SSH stay off unless the user turned them on in the profile. After tools, send a short reply to the user. Direct messages from other bots appear as user messages prefixed with [DM from Name]. Scheduled prompts are prefixed with [scheduled]. If you need a tool, call it in this response. Do not reply with only an announcement such as \"Let me check.\"\n")
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
		if strings.HasPrefix(m.Content, "Message from ") || strings.HasPrefix(m.Content, "Notice: ") {
			return model.Message{Role: "user", Content: m.Content}
		}
		return model.Message{Role: "user", Content: "[scheduled] " + m.Content}
	default:
		return model.Message{Role: "user", Content: m.Content}
	}
}
