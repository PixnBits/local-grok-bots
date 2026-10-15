package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// toolAuthority tells the model the attached tools are the truth, so its own
// stale claims in history or memory do not hide tools it has.
const toolAuthority = "The tools attached to this request are the current, authoritative set. They override anything said earlier in this conversation or in your memory about which tools exist or how they are called. If you said before that you lack a tool that is attached now, you were wrong; use it."

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
	a.touchActivity(botID)

	bot, err := a.st.GetBot(botID)
	if err != nil {
		a.takePending(runID)
		a.dropResume(botID)
		_, _ = a.st.FinishRun(runID, "error", err.Error())
		a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": err.Error()})
		return
	}
	modelName := a.cfg.Model
	if bot.Model != nil && *bot.Model != "" {
		modelName = *bot.Model
	}
	if a.policy.UsesCLI() {
		a.executeCLI(ctx, bot, runID)
		return
	}
	if !a.policy.AllowsBackend("ollama") {
		a.takePending(runID)
		a.dropResume(bot.ID)
		msg := "ollama backend is not allowed by policy"
		_, _ = a.st.FinishRun(runID, "error", msg)
		a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": msg})
		return
	}
	if err := a.policy.AllowsModel(modelName); err != nil {
		a.takePending(runID)
		a.dropResume(bot.ID)
		_, _ = a.st.FinishRun(runID, "error", err.Error())
		a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": err.Error()})
		return
	}
	// A continuation already holds the transcript, including tool results.
	// Any other run drops the offer so a timer or DM does not keep it.
	run, err := a.st.GetRun(runID)
	if err != nil {
		_, _ = a.st.FinishRun(runID, "error", err.Error())
		a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": err.Error()})
		return
	}
	// seen holds turn input already in the transcript, so a message that
	// lands between CreateRun and buildMessages is not folded in twice.
	seen := map[string]bool{}
	msgs, ok := a.takePending(runID)
	if !ok {
		a.dropResume(botID)
		a.noteToolChanges(bot)
		var hist []store.Message
		msgs, hist, err = a.buildMessagesHist(bot)
		if err != nil {
			_, _ = a.st.FinishRun(runID, "error", err.Error())
			a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": err.Error()})
			return
		}
		for _, m := range hist {
			seen[m.ID] = true
		}
	}
	through := run.StartedAt

	a.bus.Publish(runID, "status", map[string]any{"state": "working", "text": "working"})
	parseRetried := false
	for round := 0; round < maxToolRounds; round++ {
		if ctx.Err() != nil {
			a.finishInterrupted(bot.ID, runID, ctx)
			return
		}
		a.bus.Publish(runID, "status", map[string]any{"state": "working", "text": "working"})
		msgs, through = a.foldInput(bot.ID, runID, msgs, through, seen)
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
			var parseErr *model.ToolCallParseError
			// One more call, and only when a round remains. The failed call still counts toward the cap.
			if errors.As(err, &parseErr) && !parseRetried && round+1 < maxToolRounds {
				parseRetried = true
				a.log(bot.ID, "model_call", map[string]any{
					"model": modelName, "ok": false, "error": err.Error(), "retry": true,
				})
				a.bus.Publish(runID, "status", map[string]any{"state": "working", "text": "retrying"})
				msgs = append(msgs, model.Message{
					Role:    "user",
					Content: "The tool call could not be parsed: " + clip(parseErr.Detail, 500) + ". Call the tool again with valid arguments, or reply in text.",
				})
				continue
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
		// Kept with the run's tool records so the page can show it in the
		// expanded tool view, in order with the calls.
		if strings.TrimSpace(resp.Content) != "" {
			_ = a.st.AddRunTool(runID, bot.ID, store.ToolRecord{
				Kind: "text", OK: true, Result: clip(resp.Content, maxReplyBytes),
			})
		}
		for _, tc := range resp.ToolCalls {
			if ctx.Err() != nil {
				a.finishInterrupted(bot.ID, runID, ctx)
				return
			}
			a.bus.Publish(runID, "status", map[string]any{"state": tc.Name, "text": tc.Name})
			redacted := redactValue(tc.Arguments)
			a.bus.Publish(runID, "tool_call", map[string]any{
				"name": tc.Name, "arguments": redacted,
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
			argJSON, _ := json.Marshal(redacted)
			_ = a.st.AddRunTool(runID, bot.ID, store.ToolRecord{
				Name: tc.Name, Arguments: argJSON, OK: terr == nil, Result: clip(body, 4000),
			})
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

// foldInput appends turn input that arrived after through to the live
// transcript, so a message sent mid-run is answered by this run. The run
// then records how far it has read; NeedsRun only queues a new run for
// messages past that point.
func (a *App) foldInput(botID, runID string, msgs []model.Message, through string, seen map[string]bool) ([]model.Message, string) {
	fresh, err := a.st.TurnInputSince(botID, through)
	if err != nil || len(fresh) == 0 {
		return msgs, through
	}
	names, _ := a.st.BotNames()
	n := 0
	for _, m := range fresh {
		if m.CreatedAt > through {
			through = m.CreatedAt
		}
		if seen[m.ID] {
			continue
		}
		seen[m.ID] = true
		msgs = append(msgs, mapHist(m, names))
		n++
	}
	_ = a.st.MarkRunInput(runID, through)
	if n > 0 {
		a.log(botID, "run_input", map[string]any{"run_id": runID, "messages": n})
	}
	return msgs, through
}

func (a *App) buildMessages(bot store.Bot) ([]model.Message, error) {
	out, _, err := a.buildMessagesHist(bot)
	return out, err
}

func (a *App) buildMessagesHist(bot store.Bot) ([]model.Message, []store.Message, error) {
	mem, err := a.st.ListMemory(bot.ID)
	if err != nil {
		return nil, nil, err
	}
	names, err := a.st.BotNames()
	if err != nil {
		return nil, nil, err
	}
	hist, err := a.st.RecentContext(bot.ID, 40)
	if err != nil {
		return nil, nil, err
	}
	var b strings.Builder
	now := time.Now()
	fmt.Fprintf(&b, "Current time: %s (%s).\n\n", now.Format(time.RFC3339), zoneLabel(now))
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
	b.WriteString("\n" + toolAuthority + "\n\nYou can call tools. create_bot creates a bot: pass name and description. description is the standing prompt the new bot is given. instructions is an old name for that same field and still works. Do not use the shell to create a bot. update_bot changes a bot. list_bots and read_bot inspect bots. send_dm sends a direct message. write_memory and delete_memory keep notes. set_timer schedules a prompt back to you: pass prompt plus one of in (one-shot duration such as \"5m\"), at (one-shot RFC 3339 time), or every (repeating interval); list_timers and clear_timer manage them. Each tool's arguments are described in its schema; use those names. read_file, write_file, and run_shell stay inside the workspace; paths outside it are rejected. go, gofmt, and other tools installed under /usr are on PATH. Network, git push, and SSH stay off unless the user turned them on in the profile. After tools, send a short reply to the user. Direct messages from other bots appear as user messages prefixed with [DM from Name]. Scheduled prompts are prefixed with [scheduled]. If you need a tool, call it in this response. Do not reply with only an announcement such as \"Let me check.\"\n")
	out := []model.Message{{Role: "system", Content: b.String()}}
	for _, m := range hist {
		out = append(out, mapHist(m, names))
	}
	return out, hist, nil
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

// zoneLabel names the daemon's zone for the model: the IANA name from TZ
// when set (Go reports time.Local as "Local"), with the abbreviation.
func zoneLabel(now time.Time) string {
	abbr, _ := now.Zone()
	name := now.Location().String()
	if name == "Local" {
		name = strings.TrimPrefix(os.Getenv("TZ"), ":")
	}
	if name == "" || name == abbr {
		return abbr
	}
	return name + ", " + abbr
}
