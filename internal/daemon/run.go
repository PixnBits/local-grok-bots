package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// toolAuthority tells the model the attached tools are the truth, so its own
// stale claims in history or memory do not hide tools it has.
const toolAuthority = "The tools attached to this request are the current, authoritative set. They override anything said earlier in this conversation or in your memory about which tools exist or how they are called. If you said before that you lack a tool that is attached now, you were wrong; use it."

const (
	maxToolRounds = 8
	maxReplyBytes = 64 * 1024
)

func (a *App) execute(botID, runID string) {
	// A CLI turn gets its deadline (cli.turn_timeout) in executeCLI so a
	// timeout is told apart from a cancel. An Ollama run uses
	// ollama.run_timeout.
	var ctx context.Context
	var cancel context.CancelFunc
	if a.policy.UsesCLI() {
		ctx, cancel = context.WithCancel(a.ctx)
	} else {
		ctx, cancel = context.WithTimeout(a.ctx, a.policy.EffectiveOllamaRunTimeout())
	}
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
		_, _ = a.finishRun(runID, "error", err.Error())
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
		_, _ = a.finishRun(runID, "error", msg)
		a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": msg})
		return
	}
	if err := a.policy.AllowsModel(modelName); err != nil {
		a.takePending(runID)
		a.dropResume(bot.ID)
		_, _ = a.finishRun(runID, "error", err.Error())
		a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": err.Error()})
		return
	}
	// A continuation already holds the transcript, including tool results.
	// Any other run drops the offer so a timer or DM does not keep it.
	run, err := a.st.GetRun(runID)
	if err != nil {
		_, _ = a.finishRun(runID, "error", err.Error())
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
			_, _ = a.finishRun(runID, "error", err.Error())
			a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": err.Error()})
			return
		}
		for _, m := range hist {
			seen[m.ID] = true
		}
	}
	through := run.StartedAt

	parseRetried := false
	retriesLeft := a.policy.EffectiveOllamaStallRetries()
	retried := 0
	var lastFirst time.Duration
	for round := 0; round < maxToolRounds; round++ {
		if a.finishOllamaCtx(bot, runID, ctx, msgs, "", retried, lastFirst) {
			return
		}
		a.bus.Publish(runID, "status", map[string]any{"state": "working", "text": "working"})
		var resp model.ChatResponse
		parseContinue := false
		attempt := 0
		// bestPartial is the longest text streamed on this call, across retries.
		bestPartial := ""
		for {
			attempt++
			if attempt == 1 {
				msgs, through = a.foldInput(bot.ID, runID, msgs, through, seen)
			}
			if a.finishOllamaCtx(bot, runID, ctx, msgs, "", retried, lastFirst) {
				return
			}
			mctx, mcancel := a.modelCallContext(ctx, a.policy.EffectiveOllamaModelTimeout())
			var roundText strings.Builder
			callResp, err := a.model.Chat(mctx, model.ChatRequest{
				Model:              modelName,
				Messages:           msgs,
				Tools:              toolDefs(),
				FirstOutputTimeout: a.policy.EffectiveOllamaFirstOutputTimeout(),
				StallTimeout:       a.policy.EffectiveOllamaStallTimeout(),
				KeepAlive:          a.policy.EffectiveOllamaKeepAlive(),
			}, func(tok string) {
				roundText.WriteString(tok)
				a.bus.Publish(runID, "token", map[string]string{"text": tok})
			})
			mcancel()
			resp = callResp
			first := resp.FirstOutput
			var te *model.TimeoutError
			if errors.As(err, &te) && te != nil && te.FirstOutput > 0 {
				first = te.FirstOutput
			}
			if first > 0 {
				lastFirst = first
			}
			partial := roundText.String()
			if strings.TrimSpace(partial) == "" && te != nil {
				partial = te.Partial
			}
			bestPartial = longerPartial(bestPartial, partial)
			if te != nil {
				bestPartial = longerPartial(bestPartial, te.Partial)
			}
			// A dead run context wins over a typed stall: Stop, shutdown,
			// and the run deadline are not retried.
			if a.ctx.Err() != nil || ctx.Err() != nil {
				limit, limitValue := "", ""
				shown := partial
				if a.ctx.Err() == nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
					limit = "run_timeout"
					limitValue = compactDuration(a.policy.EffectiveOllamaRunTimeout())
					shown = bestPartial
				}
				errLogged := err
				if errLogged == nil {
					errLogged = ctx.Err()
				}
				a.logOllamaCall(bot.ID, modelName, false, attempt, false, first, errLogged, 0, limit, limitValue)
				a.finishOllamaCtx(bot, runID, ctx, msgs, shown, retried, first)
				return
			}
			if te != nil && (te.Limit == "first_output_timeout" || te.Limit == "stall_timeout") {
				willRetry := retriesLeft > 0
				a.logOllamaCall(bot.ID, modelName, false, attempt, willRetry, first, te, 0, te.Limit, compactDuration(a.limitDuration(te.Limit)))
				if willRetry {
					retriesLeft--
					retried++
					a.bus.Publish(runID, "status", map[string]any{"state": "working", "text": "retrying"})
					a.bus.Publish(runID, "stream_reset", map[string]any{"run_id": runID, "reason": te.Limit})
					continue
				}
				a.finishOllamaTimeout(bot, runID, msgs, te.Limit, bestPartial, retried, first)
				return
			}
			if te != nil && te.Limit == "model_timeout" {
				a.logOllamaCall(bot.ID, modelName, false, attempt, false, first, te, 0, "model_timeout", compactDuration(a.policy.EffectiveOllamaModelTimeout()))
				a.finishOllamaTimeout(bot, runID, msgs, "model_timeout", bestPartial, retried, first)
				return
			}
			if err != nil {
				var parseErr *model.ToolCallParseError
				// One more call, and only when a round remains. The failed call still counts toward the cap.
				if errors.As(err, &parseErr) && !parseRetried && round+1 < maxToolRounds {
					parseRetried = true
					a.logOllamaCall(bot.ID, modelName, false, attempt, true, first, err, 0, "", "")
					a.bus.Publish(runID, "status", map[string]any{"state": "working", "text": "retrying"})
					msgs = append(msgs, model.Message{
						Role:    "user",
						Content: "The tool call could not be parsed: " + clip(parseErr.Detail, 500) + ". Call the tool again with valid arguments, or reply in text.",
					})
					parseContinue = true
					break
				}
				a.logOllamaCall(bot.ID, modelName, false, attempt, false, first, err, 0, "", "")
				if t := strings.TrimSpace(partial); t != "" {
					a.persistBotText(bot.ID, runID, t, false)
				}
				_, _ = a.finishRun(runID, "error", err.Error())
				a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": err.Error()})
				return
			}
			a.logOllamaCall(bot.ID, modelName, true, attempt, false, first, nil, resp.PromptTokens+resp.OutputTokens, "", "")
			break
		}
		if parseContinue {
			continue
		}
		if len(resp.ToolCalls) == 0 {
			if strings.TrimSpace(resp.Content) != "" {
				a.persistBotText(bot.ID, runID, resp.Content, false)
			}
			_, _ = a.finishRun(runID, "done", "")
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
			if a.finishOllamaCtx(bot, runID, ctx, msgs, "", retried, lastFirst) {
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
	_, _ = a.finishRun(runID, "error", msg)
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
	_, _ = a.finishRun(runID, status, errText)
	if status == "cancelled" {
		a.bus.Publish(runID, "done", map[string]any{"run_id": runID, "status": "cancelled"})
		return
	}
	a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": errText})
}

// finishRun stores a run's end state. A run that did not finish "done"
// first gets a "Notice: " thread message tied to the run, so the thread keeps
// the error and the run's tool and permission records (shown with the first
// message of the run) after a failure, the same as after a reply. Notices are
// not turn input, so they do not start another run.
func (a *App) finishRun(runID, status, errText string) (bool, error) {
	if status != "done" {
		if run, err := a.st.GetRun(runID); err == nil && run.Status == "running" {
			a.persistRunNotice(run.BotID, runID, status, errText)
		}
	}
	return a.st.FinishRun(runID, status, errText)
}

func runNoticeText(status, errText string) string {
	errText = strings.TrimSpace(audit.RedactText(errText))
	switch {
	case status == "cancelled":
		return "Notice: Run cancelled."
	case status == "timeout":
		if errText == "" {
			return "Notice: Run timed out."
		}
		return "Notice: " + errText
	case status == "stopped" && errText == "stopped after denial":
		return "Notice: Stopped after denial."
	case errText == "interrupted":
		return "Notice: Run interrupted before it finished."
	case errText == "turn_timeout" || errText == "timed out":
		return "Notice: Run timed out (" + errText + "). Partial output and tool results are kept above."
	case errText == "":
		return "Notice: Run failed."
	default:
		return "Notice: Run failed: " + clip(errText, 2000)
	}
}

func (a *App) persistRunNotice(botID, runID, status, errText string) {
	m, err := a.st.AddMessage(store.Message{
		BotID: botID, Thread: "user", Role: "system", Content: runNoticeText(status, errText), RunID: &runID,
	})
	if err != nil {
		return
	}
	a.log(botID, "run_notice", map[string]any{"message_id": m.ID, "run_id": runID, "status": status})
}

func (a *App) persistBotText(botID, runID, content string, timedOut bool) {
	content = clip(content, maxReplyBytes)
	m, err := a.st.AddMessage(store.Message{
		BotID: botID, Thread: "user", Role: "bot", Content: content, RunID: &runID, TimedOut: timedOut,
	})
	if err != nil {
		return
	}
	a.log(botID, "bot_message", map[string]any{"message_id": m.ID, "run_id": runID})
}

// finishOllamaCtx ends the run when the daemon is shutting down, the user
// stopped it, or the run deadline fired. A stall is not this path. False
// means the run context is still alive.
func (a *App) finishOllamaCtx(bot store.Bot, runID string, ctx context.Context, msgs []model.Message, partial string, retried int, first time.Duration) bool {
	if a.ctx.Err() == nil && ctx.Err() == nil {
		return false
	}
	if a.ctx.Err() != nil {
		if t := strings.TrimSpace(partial); t != "" {
			a.persistBotText(bot.ID, runID, t, false)
		}
		a.finishInterrupted(bot.ID, runID, a.ctx)
		return true
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		a.finishOllamaTimeout(bot, runID, msgs, "run_timeout", partial, retried, first)
		return true
	}
	if t := strings.TrimSpace(partial); t != "" {
		a.persistBotText(bot.ID, runID, t, false)
	}
	a.finishInterrupted(bot.ID, runID, ctx)
	return true
}

// finishOllamaTimeout keeps the longest partial reply and ends the run as
// timeout. Continue is offered only when some text was kept. errText on the
// run is the notice without "Notice: ".
func (a *App) finishOllamaTimeout(bot store.Bot, runID string, msgs []model.Message, limit, partial string, retried int, first time.Duration) {
	dur := a.limitDuration(limit)
	kept := ""
	if t := strings.TrimSpace(partial); t != "" {
		kept = clip(t, maxReplyBytes)
		a.persistBotText(bot.ID, runID, kept, true)
		resume := append([]model.Message{}, msgs...)
		resume = append(resume, model.Message{Role: "assistant", Content: kept})
		resume = append(resume, model.Message{Role: "user", Content: "Continue from where you stopped."})
		a.holdResume(bot.ID, runID, resume)
	}
	body := timeoutBody(limit, dur, retried, kept)
	_, _ = a.finishRun(runID, "timeout", body)
	a.bus.Publish(runID, "timeout", map[string]any{"run_id": runID, "error": body, "limit": limit})
	a.log(bot.ID, "run_timed_out", map[string]any{
		"run_id":          runID,
		"limit":           limit,
		"limit_value":     compactDuration(dur),
		"first_output_ms": first.Milliseconds(),
		"retried":         retried > 0,
		"partial_bytes":   len(kept),
	})
}

// longerPartial keeps the longest trimmed text seen on this call.
func longerPartial(best, next string) string {
	next = strings.TrimSpace(next)
	if next == "" || len(next) <= len(best) {
		return best
	}
	return next
}

// modelCallContext is the per-call hard cap. An Ollama client with a test
// clock applies that clock to the cap as well as to the stall watchdog.
func (a *App) modelCallContext(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if ol, ok := a.model.(*model.Ollama); ok && ol != nil {
		return ol.TimeoutContext(parent, d)
	}
	if d <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, d)
}

func (a *App) limitDuration(limit string) time.Duration {
	switch limit {
	case "first_output_timeout":
		return a.policy.EffectiveOllamaFirstOutputTimeout()
	case "stall_timeout":
		return a.policy.EffectiveOllamaStallTimeout()
	case "model_timeout":
		return a.policy.EffectiveOllamaModelTimeout()
	default:
		return a.policy.EffectiveOllamaRunTimeout()
	}
}

func (a *App) logOllamaCall(botID, modelName string, ok bool, attempt int, retry bool, first time.Duration, err error, tokens int, limit, limitValue string) {
	detail := map[string]any{
		"model":           modelName,
		"ok":              ok,
		"attempt":         attempt,
		"retry":           retry,
		"first_output_ms": first.Milliseconds(),
	}
	if err != nil {
		detail["error"] = err.Error()
	}
	if ok {
		detail["tokens"] = tokens
	}
	if limit != "" {
		detail["limit"] = limit
		detail["limit_value"] = limitValue
	}
	a.log(botID, "model_call", detail)
}

// timeoutBody is the run error text. The thread notice prefixes "Notice: ".
func timeoutBody(limit string, d time.Duration, retried int, partial string) string {
	shown := compactDuration(d)
	var b strings.Builder
	switch limit {
	case "stall_timeout":
		fmt.Fprintf(&b, "No output from the model for %s (stall_timeout).", shown)
	case "first_output_timeout":
		fmt.Fprintf(&b, "The model sent no output within %s (first_output_timeout).", shown)
	case "model_timeout":
		fmt.Fprintf(&b, "The model call hit its %s limit (model_timeout).", shown)
	case "run_timeout":
		fmt.Fprintf(&b, "The run hit its %s limit (run_timeout).", shown)
	default:
		fmt.Fprintf(&b, "The run hit its %s limit (%s).", shown, limit)
	}
	switch {
	case retried == 1:
		b.WriteString(" Retried once.")
	case retried > 1:
		fmt.Fprintf(&b, " Retried %d times.", retried)
	}
	if strings.TrimSpace(partial) != "" {
		b.WriteString(" The partial reply is kept above.")
	}
	return b.String()
}

// compactDuration drops zero units: 2m, 1h30m, 45s. Under a second it keeps
// milliseconds so a short test limit stays exact.
func compactDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	if d == 0 {
		return "0s"
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	d = d.Truncate(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	var b strings.Builder
	if h > 0 {
		fmt.Fprintf(&b, "%dh", h)
	}
	if m > 0 {
		fmt.Fprintf(&b, "%dm", m)
	}
	if s > 0 {
		fmt.Fprintf(&b, "%ds", s)
	}
	if b.Len() == 0 {
		return "0s"
	}
	return b.String()
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
	b.WriteString("\n" + toolAuthority + "\n\nYou can call tools. create_bot creates a bot: pass name and description. description is the standing prompt the new bot is given. instructions is an old name for that same field and still works. Do not use the shell to create a bot. update_bot changes a bot. list_bots and read_bot inspect bots. send_dm sends a direct message. write_memory and delete_memory keep notes. set_timer schedules a prompt back to you: pass prompt plus one of in (one-shot duration such as \"5m\"), at (one-shot RFC 3339 time), or every (repeating interval); list_timers and clear_timer manage them. Each tool's arguments are described in its schema; use those names. read_file, write_file, edit_file, and delete_file stay inside the workspace; paths outside it are rejected and symlinks are refused. run_shell stays inside the workspace. go, gofmt, and other tools installed under /usr are on PATH. Tests stay offline unless net is granted. The build grant does not add a network exception. GitHub remotes are HTTPS to allowlisted repositories. git push waits for an approval card and the daemon sends it; the jail does not send the push. create_pr waits for an approval card. pr_status reads one allowlisted pull request. SSH stays off unless the user turned it on in the profile. After tools, send a short reply to the user. Direct messages from other bots appear as user messages prefixed with [DM from Name]. Scheduled prompts are prefixed with [scheduled]. If you need a tool, call it in this response. Do not reply with only an announcement such as \"Let me check.\"\n")
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
