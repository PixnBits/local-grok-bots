package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/github"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// prop is one JSON Schema property with a description the model reads.
func prop(typ, desc string) map[string]any {
	return map[string]any{"type": typ, "description": desc}
}

// serverToolsProp is the create_bot and update_bot argument for the
// per-bot allow list. Leaving it out inherits on create and leaves the
// stored list unchanged on update.
func serverToolsProp(desc string) map[string]any {
	return map[string]any{
		"type":        "array",
		"description": desc,
		"items":       map[string]any{"type": "string", "description": "One non-function model tool type. Example: \"web_search\"."},
	}
}

// schemaObj is a JSON Schema object. additionalProperties stays open so
// documented aliases keep working.
func schemaObj(props map[string]any, req ...string) map[string]any {
	if req == nil {
		req = []string{}
	}
	return map[string]any{"type": "object", "properties": props, "required": req}
}

// toolDefs is the full tool list sent to Ollama on every model call: name,
// description, and a JSON Schema with a description (and example) for every
// argument. The model is not asked to discover signatures; it gets them here.
func toolDefs() []model.Tool {
	name := func(what string) map[string]any { return prop("string", what+" Example: \"Ada\".") }
	// File and shell tools come first. qwen3.8's default thinking only
	// reliably notices tools near the end of this list. The bot tools
	// stay last so create_bot is among the ones it uses. When they sit
	// earlier, the model treats them as missing and keeps thinking past
	// the three-minute model limit (about 8 tokens/s on this machine).
	return []model.Tool{
		{Name: "write_memory", Description: "Save or replace a memory note on yourself. Notes appear in your system prompt on later turns.",
			Parameters: schemaObj(map[string]any{
				"key":   prop("string", "Short note name without slashes. Example: \"favorite_color\"."),
				"value": prop("string", "Note text. Example: \"blue\"."),
			}, "key", "value")},
		{Name: "delete_memory", Description: "Delete one of your memory notes by key.",
			Parameters: schemaObj(map[string]any{"key": prop("string", "The note's key. Example: \"favorite_color\".")}, "key")},
		{Name: "set_timer", Description: "Schedule a prompt that is sent back to you later, for reminders and routines. " +
			"Give prompt plus exactly one of: in (fire once after a duration), at (fire once at a time), or every (repeat). " +
			"When it fires, the prompt arrives in this thread as a [scheduled] message and you reply to the user then. " +
			"Example for \"remind me in 5 minutes to walk the dog\": {\"prompt\": \"Remind the user to walk the dog.\", \"in\": \"5m\"}.",
			Parameters: schemaObj(map[string]any{
				"prompt": prop("string", "What to do when it fires, written as an instruction to yourself. Example: \"Remind the user to walk the dog.\""),
				"in":     prop("string", "One-shot delay as a duration: number plus s, m, h, or d. Examples: \"90s\", \"5m\", \"2h\", \"1d\"."),
				"at":     prop("string", "One-shot absolute time in RFC 3339 with a UTC offset. Example: \"2026-10-14T17:30:00-07:00\". The current time and zone are in your system prompt."),
				"every":  prop("string", "Repeat interval for a recurring routine: number plus s, m, h, or d. Example: \"1d\". The first run is one interval from now."),
				"name":   prop("string", "Optional label shown to the user. Example: \"walk the dog\"."),
			}, "prompt")},
		{Name: "list_timers", Description: "List your timers with id, name, schedule (an interval or \"once\"), prompt, enabled, and next_fire_at (UTC).",
			Parameters: schemaObj(map[string]any{})},
		{Name: "clear_timer", Description: "Delete one of your timers. Get the id from list_timers or from set_timer's result.",
			Parameters: schemaObj(map[string]any{"id": prop("string", "Timer id (a UUID). Example: \"b2af098c-57fc-4aa0-ba5d-bec6613f7a57\".")}, "id")},
		{Name: "read_file", Description: "Read a UTF-8 text file inside the workspace. Symlinks are refused and not followed.",
			Parameters: schemaObj(map[string]any{"path": prop("string", "Path relative to the workspace. Example: \"notes/todo.md\".")}, "path")},
		{Name: "write_file", Description: "Write a UTF-8 text file inside the workspace, replacing it if it exists. Creates parent directories. Symlinks are refused and not followed.",
			Parameters: schemaObj(map[string]any{
				"path":    prop("string", "Path relative to the workspace. Example: \"notes/todo.md\"."),
				"content": prop("string", "Full file contents."),
			}, "path", "content")},
		{Name: "edit_file", Description: "Replace an exact string in an existing workspace file. Refuses zero matches and a match count other than expected_count. Omit expected_count to require exactly one match. Symlinks are refused.",
			Parameters: schemaObj(map[string]any{
				"path":           prop("string", "Path relative to the workspace. Example: \"notes/todo.md\"."),
				"old_string":     prop("string", "Exact text to replace. Example: \"TODO\"."),
				"new_string":     prop("string", "Replacement text. An empty string deletes the match."),
				"expected_count": prop("integer", "How many times old_string must occur. Omit it to require one match. Example: 2."),
			}, "path", "old_string")},
		{Name: "delete_file", Description: "Delete one regular file inside the workspace. Directories and symlinks are refused.",
			Parameters: schemaObj(map[string]any{"path": prop("string", "Path relative to the workspace. Example: \"notes/old.md\".")}, "path")},
		{Name: "run_shell", Description: "Run a shell command inside the workspace jail and return its output. Paths outside the workspace are rejected. Network and SSH fail unless the user granted them. git push is an approval: the jail does not send it, and the daemon sends it only after the approval card.",
			Parameters: schemaObj(map[string]any{"command": prop("string", "A bash command line. Example: \"ls -la && go version\".")}, "command")},
		{Name: "create_pr", Description: "Open a pull request on an allowlisted GitHub repository. The daemon asks for approval on a card and sends it from the host. draft defaults to true. head cannot be the repository default branch.",
			Parameters: schemaObj(map[string]any{
				"repo":  prop("string", "Repository as owner/repo. Example: \"acme/widgets\"."),
				"head":  prop("string", "Branch that contains the changes. Example: \"feature\"."),
				"base":  prop("string", "Branch the pull request merges into. Example: \"main\"."),
				"title": prop("string", "Pull request title. Example: \"Add a widget\"."),
				"body":  prop("string", "Pull request text. Example: \"Fixes the empty state.\""),
				"draft": prop("boolean", "Open as a draft. Omit to default to true. Example: true."),
			}, "repo", "head", "base", "title")},
		{Name: "pr_status", Description: "Read one pull request on an allowlisted GitHub repository. Returns the url, state, draft flag, head branch, and base branch. It does not change the pull request and does not ask for approval.",
			Parameters: schemaObj(map[string]any{
				"repo":   prop("string", "Repository as owner/repo. Example: \"acme/widgets\"."),
				"number": prop("integer", "Pull request number. Example: 7."),
			}, "repo", "number")},
		{Name: "list_bots", Description: "List all bots with id, name, label, and status.",
			Parameters: schemaObj(map[string]any{})},
		{Name: "read_bot", Description: "Read one bot's description and memory.",
			Parameters: schemaObj(map[string]any{"name": name("The bot's name or id.")}, "name")},
		{Name: "send_dm", Description: "Send a direct message to another bot. Returns immediately; the recipient answers in its own turn.",
			Parameters: schemaObj(map[string]any{
				"to":      name("Recipient bot name or id."),
				"content": prop("string", "Message text."),
			}, "to", "content")},
		{Name: "create_bot", Description: "Create a new bot. description is the standing prompt the new bot is given. instructions is an accepted alias for description. server_tools omitted or null inherits policy; an empty array allows none.",
			Parameters: schemaObj(map[string]any{
				"name":         name("Unique bot name (case-insensitive)."),
				"description":  prop("string", "Standing prompt for the new bot. Example: \"You summarize the news each morning.\""),
				"label":        prop("string", "Optional short role line. Example: \"news digest\"."),
				"instructions": prop("string", "Alias for description."),
				"model":        prop("string", "Optional Ollama model name; omit to use the default."),
				"server_tools": serverToolsProp("Non-function model tool types this bot may keep. Omit or null inherits policy. An empty array allows none. Example: [\"web_search\"]."),
			}, "name", "description")},
		{Name: "update_bot", Description: "Change another bot's name, label, description, model, or server_tools. Identify it by id or name; renaming requires id. instructions is an accepted alias for description. server_tools omitted leaves the field unchanged; null inherits policy; an empty array allows none.",
			Parameters: schemaObj(map[string]any{
				"id":           prop("string", "Target bot id. Required to rename."),
				"name":         name("Target bot name, or the new name when id is given."),
				"label":        prop("string", "New label."),
				"description":  prop("string", "New standing prompt."),
				"instructions": prop("string", "Alias for description."),
				"model":        prop("string", "New Ollama model name; empty string resets to the default."),
				"server_tools": serverToolsProp("Non-function model tool types this bot may keep. Omit to leave unchanged. Null inherits policy. An empty array allows none. Example: [\"web_search\"]."),
			})},
	}
}

// toolUsage renders a tool's arguments compactly for error messages, so a
// wrong call learns the expected shape in one round.
func toolUsage(name string) string {
	for _, t := range toolDefs() {
		if t.Name != name {
			continue
		}
		props, _ := t.Parameters["properties"].(map[string]any)
		req := map[string]bool{}
		for _, r := range t.Parameters["required"].([]string) {
			req[r] = true
		}
		keys := make([]string, 0, len(props))
		for k := range props {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if req[keys[i]] != req[keys[j]] {
				return req[keys[i]]
			}
			return keys[i] < keys[j]
		})
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			p := props[k].(map[string]any)
			opt := "?"
			if req[k] {
				opt = ""
			}
			parts = append(parts, fmt.Sprintf("%s%s: %s — %s", k, opt, p["type"], p["description"]))
		}
		return name + " arguments: {" + strings.Join(parts, "; ") + "}"
	}
	return ""
}

// argError is a bad-arguments error; execTool appends the tool's usage.
type argError struct{ msg string }

func (e argError) Error() string { return e.msg }

func badArgs(format string, a ...any) error { return argError{fmt.Sprintf(format, a...)} }

// checkRequired rejects a call missing a required argument before dispatch.
func checkRequired(name string, args map[string]any) error {
	for _, t := range toolDefs() {
		if t.Name != name {
			continue
		}
		var missing []string
		for _, r := range t.Parameters["required"].([]string) {
			if strings.TrimSpace(strArg(args, r)) == "" && !hasAlias(name, r, args) {
				missing = append(missing, r)
			}
		}
		if len(missing) > 0 {
			return badArgs("missing required argument(s): %s", strings.Join(missing, ", "))
		}
		return nil
	}
	return fmt.Errorf("unknown tool %q", name)
}

// hasAlias reports whether a documented alias stands in for a required field.
func hasAlias(tool, field string, args map[string]any) bool {
	var alts []string
	switch {
	case tool == "create_bot" && field == "description":
		alts = []string{"instructions"}
	case tool == "set_timer" && field == "prompt":
		alts = []string{"message", "text", "reminder"}
	case tool == "read_bot" && field == "name":
		alts = []string{"id"}
	}
	for _, k := range alts {
		if strings.TrimSpace(strArg(args, k)) != "" {
			return true
		}
	}
	return false
}

func (a *App) execTool(ctx context.Context, bot store.Bot, name string, args map[string]any) (string, error) {
	if args == nil {
		args = map[string]any{}
	}
	a.log(bot.ID, "tool_start", map[string]any{"name": name, "arguments": redactValue(args)})
	err := checkRequired(name, args)
	var result string
	if err == nil {
		result, err = a.dispatchTool(ctx, bot, name, args)
	}
	var ae argError
	if errors.As(err, &ae) {
		err = fmt.Errorf("%s. Expected %s", ae.msg, toolUsage(name))
	}
	detail := map[string]any{"name": name, "ok": err == nil}
	if err != nil {
		detail["error"] = clip(err.Error(), 500)
	}
	a.log(bot.ID, "tool_end", detail)
	return result, err
}

func (a *App) dispatchTool(ctx context.Context, bot store.Bot, name string, args map[string]any) (string, error) {
	turnPol := a.effPol(bot.ID)

	switch name {
	case "list_bots":
		bots, err := a.st.ListBots()
		if err != nil {
			return "", err
		}
		type row struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Label  string `json:"label"`
			Status string `json:"status"`
		}
		out := make([]row, 0, len(bots))
		for _, b := range bots {
			out = append(out, row{ID: b.ID, Name: b.Name, Label: b.Label, Status: b.Status})
		}
		return mustJSON(out), nil
	case "read_bot":
		who := strArg(args, "name")
		if who == "" {
			who = strArg(args, "id")
		}
		if who == "" {
			return "", errors.New("name or id required")
		}
		other, err := a.st.FindBot(who)
		if err != nil {
			return "", err
		}
		mem, err := a.st.ListMemory(other.ID)
		if err != nil {
			return "", err
		}
		return mustJSON(map[string]any{
			"id": other.ID, "name": other.Name, "label": other.Label, "status": other.Status,
			"description": other.Description, "model": other.Model, "memory": mem,
		}), nil
	case "send_dm":
		to := strArg(args, "to")
		content := strArg(args, "content")
		if to == "" || strings.TrimSpace(content) == "" {
			return "", errors.New("to and content required")
		}
		other, err := a.st.FindBot(to)
		if err != nil {
			return "", err
		}
		if other.ID == bot.ID {
			return "", errors.New("cannot DM yourself")
		}
		if err := a.allowBotTurn(bot.ID, other.ID, "send_dm"); err != nil {
			return "", err
		}
		if _, _, err := a.st.AddDMPair(bot.ID, other.ID, content, ""); err != nil {
			return "", err
		}
		a.kick(other.ID)
		return mustJSON(map[string]any{"to": other.ID, "name": other.Name, "ok": true}), nil
	case "create_bot":
		name, err := cleanName(strArg(args, "name"))
		if err != nil {
			return "", err
		}
		description := strArg(args, "description")
		if _, ok := args["description"]; !ok {
			description = strArg(args, "instructions")
		}
		var modelPtr *string
		if m := strings.TrimSpace(strArg(args, "model")); m != "" {
			modelPtr = &m
		}
		var tools *[]string
		if v, ok := args["server_tools"]; ok {
			tools, err = serverToolsArg(v)
			if err != nil {
				return "", err
			}
		}
		created, err := a.st.InsertBot(store.BotDraft{
			Name: name, Label: strArg(args, "label"), Description: description, Model: modelPtr, ServerTools: tools,
		}, bot.ID)
		if err != nil {
			return "", err
		}
		a.notePermCallback()
		return mustJSON(map[string]any{"id": created.ID, "name": created.Name}), nil
	case "update_bot":
		who := strArg(args, "id")
		if who == "" {
			who = strArg(args, "name")
		}
		if who == "" {
			return "", errors.New("id or name required")
		}
		target, err := a.st.FindBot(who)
		if err != nil {
			return "", err
		}
		patch := store.BotPatch{By: bot.ID}
		if id := strArg(args, "id"); id != "" {
			if n := strArg(args, "name"); n != "" && !strings.EqualFold(n, target.Name) {
				cn, err := cleanName(n)
				if err != nil {
					return "", err
				}
				patch.Name = &cn
			}
		}
		if _, ok := args["label"]; ok {
			label := strArg(args, "label")
			patch.Label = &label
		}
		if _, ok := args["description"]; ok {
			desc := strArg(args, "description")
			patch.Description = &desc
		} else if _, ok := args["instructions"]; ok {
			desc := strArg(args, "instructions")
			patch.Description = &desc
		}
		if _, ok := args["model"]; ok {
			m := strings.TrimSpace(strArg(args, "model"))
			patch.ModelSet = true
			if m != "" {
				patch.Model = &m
			}
		}
		if v, ok := args["server_tools"]; ok {
			tools, err := serverToolsArg(v)
			if err != nil {
				return "", err
			}
			patch.ServerToolsSet = true
			patch.ServerTools = tools
		}
		updated, err := a.st.UpdateBot(target.ID, patch)
		if err != nil {
			return "", err
		}
		return mustJSON(map[string]any{"id": updated.ID, "name": updated.Name}), nil
	case "write_memory":
		key := strArg(args, "key")
		if strings.TrimSpace(key) == "" || strings.Contains(key, "/") {
			return "", errors.New("invalid memory key")
		}
		val := strArg(args, "value")
		if memoryClaimsTools(key, val) {
			return "", errors.New("do not store notes about which tools you have or lack; tools are attached fresh on every call and override earlier claims. Use the attached list, not memory.")
		}
		m, err := a.st.UpsertMemory(bot.ID, key, val)
		if err != nil {
			return "", err
		}
		return mustJSON(m), nil
	case "delete_memory":
		key := strArg(args, "key")
		if key == "" {
			return "", errors.New("key required")
		}
		if err := a.st.DeleteMemory(bot.ID, key); err != nil {
			return "", err
		}
		return `{"ok":true}`, nil
	case "set_timer":
		return a.setTimer(bot, args)
	case "list_timers":
		ts, err := a.st.ListTimers(bot.ID)
		if err != nil {
			return "", err
		}
		return mustJSON(ts), nil
	case "clear_timer":
		id := strArg(args, "id")
		if id == "" {
			return "", errors.New("id required")
		}
		t, err := a.st.GetTimer(id)
		if err != nil {
			return "", err
		}
		if t.BotID != bot.ID {
			return "", errors.New("timer belongs to another bot")
		}
		if err := a.st.DeleteTimer(id); err != nil {
			return "", err
		}
		return `{"ok":true}`, nil
	case "read_file":
		return a.toolReadFile(args)
	case "write_file":
		return a.toolWriteFile(bot.ID, args)
	case "edit_file":
		return a.toolEditFile(bot.ID, args)
	case "delete_file":
		return a.toolDeleteFile(bot.ID, args)
	case "create_pr":
		return a.toolCreatePR(ctx, bot, args)
	case "pr_status":
		return a.toolPRStatus(ctx, bot, args)
	case "run_shell":
		command := strArg(args, "command")
		current := bot
		if fresh, err := a.st.GetBot(bot.ID); err == nil {
			current = fresh
		}
		shellCtx, shellCancel := context.WithCancel(ctx)
		defer shellCancel()
		var timerMu sync.Mutex
		var shellTimer *time.Timer
		armShell := func(d time.Duration) {
			timerMu.Lock()
			defer timerMu.Unlock()
			if shellTimer != nil {
				shellTimer.Stop()
			}
			shellTimer = time.AfterFunc(d, shellCancel)
		}
		armShell(30 * time.Second)
		defer func() {
			timerMu.Lock()
			if shellTimer != nil {
				shellTimer.Stop()
			}
			timerMu.Unlock()
		}()
		ghSock, ghRepos := "", []string(nil)
		author, email, aerr := github.CommitAuthor(current.Name, turnPol.GitHub.AuthorName, turnPol.GitHub.AuthorEmail)
		if aerr != nil {
			author, email = "", ""
		}
		var px *github.Proxy
		if granted(current.Grants, "github") {
			opened, perr := a.openGitHubProxy(current)
			if perr != nil || opened == nil {
				a.auditGitHubDecision(current, "github_proxy_denied", "", "", "deny", "proxy unavailable")
			} else {
				px = opened
				defer px.Close()
				ghSock = px.Sock()
				ghRepos = turnPol.EffectiveGitHubRepos(current.GitHubAllow)
				a.noteGitHubSock(current.ID, ghSock)
				defer a.noteGitHubSock(current.ID, "")
			}
		}
		gate := &gitHubGate{px: px}
		a.observeProtectBaseline()
		protect := a.shellProtectBot(current.ID)
		binds := a.cfg.BuildBinds
		if granted(current.Grants, "build") {
			var blocked []sandbox.Event
			binds, blocked = guardBuildBinds(protect, binds)
			for _, ev := range blocked {
				a.recordSandbox(current.ID, ev)
			}
		}
		cleanBash, gerr := a.gateShell(shellCtx, current, command)
		if gerr != nil {
			return "", gerr
		}
		shellWS, werr := a.shellWorkspace(current.ID)
		if werr != nil {
			return "", werr
		}
		res, err := sandbox.Run(shellCtx, sandbox.Request{
			Workspace:       shellWS,
			Command:         command,
			CleanBash:       cleanBash,
			Grants:          current.Grants,
			NetAllow:        current.NetAllow,
			SSHAllow:        current.SSHAllow,
			BuildBinds:      binds,
			Protect:         protect,
			ProtectInodes:   a.protectInodes(),
			ProtectTripped:  a.protectBlockReason(),
			SSHKey:          a.sshKeyPath(),
			GitHubSock:      ghSock,
			GitHubRepos:     ghRepos,
			GitAuthor:       author,
			GitAuthorEmail:  email,
			GitAuthorRefuse: aerr != nil,
			OnPushStart: func() {
				armShell(turnPol.EffectivePromptTimeout() + 15*time.Second)
			},
			OnPush: func(pctx context.Context, cwd string, pushArgs []string) sandbox.PushResult {
				return a.handleGitPush(pctx, ctx, current, gate, cwd, pushArgs)
			},
			Dial: a.shellDial,
		})
		a.recordSandboxEvents(current.ID, res.Events)
		summary := formatShell(res.Stdout, res.Stderr)
		if err != nil {
			return summary, fmt.Errorf("%s\n%s", err.Error(), summary)
		}
		return summary, nil
	default:
		return "", fmt.Errorf("unknown tool %s", name)
	}
}

func (a *App) sshKeyPath() string {
	return filepath.Join(a.cfg.DataDir, "sandbox", "id_ed25519")
}

func (a *App) recordSandbox(botID string, ev sandbox.Event) {
	a.recordSandboxNotice(botID, ev, true)
}

// netAuditKey is one trusted net or ssh audit row for this turn.
type netAuditKey struct {
	action string
	grant  string
	host   string
}

type netAuditRow struct {
	ev sandbox.Event
	n  int
}

// recordSandboxEvents logs every event from one turn. Untrusted jail
// notices are posted once per notice text. A count is added when the same
// text was reported more than once. A dropped-line count is included on
// the first notice only, or as its own summary when there is no notice.
// Trusted net and ssh audit rows are deduped per action, grant, and host.
// The bot log stays one row per event. Trusted notices stay one per event.
func (a *App) recordSandboxEvents(botID string, events []sandbox.Event) {
	counts := map[string]int{}
	var order []string
	dropped := 0
	var netOrder []netAuditKey
	netRows := map[netAuditKey]*netAuditRow{}
	suppressed := 0
	for _, ev := range events {
		if ev.Untrusted || ev.Kind == "jail_report" || ev.Kind == "jail_report_truncated" {
			a.recordSandboxNotice(botID, ev, false)
			dropped += droppedLines(ev)
			if text := untrustedNotice(ev); text != "" {
				if counts[text] == 0 {
					order = append(order, text)
				}
				counts[text]++
			}
			continue
		}
		if action := netAuditAction(ev); action != "" {
			a.logSandboxEvent(botID, ev)
			key := netAuditKey{action: action, grant: ev.Grant, host: ev.Host}
			if row := netRows[key]; row != nil {
				row.n++
				continue
			}
			if len(netOrder) >= 64 {
				suppressed++
				continue
			}
			netRows[key] = &netAuditRow{ev: ev, n: 1}
			netOrder = append(netOrder, key)
			continue
		}
		a.recordSandbox(botID, ev)
	}
	for _, key := range netOrder {
		row := netRows[key]
		a.writeNetAudit(botID, row.ev, key.action, row.n)
	}
	if suppressed > 0 && a != nil && a.audit != nil && a.audit.Enabled() {
		a.audit.Write(map[string]any{
			"action": "audit_suppressed",
			"count":  suppressed,
		})
	}
	if len(order) == 0 {
		if dropped > 0 {
			a.postSystemNotice(botID, fmt.Sprintf("Notice: Untrusted jail report: dropped lines (dropped %d)", dropped))
		}
		return
	}
	for i, text := range order {
		n := counts[text]
		msg := "Notice: " + text
		switch {
		case i == 0 && n > 1 && dropped > 0:
			msg = fmt.Sprintf("%s (x%d, dropped %d)", msg, n, dropped)
		case i == 0 && dropped > 0:
			msg = fmt.Sprintf("%s (dropped %d)", msg, dropped)
		case n > 1:
			msg = fmt.Sprintf("%s (x%d)", msg, n)
		}
		a.postSystemNotice(botID, msg)
	}
}

// logSandboxEvent writes the bot log and a trusted notice without auditing.
func (a *App) logSandboxEvent(botID string, ev sandbox.Event) {
	if ev.Kind == "" {
		return
	}
	a.log(botID, ev.Kind, sandboxEventDetail(ev))
	if ev.Notice != "" {
		a.postSystemNotice(botID, "Notice: "+ev.Notice)
	}
}

func sandboxEventDetail(ev sandbox.Event) map[string]any {
	detail := map[string]any{}
	if ev.Grant != "" {
		detail["grant"] = ev.Grant
	}
	if ev.Host != "" {
		detail["host"] = ev.Host
	}
	if ev.Detail != "" {
		detail["detail"] = ev.Detail
	}
	return detail
}

func droppedLines(ev sandbox.Event) int {
	if ev.Kind != "jail_report_truncated" {
		return 0
	}
	rest, ok := strings.CutPrefix(ev.Detail, "dropped ")
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func untrustedNotice(ev sandbox.Event) string {
	if ev.Notice == "" {
		return ""
	}
	notice := ev.Notice
	if !strings.Contains(strings.ToLower(notice), "untrusted") {
		notice = "Untrusted jail report: " + notice
	}
	return notice
}

func (a *App) postSystemNotice(botID, content string) {
	if a == nil || a.st == nil || content == "" {
		return
	}
	_, _ = a.st.AddMessage(store.Message{
		BotID: botID, Thread: "user", Role: "system", Content: content,
	})
}

func (a *App) recordSandboxNotice(botID string, ev sandbox.Event, postNotice bool) {
	if ev.Untrusted || ev.Kind == "jail_report" {
		detail := map[string]any{"untrusted": true}
		if ev.Reported != "" {
			detail["reported"] = ev.Reported
		}
		if ev.Grant != "" {
			detail["grant"] = ev.Grant
		}
		if ev.Host != "" {
			detail["host"] = ev.Host
		}
		if ev.Detail != "" {
			detail["detail"] = ev.Detail
		}
		if ev.Owner != "" {
			detail["owner"] = ev.Owner
		}
		if ev.Repo != "" {
			detail["repo"] = ev.Repo
		}
		a.log(botID, "jail_report", detail)
		if postNotice {
			if text := untrustedNotice(ev); text != "" {
				a.postSystemNotice(botID, "Notice: "+text)
			}
		}
		return
	}
	if ev.Kind != "" {
		a.log(botID, ev.Kind, sandboxEventDetail(ev))
		a.auditSandboxGitHub(botID, ev)
		a.auditSandboxNet(botID, ev)
	}
	if postNotice && ev.Notice != "" {
		a.postSystemNotice(botID, "Notice: "+ev.Notice)
	}
}

func formatShell(stdout, stderr string) string {
	var b strings.Builder
	b.WriteString("stdout:\n")
	b.WriteString(stdout)
	if !strings.HasSuffix(stdout, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("stderr:\n")
	b.WriteString(stderr)
	return b.String()
}

// serverToolsArg reads a create_bot or update_bot server_tools value.
// Null inherits. An array is stored after the same name check as the API.
func serverToolsArg(v any) (*[]string, error) {
	if v == nil {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, errors.New("invalid server_tools")
	}
	names := make([]string, 0, len(arr))
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, errors.New("invalid server_tools")
		}
		names = append(names, s)
	}
	norm, err := store.NormalizeServerTools(names)
	if err != nil {
		return nil, err
	}
	return &norm, nil
}

func strArg(args map[string]any, key string) string {
	v, ok := args[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return string(b)
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"error":"encode"}`
	}
	return string(b)
}

func cleanName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("name required")
	}
	if len(s) > 80 {
		return "", errors.New("name too long")
	}
	if strings.ContainsAny(s, "\r\n\t/") {
		return "", errors.New("invalid name")
	}
	return s, nil
}

// setTimer reads prompt plus one of in, at, or every. It also accepts the
// shapes models reach for on their own: schedule (as every, or as a one-shot
// when repeat is false), seconds / in_seconds / minutes as numbers, and
// message / text / reminder for prompt.
func (a *App) setTimer(bot store.Bot, args map[string]any) (string, error) {
	prompt := strings.TrimSpace(strArg(args, "prompt"))
	for _, k := range []string{"message", "text", "reminder"} {
		if prompt == "" {
			prompt = strings.TrimSpace(strArg(args, k))
		}
	}
	if prompt == "" {
		return "", badArgs("prompt is required")
	}
	in := strings.TrimSpace(strArg(args, "in"))
	at := strings.TrimSpace(strArg(args, "at"))
	every := strings.TrimSpace(strArg(args, "every"))
	if sched := strings.TrimSpace(strArg(args, "schedule")); sched != "" && in == "" && every == "" {
		if isFalse(args["repeat"]) {
			in = sched
		} else {
			every = sched
		}
	}
	if in == "" {
		for k, unit := range map[string]string{"seconds": "s", "in_seconds": "s", "delay_seconds": "s", "minutes": "m", "in_minutes": "m"} {
			if v := strings.Trim(strings.TrimSpace(strArg(args, k)), `"`); v != "" {
				if n, err := strconv.ParseFloat(v, 64); err == nil && n > 0 {
					in = strconv.FormatFloat(n, 'f', -1, 64) + unit
					break
				}
				return "", badArgs("%s must be a positive number, got %q", k, v)
			}
		}
	}
	set := 0
	for _, v := range []string{in, at, every} {
		if v != "" {
			set++
		}
	}
	if set != 1 {
		return "", badArgs("give exactly one of in, at, or every (got %d)", set)
	}
	name := strArg(args, "name")
	var t store.Timer
	var err error
	switch {
	case in != "":
		d, perr := store.ParseInterval(in)
		if perr != nil || d <= 0 {
			return "", badArgs("in must be a duration like \"90s\", \"5m\", \"2h\", or \"1d\", got %q", in)
		}
		when := time.Now().Add(d)
		if err = a.guardBotTimer(bot.ID, 0, when, true); err != nil {
			return "", err
		}
		t, err = a.st.CreateTimerAt(bot.ID, name, prompt, when, "bot")
	case at != "":
		when, perr := time.Parse(time.RFC3339, at)
		if perr != nil {
			return "", badArgs("at must be RFC 3339 with an offset like \"2026-10-14T17:30:00-07:00\", got %q", at)
		}
		if !when.After(time.Now()) {
			return "", badArgs("at %q is in the past; the current time is %s", at, time.Now().Format(time.RFC3339))
		}
		if err = a.guardBotTimer(bot.ID, 0, when, true); err != nil {
			return "", err
		}
		t, err = a.st.CreateTimerAt(bot.ID, name, prompt, when, "bot")
	default:
		d, perr := store.ParseInterval(every)
		if perr != nil {
			return "", badArgs("every must be an interval like \"30s\", \"5m\", \"2h\", or \"1d\", got %q", every)
		}
		if err = a.guardBotTimer(bot.ID, d, time.Time{}, false); err != nil {
			return "", err
		}
		t, err = a.st.CreateTimer(bot.ID, name, every, prompt, true, "bot")
	}
	if err != nil {
		return "", err
	}
	out := map[string]any{"id": t.ID, "schedule": t.Schedule, "prompt": t.Prompt, "next_fire_at": t.NextFireAt}
	if when, perr := time.Parse(time.RFC3339Nano, t.NextFireAt); perr == nil {
		out["fires_at_local"] = when.Local().Format(time.RFC3339)
	}
	return mustJSON(out), nil
}

func isFalse(v any) bool {
	switch t := v.(type) {
	case bool:
		return !t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "false") || t == "0" || strings.EqualFold(t, "no")
	}
	return false
}
