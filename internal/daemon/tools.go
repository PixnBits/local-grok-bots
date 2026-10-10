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
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func toolDefs() []model.Tool {
	obj := func(props map[string]any, req []string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": req}
	}
	str := map[string]any{"type": "string"}
	return []model.Tool{
		{Name: "list_bots", Description: "List bots: id, name, and status.", Parameters: obj(map[string]any{}, nil)},
		{Name: "read_bot", Description: "Read a bot's instructions and memory by name or id.", Parameters: obj(map[string]any{"name": str}, []string{"name"})},
		{Name: "send_dm", Description: "Send a direct message to another bot by name or id. Returns immediately; the recipient gets its own turn.", Parameters: obj(map[string]any{"to": str, "content": str}, []string{"to", "content"})},
		{Name: "create_bot", Description: "Create a bot with a unique name and instructions.", Parameters: obj(map[string]any{"name": str, "instructions": str, "model": str}, []string{"name", "instructions"})},
		{Name: "update_bot", Description: "Update another bot's name, instructions, or model. Identify it by id or name.", Parameters: obj(map[string]any{"id": str, "name": str, "instructions": str, "model": str}, nil)},
		{Name: "write_memory", Description: "Upsert a memory note on yourself.", Parameters: obj(map[string]any{"key": str, "value": str}, []string{"key", "value"})},
		{Name: "delete_memory", Description: "Delete one of your memory notes.", Parameters: obj(map[string]any{"key": str}, []string{"key"})},
		{Name: "set_timer", Description: "Schedule a prompt on yourself. Schedule is an interval like 30s, 5m, 2h, or 1d.", Parameters: obj(map[string]any{"schedule": str, "prompt": str}, []string{"schedule", "prompt"})},
		{Name: "clear_timer", Description: "Delete one of your timers by id.", Parameters: obj(map[string]any{"id": str}, []string{"id"})},
		{Name: "read_file", Description: "Read a UTF-8 file inside the workspace.", Parameters: obj(map[string]any{"path": str}, []string{"path"})},
		{Name: "write_file", Description: "Write a UTF-8 file inside the workspace. Creates parent directories.", Parameters: obj(map[string]any{"path": str, "content": str}, []string{"path", "content"})},
		{Name: "run_shell", Description: "Run a shell command with the workspace as the working directory. Cannot read or write outside the workspace.", Parameters: obj(map[string]any{"command": str}, []string{"command"})},
	}
}

func (a *App) execTool(ctx context.Context, bot store.Bot, name string, args map[string]any) (string, error) {
	if args == nil {
		args = map[string]any{}
	}
	a.log(bot.ID, "tool_start", map[string]any{"name": name, "arguments": redactValue(args)})
	result, err := a.dispatchTool(ctx, bot, name, args)
	detail := map[string]any{"name": name, "ok": err == nil}
	if err != nil {
		detail["error"] = clip(err.Error(), 500)
	}
	a.log(bot.ID, "tool_end", detail)
	return result, err
}

func (a *App) dispatchTool(ctx context.Context, bot store.Bot, name string, args map[string]any) (string, error) {
	switch name {
	case "list_bots":
		bots, err := a.st.ListBots()
		if err != nil {
			return "", err
		}
		type row struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		out := make([]row, 0, len(bots))
		for _, b := range bots {
			out = append(out, row{ID: b.ID, Name: b.Name, Status: b.Status})
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
			"id": other.ID, "name": other.Name, "status": other.Status,
			"instructions": other.Instructions, "model": other.Model, "memory": mem,
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
		instructions := strArg(args, "instructions")
		var modelPtr *string
		if m := strings.TrimSpace(strArg(args, "model")); m != "" {
			modelPtr = &m
		}
		created, err := a.st.CreateBot(name, instructions, modelPtr, bot.ID)
		if err != nil {
			return "", err
		}
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
		if v, ok := args["name"]; ok && fmt.Sprint(v) != "" && (strArg(args, "id") != "" || hasKey(args, "instructions") || hasKey(args, "model")) {
			// name field is the new name only when the bot was identified separately,
			// or when both id and name are present. If only name is set and it matched
			// the lookup, a rename requires the new name under "name" plus id.
		}
		if id := strArg(args, "id"); id != "" {
			if n := strArg(args, "name"); n != "" && !strings.EqualFold(n, target.Name) {
				cn, err := cleanName(n)
				if err != nil {
					return "", err
				}
				patch.Name = &cn
			}
		}
		if _, ok := args["instructions"]; ok {
			ins := strArg(args, "instructions")
			patch.Instructions = &ins
		}
		if _, ok := args["model"]; ok {
			m := strings.TrimSpace(strArg(args, "model"))
			patch.ModelSet = true
			if m != "" {
				patch.Model = &m
			}
		}
		// Allow rename when called as update_bot {name: current, new_name}? Spec says
		// {id or name, name?, instructions?, model?}. If both id and name are sent,
		// name is the new name. If only name is sent, it identifies the bot and does
		// not rename. A rename without an id uses the lookup name and cannot also
		// pass a new name in the same field. Callers pass id to rename.
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
		m, err := a.st.UpsertMemory(bot.ID, key, strArg(args, "value"))
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
		schedule := strArg(args, "schedule")
		prompt := strArg(args, "prompt")
		if strings.TrimSpace(prompt) == "" {
			return "", errors.New("prompt required")
		}
		t, err := a.st.CreateTimer(bot.ID, schedule, prompt, true)
		if err != nil {
			return "", err
		}
		return mustJSON(t), nil
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
		path, err := sandbox.Resolve(a.ws, strArg(args, "path"))
		if err != nil {
			return "", err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		const max = 256 * 1024
		s := string(b)
		if len(s) > max {
			s = s[:max] + "\n…(truncated)"
		}
		return s, nil
	case "write_file":
		path, err := sandbox.Resolve(a.ws, strArg(args, "path"))
		if err != nil {
			return "", err
		}
		content := strArg(args, "content")
		if len(content) > 1<<20 {
			return "", errors.New("content too large")
		}
		if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return "", err
		}
		return `{"ok":true}`, nil
	case "run_shell":
		command := strArg(args, "command")
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		stdout, stderr, err := sandbox.Run(sctx, a.ws, command)
		summary := formatShell(stdout, stderr)
		if err != nil {
			return summary, fmt.Errorf("%s\n%s", err.Error(), summary)
		}
		return summary, nil
	default:
		return "", fmt.Errorf("unknown tool %s", name)
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

func dirOf(path string) string {
	i := strings.LastIndex(path, "/")
	if i <= 0 {
		return "."
	}
	return path[:i]
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

func hasKey(args map[string]any, key string) bool {
	_, ok := args[key]
	return ok
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
