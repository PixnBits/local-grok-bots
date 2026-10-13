package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func toolDefs() []model.Tool {
	obj := func(props map[string]any, req []string) map[string]any {
		if req == nil {
			req = []string{}
		}
		return map[string]any{"type": "object", "properties": props, "required": req}
	}
	str := map[string]any{"type": "string"}
	// File and shell tools come first. qwen3.8's default thinking only
	// reliably notices tools near the end of this list. Memory and roster
	// reads stay after the shell so they are not dropped. When they sit
	// earlier, the model treats them as missing and keeps thinking past
	// the three-minute model limit (about 8 tokens/s on this machine).
	return []model.Tool{
		{Name: "write_memory", Description: "Upsert a memory note on yourself.", Parameters: obj(map[string]any{"key": str, "value": str}, []string{"key", "value"})},
		{Name: "delete_memory", Description: "Delete one of your memory notes.", Parameters: obj(map[string]any{"key": str}, []string{"key"})},
		{Name: "clear_timer", Description: "Delete one of your timers by id.", Parameters: obj(map[string]any{"id": str}, []string{"id"})},
		{Name: "read_file", Description: "Read a UTF-8 file inside the workspace.", Parameters: obj(map[string]any{"path": str}, []string{"path"})},
		{Name: "write_file", Description: "Write a UTF-8 file inside the workspace. Creates parent directories.", Parameters: obj(map[string]any{"path": str, "content": str}, []string{"path", "content"})},
		{Name: "run_shell", Description: "Run a shell command inside the workspace jail. Paths outside the workspace are rejected. Network, git push, and SSH fail unless the user granted them.", Parameters: obj(map[string]any{"command": str}, []string{"command"})},
		{Name: "list_bots", Description: "List bots: id, name, label, and status.", Parameters: obj(map[string]any{}, nil)},
		{Name: "read_bot", Description: "Read a bot's description and memory by name or id.", Parameters: obj(map[string]any{"name": str}, []string{"name"})},
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
	case "send_dm", "create_bot", "update_bot", "set_timer":
		// The page is the user path. A bot must not create or rewrite bots,
		// message another bot, or schedule itself.
		return "", fmt.Errorf("%s requires the user; a bot cannot do that", name)
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
		if err := sandbox.CheckWrite(a.ws, path); err != nil {
			a.log(bot.ID, "sandbox_block", map[string]any{"path": strArg(args, "path"), "detail": err.Error()})
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
		current := bot
		if fresh, err := a.st.GetBot(bot.ID); err == nil {
			current = fresh
		}
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		res, err := sandbox.Run(sctx, sandbox.Request{
			Workspace:  a.ws,
			Command:    command,
			Grants:     current.Grants,
			NetAllow:   a.policy.NetAllow(current.Grants, current.NetAllow),
			SSHAllow:   current.SSHAllow,
			BuildBinds: a.policy.BuildBinds,
			SSHKey:     a.sshKeyPath(),
			Dial:       a.shellDial,
		})
		for _, ev := range res.Events {
			a.recordSandbox(current.ID, ev)
		}
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
	if ev.Kind != "" {
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
		a.log(botID, ev.Kind, detail)
	}
	if ev.Notice != "" {
		_, _ = a.st.AddMessage(store.Message{
			BotID: botID, Thread: "user", Role: "system", Content: "Notice: " + ev.Notice,
		})
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
