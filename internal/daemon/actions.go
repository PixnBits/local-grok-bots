package daemon

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var actionFence = regexp.MustCompile("(?s)```(?:action|bot-action)[ \t]*\n(.*?)```")

type cliAction struct {
	Name string
	Args map[string]any
}

func extractActions(text string) (string, []cliAction) {
	var calls []cliAction
	visible := actionFence.ReplaceAllStringFunc(text, func(block string) string {
		m := actionFence.FindStringSubmatch(block)
		if len(m) < 2 {
			return block
		}
		parsed, ok := parseActionBody(m[1])
		if !ok || len(parsed) == 0 {
			return block
		}
		calls = append(calls, parsed...)
		return ""
	})
	return strings.TrimSpace(visible), calls
}

func parseActionBody(body string) ([]cliAction, bool) {
	dec := json.NewDecoder(strings.NewReader(strings.TrimSpace(body)))
	var out []cliAction
	for {
		var raw map[string]any
		if err := dec.Decode(&raw); err != nil {
			if len(out) == 0 {
				return nil, false
			}
			break
		}
		toolName, _ := raw["tool"].(string)
		alias, _ := raw["name"].(string)
		name := strings.TrimSpace(toolName)
		if name == "" {
			name = strings.TrimSpace(alias)
		}
		if name == "" {
			return nil, false
		}
		args := map[string]any{}
		if nested, ok := raw["arguments"].(map[string]any); ok {
			args = nested
		} else if nested, ok := raw["args"].(map[string]any); ok {
			args = nested
		} else {
			for k, v := range raw {
				if k == "tool" || k == "arguments" || k == "args" {
					continue
				}
				// "name" is the tool only when "tool" was omitted.
				if k == "name" && strings.TrimSpace(toolName) == "" {
					continue
				}
				args[k] = v
			}
		}
		out = append(out, cliAction{Name: name, Args: args})
	}
	return out, true
}

func allowedCLIAction(name string) bool {
	switch name {
	case "write_memory", "delete_memory", "set_timer", "clear_timer",
		"list_bots", "read_bot", "send_dm", "create_bot", "update_bot":
		return true
	default:
		return false
	}
}

func errNotDaemonAction(name string) error {
	return fmt.Errorf("%s is not a daemon action; use your own file and shell tools", name)
}

func formatActionResults(lines []string) string {
	var b strings.Builder
	b.WriteString("Daemon action results:\n")
	for _, line := range lines {
		b.WriteString("- ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\nReply to the user. Emit another ```action block only if you still need a daemon action.\n")
	return b.String()
}
