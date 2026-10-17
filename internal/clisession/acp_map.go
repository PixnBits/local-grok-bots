package clisession

import (
	"fmt"
	"strings"
)

// acpOption is one entry on a session/request_permission options list.
type acpOption struct {
	OptionID string
	Name     string
	Kind     string
}

// mapACPTool turns one ACP toolCall object into the tool name and arguments
// the permission classifier already understands. An unknown tool is reported
// as "unknown" so the audit does not keep the raw name.
func mapACPTool(call map[string]any) (tool string, args map[string]any, useID string, err error) {
	if call == nil {
		return "", nil, "", fmt.Errorf("malformed permission request")
	}
	useID = strOf(call, "toolCallId", "tool_call_id")
	raw := asMap(call["rawInput"])
	meta := xaiTool(call)
	metaIn := asMap(nil)
	metaName := ""
	if meta != nil {
		metaName = strOf(meta, "name")
		metaIn = asMap(meta["input"])
	}
	args = map[string]any{}
	for k, v := range metaIn {
		args[k] = v
	}
	for k, v := range raw {
		if k == "variant" {
			continue
		}
		args[k] = v
	}
	variant := strings.ToLower(strOf(raw, "variant"))
	name := strings.ToLower(strings.TrimSpace(metaName))
	kind := strings.ToLower(strOf(call, "kind"))
	switch {
	case variant == "bash" || name == "run_terminal_command" || (kind == "execute" && variant == "" && name == ""):
		tool = "Bash"
		if cmd := strOf(args, "command", "cmd"); cmd != "" {
			args["command"] = cmd
		}
	case variant == "readfile" || variant == "read" || name == "read_file":
		tool = "Read"
		setFilePath(args, raw, metaIn)
	case name == "list_dir" || variant == "listdir":
		tool = "Glob"
		p := strOf(raw, "target_directory", "path", "file_path")
		if p == "" {
			p = strOf(args, "target_directory", "path", "file_path")
		}
		if p != "" {
			args["path"] = p
			args["file_path"] = p
		}
		if strOf(args, "pattern") == "" {
			args["pattern"] = "*"
		}
	case name == "grep" || variant == "grep":
		tool = "Grep"
		setFilePath(args, raw, metaIn)
	case name == "glob" || variant == "glob":
		tool = "Glob"
		setFilePath(args, raw, metaIn)
		if strOf(args, "pattern") == "" {
			if p := strOf(args, "glob", "glob_pattern"); p != "" {
				args["pattern"] = p
			}
		}
	case name == "search_replace" || name == "edit" || variant == "edit":
		tool = "Edit"
		setFilePath(args, raw, metaIn)
	case name == "write" || variant == "write":
		tool = "Write"
		setFilePath(args, raw, metaIn)
	case name == "web_fetch" || name == "webfetch" || variant == "webfetch":
		tool = "WebFetch"
		if u := strOf(args, "url"); u != "" {
			args["url"] = u
		}
	case name == "web_search" || name == "websearch" || variant == "websearch":
		tool = "WebSearch"
	default:
		if strings.TrimSpace(metaName) == "" && strOf(raw, "variant") == "" && strOf(call, "title") == "" && strOf(call, "kind") == "" {
			return "", nil, useID, fmt.Errorf("malformed permission request")
		}
		tool = "unknown"
	}
	// argText prefers command over file_path. File tools must not keep a
	// command key or a Read of a path is classified as that command.
	switch tool {
	case "Read", "Grep", "Glob", "Edit", "Write":
		delete(args, "command")
		delete(args, "cmd")
	}
	return tool, args, useID, nil
}

func setFilePath(args, raw, meta map[string]any) {
	fp := strOf(raw, "target_file", "file_path", "filePath", "path", "target_directory")
	if fp == "" {
		fp = strOf(args, "file_path", "filePath", "path", "target_file", "target_directory")
	}
	if fp == "" {
		fp = strOf(meta, "path", "file_path", "target_file", "target_directory")
	}
	if fp != "" {
		args["file_path"] = fp
	}
}

func xaiTool(call map[string]any) map[string]any {
	meta := asMap(call["_meta"])
	if meta == nil {
		return nil
	}
	return asMap(meta["x.ai/tool"])
}

func strOf(m map[string]any, keys ...string) string {
	if m == nil {
		return ""
	}
	for _, k := range keys {
		s, ok := m[k].(string)
		if ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// selectACPOption picks allow-once or reject-once. allow_always is never a
// valid choice, including when it is the only allow option.
func selectACPOption(opts []acpOption, allow bool) (string, error) {
	wantKind := "reject_once"
	wantID := "reject-once"
	if allow {
		wantKind = "allow_once"
		wantID = "allow-once"
	}
	for _, o := range opts {
		if allowAlwaysOption(o) {
			continue
		}
		if strings.EqualFold(o.Kind, wantKind) && strings.TrimSpace(o.OptionID) != "" {
			return o.OptionID, nil
		}
	}
	for _, o := range opts {
		if allowAlwaysOption(o) {
			continue
		}
		if strings.EqualFold(o.OptionID, wantID) {
			return o.OptionID, nil
		}
	}
	return "", fmt.Errorf("permission options have no %s", wantKind)
}

func allowAlwaysOption(o acpOption) bool {
	k := strings.ToLower(strings.TrimSpace(o.Kind))
	id := strings.ToLower(strings.TrimSpace(o.OptionID))
	name := strings.ToLower(strings.TrimSpace(o.Name))
	if strings.Contains(id, "always") || strings.Contains(name, "always") || strings.Contains(k, "always") {
		return true
	}
	return k == "allow_always" || id == "always-allow" || id == "allow_always"
}

func acpOptions(v any) []acpOption {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]acpOption, 0, len(items))
	for _, item := range items {
		m := asMap(item)
		if m == nil {
			continue
		}
		out = append(out, acpOption{
			OptionID: strOf(m, "optionId", "option_id"),
			Name:     strOf(m, "name", "title"),
			Kind:     strOf(m, "kind"),
		})
	}
	return out
}
