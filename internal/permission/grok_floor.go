package permission

import (
	"path/filepath"
	"strings"
)

// refusedTool is a tool the broker always denies. The returned name is the
// audit tool. A hit is not overridden by a hook, a bypass, or a user allow.
func refusedTool(name string) (tool, rule string, hit bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "task":
		return "Task", "task", true
	case "workflow":
		return "Workflow", "workflow", true
	case "scheduler", "scheduler_create", "scheduler_delete", "scheduler_list":
		return "Scheduler", "scheduler", true
	case "imagegen", "image_gen":
		return "ImageGen", "image", true
	case "imageedit", "image_edit":
		return "ImageEdit", "image", true
	case "imagetovideo", "image_to_video":
		return "ImageToVideo", "image", true
	case "referencetovideo", "reference_to_video":
		return "ReferenceToVideo", "image", true
	default:
		return "", "", false
	}
}

// grokHomeDenied reports a write, an edit, or a shell target under GROK_HOME.
// An empty home skips the check.
func grokHomeDenied(req Request) bool {
	home := strings.TrimSpace(req.GrokHome)
	if home == "" || !filepath.IsAbs(home) {
		return false
	}
	home = filepath.Clean(home)
	switch strings.ToLower(strings.TrimSpace(req.Tool)) {
	case "edit", "write", "multiedit", "notebookedit", "search_replace":
		return fileTargetsHome(req.Args, req.Workspace, home)
	case "bash", "monitor":
		return commandTargetsHome(argText(req.Args), req.Workspace, home)
	default:
		return false
	}
}

func fileTargetsHome(args map[string]any, workspace, home string) bool {
	if args == nil {
		return false
	}
	for k, v := range args {
		if pathArg(k) {
			if s, ok := v.(string); ok && stringUnderHome(s, workspace, home) {
				return true
			}
		}
		switch t := v.(type) {
		case []any:
			for _, item := range t {
				if m, ok := item.(map[string]any); ok && fileTargetsHome(m, workspace, home) {
					return true
				}
			}
		case map[string]any:
			if fileTargetsHome(t, workspace, home) {
				return true
			}
		}
	}
	return false
}

func pathArg(k string) bool {
	switch k {
	case "file_path", "filePath", "path", "target_file", "target_directory":
		return true
	default:
		return false
	}
}

func stringUnderHome(s, workspace, home string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.Contains(s, "$GROK_HOME") || strings.Contains(s, "${GROK_HOME}") {
		return true
	}
	return insideRoot(resolvedGrantPath(s, workspace), home)
}

func commandTargetsHome(cmd, workspace, home string) bool {
	if strings.Contains(cmd, "$GROK_HOME") || strings.Contains(cmd, "${GROK_HOME}") {
		return true
	}
	for _, tok := range splitCmd(cmd) {
		if tokenUnderHome(tok, workspace, home) {
			return true
		}
	}
	return false
}

func tokenUnderHome(tok, workspace, home string) bool {
	tok = strings.Trim(strings.TrimSpace(tok), `"'`)
	if tok == "" {
		return false
	}
	if strings.Contains(tok, "$GROK_HOME") || strings.Contains(tok, "${GROK_HOME}") {
		return true
	}
	stripped := strings.TrimLeft(tok, "0123456789")
	if strings.HasPrefix(stripped, ">") || strings.HasPrefix(stripped, "<") {
		stripped = strings.TrimLeft(stripped, "<>|&")
		stripped = strings.Trim(stripped, `"'`)
		tok = stripped
	}
	if tok == "" || (!strings.Contains(tok, "/") && !strings.HasPrefix(tok, ".")) {
		return false
	}
	return insideRoot(resolvedGrantPath(tok, workspace), home)
}
