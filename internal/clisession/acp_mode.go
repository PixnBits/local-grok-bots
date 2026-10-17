package clisession

import "strings"

// acpModeRefused is the user-facing reason when a session is not in the
// default permission mode, or a bypass flag is set.
const acpModeRefused = "permission mode is not default, so the turn was refused"

// acpResultModeProblem checks a session/new or session/load result before
// the prompt is sent. The mode must be default.
func acpResultModeProblem(result map[string]any) string {
	if result == nil {
		return acpModeRefused
	}
	if p := metaModeProblem(asMap(result["_meta"])); p != "" {
		return p
	}
	if bypassSet(result) {
		return acpModeRefused
	}
	modes := asMap(result["modes"])
	if modes == nil {
		modes = asMap(result["modeState"])
	}
	if modes == nil {
		// Grok 1.0.52 reports no modes object on session/new. The mode then
		// comes from the sealed config.toml, and later mode updates are still
		// checked. A reported mode must be default.
		return configOptionsProblem(result["configOptions"])
	}
	if p := notificationProblem(modes); p != "" {
		return p
	}
	if !modeIsDefault(strOf(modes, "currentModeId", "current_mode_id")) {
		return acpModeRefused
	}
	return configOptionsProblem(result["configOptions"])
}

// acpUpdateModeProblem checks one session/update body. A message chunk is
// left alone unless its meta carries a mode or a bypass flag.
func acpUpdateModeProblem(upd map[string]any) string {
	if upd == nil {
		return ""
	}
	if p := metaModeProblem(asMap(upd["_meta"])); p != "" {
		return p
	}
	switch strOf(upd, "sessionUpdate") {
	case "current_mode_update":
		if !modeIsDefault(strOf(upd, "currentModeId", "current_mode_id", "mode")) {
			return acpModeRefused
		}
	case "config_option_update":
		if p := configOptionsProblem(upd["configOptions"]); p != "" {
			return p
		}
		return oneConfigProblem(upd)
	case "_x.ai/sessions/changed", "x.ai/sessions/changed":
		return changedProblem(upd)
	default:
		if ch := asMap(upd["_x.ai/sessions/changed"]); ch != nil {
			return changedProblem(ch)
		}
		if ch := asMap(upd["x.ai/sessions/changed"]); ch != nil {
			return changedProblem(ch)
		}
	}
	return ""
}

func metaModeProblem(meta map[string]any) string {
	if meta == nil {
		return ""
	}
	for _, key := range []string{"_x.ai/session_notification", "x.ai/session_notification"} {
		if n := asMap(meta[key]); n != nil {
			if p := notificationProblem(n); p != "" {
				return p
			}
		}
	}
	return ""
}

func changedProblem(m map[string]any) string {
	return notificationProblem(m)
}

func notificationProblem(n map[string]any) string {
	if n == nil {
		return ""
	}
	if p := modeFieldsProblem(n); p != "" {
		return p
	}
	for k, v := range n {
		if skipModeWalk(k) {
			continue
		}
		if sub := asMap(v); sub != nil {
			if p := modeFieldsProblem(sub); p != "" {
				return p
			}
		}
	}
	return ""
}

func modeFieldsProblem(n map[string]any) string {
	if n == nil {
		return ""
	}
	if bypassSet(n) {
		return acpModeRefused
	}
	for _, k := range []string{"mode", "permission_mode", "permissionMode", "currentModeId", "current_mode_id"} {
		s, ok := n[k].(string)
		if !ok || strings.TrimSpace(s) == "" {
			continue
		}
		if !modeIsDefault(s) {
			return acpModeRefused
		}
	}
	return ""
}

func skipModeWalk(k string) bool {
	switch k {
	case "content", "rawInput", "rawOutput", "raw_input", "raw_output", "toolCall", "sessionUpdate":
		return true
	default:
		return false
	}
}

func configOptionsProblem(v any) string {
	if m := asMap(v); m != nil {
		return oneConfigProblem(m)
	}
	items, ok := v.([]any)
	if !ok {
		return ""
	}
	for _, item := range items {
		if p := oneConfigProblem(asMap(item)); p != "" {
			return p
		}
	}
	return ""
}

func oneConfigProblem(m map[string]any) string {
	if m == nil {
		return ""
	}
	id := strings.ToLower(strOf(m, "id", "name", "key", "configId", "config_id"))
	if !modeOption(id) {
		return ""
	}
	val := m["currentValue"]
	if val == nil {
		val = m["value"]
	}
	if val == nil {
		val = m["current_value"]
	}
	if s, ok := val.(string); ok {
		s = strings.TrimSpace(s)
		if s == "" || modeIsDefault(s) || falseString(s) {
			return ""
		}
		if strings.Contains(id, "yolo") && !modeTruthy(s) {
			return ""
		}
		return acpModeRefused
	}
	if modeTruthy(val) {
		return acpModeRefused
	}
	return ""
}

func falseString(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "false", "no", "off":
		return true
	default:
		return false
	}
}

func modeOption(id string) bool {
	switch id {
	case "mode", "permission_mode", "permissionmode", "yolo", "yolomode", "yolo_mode":
		return true
	}
	return strings.Contains(id, "yolo") || strings.Contains(id, "permission") ||
		strings.Contains(id, "approv") || strings.Contains(id, "bypass")
}

func bypassSet(m map[string]any) bool {
	if m == nil {
		return false
	}
	for _, k := range []string{"yolo", "yoloMode", "yolo_mode"} {
		if _, ok := m[k]; ok && modeTruthy(m[k]) {
			return true
		}
	}
	return false
}

func modeIsDefault(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "default")
}

func modeTruthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "1", "true", "yes", "on":
			return true
		}
	case float64:
		return t != 0
	}
	return false
}

// SlashPrompt reports a turn input that is a slash command after trimming.
func SlashPrompt(text string) bool {
	return strings.HasPrefix(strings.TrimSpace(text), "/")
}

// ErrSlash refuses a slash command before the CLI starts.
var ErrSlash = errSlash("slash commands are refused, so the turn was refused")

type errSlash string

func (e errSlash) Error() string { return string(e) }

// denyText reports a failed tool update whose text says the call was denied.
// Empty text is not a deny. A shell error that contains the same word can
// match; that still records a denial and does not allow the call.
func denyText(text string) bool {
	t := strings.ToLower(text)
	for _, s := range []string{"denied", "not allowed", "disallowed", "not permitted"} {
		if strings.Contains(t, s) {
			return true
		}
	}
	return false
}
