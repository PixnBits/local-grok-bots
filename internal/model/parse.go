package model

import "strings"

// ToolCallParseError means the model emitted a tool call the server could not parse.
// The daemon may try the turn once more. Transport failures are not this error.
type ToolCallParseError struct {
	Detail string
}

func (e *ToolCallParseError) Error() string {
	if e == nil {
		return "ollama: tool call parse error"
	}
	return "ollama: " + e.Detail
}

// AsToolCallParseError reports whether msg is a model tool-call parse failure.
func AsToolCallParseError(msg string) (*ToolCallParseError, bool) {
	if !toolParseError(msg) {
		return nil, false
	}
	return &ToolCallParseError{Detail: msg}, true
}

func toolParseError(msg string) bool {
	s := strings.ToLower(msg)
	if strings.Contains(s, "xml syntax error") {
		return true
	}
	return strings.Contains(s, "tool call") && (strings.Contains(s, "pars") || strings.Contains(s, "invalid"))
}
