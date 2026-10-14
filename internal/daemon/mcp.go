package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/permission"
)

const permissionToolName = "mcp__lgbperm__approve"

type permBind struct {
	botID     string
	runID     string
	sessionID string
}

type rpcRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

func httpBase(bind string) string {
	bind = strings.TrimSpace(bind)
	if bind == "" || strings.HasPrefix(bind, "/") {
		return ""
	}
	if strings.HasPrefix(bind, "http://") || strings.HasPrefix(bind, "https://") {
		return strings.TrimRight(bind, "/")
	}
	host, port, err := net.SplitHostPort(bind)
	if err != nil || port == "" || port == "0" {
		return ""
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

func permissionMCPConfig(base, token string) string {
	payload := map[string]any{
		"mcpServers": map[string]any{
			"lgbperm": map[string]any{
				"type": "http",
				"url":  strings.TrimRight(base, "/") + "/api/mcp/permission/" + token,
			},
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(b)
}

func (a *App) registerPerm(botID, runID, sessionID string) string {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic(err)
	}
	token := hex.EncodeToString(buf[:])
	a.permMu.Lock()
	if a.permTokens == nil {
		a.permTokens = map[string]permBind{}
	}
	a.permTokens[token] = permBind{botID: botID, runID: runID, sessionID: sessionID}
	a.permMu.Unlock()
	return token
}

func (a *App) unregisterPerm(token string) {
	a.permMu.Lock()
	delete(a.permTokens, token)
	a.permMu.Unlock()
}

func (a *App) lookupPerm(token string) (permBind, bool) {
	if !permTokenOK(token) {
		return permBind{}, false
	}
	a.permMu.Lock()
	defer a.permMu.Unlock()
	b, ok := a.permTokens[token]
	return b, ok
}

func permTokenOK(token string) bool {
	if len(token) != 64 {
		return false
	}
	for _, c := range token {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

func (a *App) handlePermissionDecision(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Decision string `json:"decision"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if a.perm == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	err := a.perm.DecideFor(r.PathValue("id"), r.PathValue("run_id"), r.PathValue("req_id"), body.Decision)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case errors.Is(err, permission.ErrDecision):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	case errors.Is(err, permission.ErrSessionGrant):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
	case errors.Is(err, permission.ErrNotFound), errors.Is(err, permission.ErrMismatch):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}

func (a *App) handleMCPPermission(w http.ResponseWriter, r *http.Request) {
	bind, ok := a.lookupPerm(r.PathValue("token"))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	w.Header().Set("Mcp-Session-Id", r.PathValue("token"))
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil || len(body) == 0 || body[0] == '[' {
		writeRPCError(w, r, nil, -32700, "parse error")
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPCError(w, r, nil, -32700, "parse error")
		return
	}
	if !rpcHasID(req.ID) {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch req.Method {
	case "initialize":
		writeRPC(w, r, req.ID, initializeResult(req.Params))
	case "ping":
		writeRPC(w, r, req.ID, map[string]any{})
	case "tools/list":
		writeRPC(w, r, req.ID, map[string]any{"tools": []any{approveToolSchema()}})
	case "tools/call":
		a.callApprove(w, r, req.ID, req.Params, bind)
	default:
		writeRPCError(w, r, req.ID, -32601, "method not found")
	}
}

func (a *App) callApprove(w http.ResponseWriter, r *http.Request, id json.RawMessage, params json.RawMessage, bind permBind) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		writeRPCError(w, r, id, -32602, "invalid params")
		return
	}
	if call.Name != "approve" {
		writeRPCError(w, r, id, -32602, "unknown tool")
		return
	}
	rawArgs := call.Arguments
	if len(rawArgs) > 0 && rawArgs[0] == '"' {
		var s string
		if json.Unmarshal(rawArgs, &s) == nil {
			rawArgs = []byte(s)
		}
	}
	var args struct {
		ToolName  string         `json:"tool_name"`
		Input     map[string]any `json:"input"`
		ToolUseID string         `json:"tool_use_id"`
	}
	if len(rawArgs) > 0 {
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			writeRPCError(w, r, id, -32602, "invalid arguments")
			return
		}
	}
	if strings.TrimSpace(args.ToolName) == "" {
		writeRPCError(w, r, id, -32602, "tool_name is required")
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stop := context.AfterFunc(a.ctx, cancel)
	defer stop()
	out := a.perm.Evaluate(ctx, a.policy.Permission(), permission.Request{
		RunID:     bind.runID,
		BotID:     bind.botID,
		SessionID: bind.sessionID,
		Tool:      args.ToolName,
		Args:      args.Input,
		ToolUseID: args.ToolUseID,
	})
	var text []byte
	if out.Behavior == "allow" {
		updated := args.Input
		if updated == nil {
			updated = map[string]any{}
		}
		text, _ = json.Marshal(map[string]any{"behavior": "allow", "updatedInput": updated})
	} else {
		msg := out.Message
		if msg == "" {
			msg = "denied"
		}
		text, _ = json.Marshal(map[string]any{"behavior": "deny", "message": msg})
	}
	writeRPC(w, r, id, map[string]any{
		"content": []any{map[string]any{"type": "text", "text": string(text)}},
		"isError": false,
	})
}

func initializeResult(params json.RawMessage) map[string]any {
	version := "2024-11-05"
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	if strings.TrimSpace(p.ProtocolVersion) != "" {
		version = strings.TrimSpace(p.ProtocolVersion)
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": "lgbperm", "version": "0.1.0"},
	}
}

func approveToolSchema() map[string]any {
	return map[string]any{
		"name":        "approve",
		"description": "Approve or deny a Claude Code tool call.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tool_name":   map[string]any{"type": "string"},
				"input":       map[string]any{"type": "object"},
				"tool_use_id": map[string]any{"type": "string"},
			},
			"required": []string{"tool_name"},
		},
	}
}

func rpcHasID(id json.RawMessage) bool {
	s := strings.TrimSpace(string(id))
	return s != "" && s != "null"
}

func writeRPC(w http.ResponseWriter, r *http.Request, id json.RawMessage, result any) {
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	if err != nil {
		writeRPCError(w, r, id, -32603, "internal error")
		return
	}
	writeRPCRaw(w, r, raw)
}

func writeRPCError(w http.ResponseWriter, r *http.Request, id json.RawMessage, code int, message string) {
	if !rpcHasID(id) {
		id = []byte("null")
	}
	raw, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": message},
	})
	writeRPCRaw(w, r, raw)
}

func writeRPCRaw(w http.ResponseWriter, r *http.Request, raw []byte) {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/event-stream") && !strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", raw)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
