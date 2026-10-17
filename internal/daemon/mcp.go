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
	"os"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/policy"
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

// permHeaderScript prints the MCP Authorization header. Claude runs it from
// headersHelper, so the token stays in a file and off argv and the JSON.
const permHeaderScript = `#!/bin/sh
tok=$(tr -d '\n' < "$1")
printf '{"Authorization":"Bearer %s"}\n' "$tok"
`

// writePermMCP writes the permission token, the header helper, and the
// --mcp-config file under DATA_DIR/cli/<bot>/perm/<run>/, so two runs of one
// bot never share or remove each other's files. Each file is mode 0600.
// The JSON names the helper; it does not contain the token.
// The returned path is what --mcp-config receives.
func (a *App) writePermMCP(botID, runID, base, token string) (string, error) {
	if !permTokenOK(token) {
		return "", fmt.Errorf("permission token is invalid")
	}
	root, err := filepath.Abs(a.cfg.DataDir)
	if err != nil {
		return "", err
	}
	if runID == "" || filepath.Base(runID) != runID || runID == "." || runID == ".." {
		return "", fmt.Errorf("permission files: bad run id")
	}
	dir := filepath.Join(root, "cli", botID, "perm", runID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	tokenPath := filepath.Join(dir, "mcp-perm.token")
	scriptPath := filepath.Join(dir, "mcp-perm-headers")
	cfgPath := filepath.Join(dir, "mcp.json")
	if err := writeOwnerFile(tokenPath, []byte(token)); err != nil {
		removePermFiles(dir)
		return "", err
	}
	if err := writeOwnerFile(scriptPath, []byte(permHeaderScript)); err != nil {
		removePermFiles(dir)
		return "", err
	}
	helper := "/bin/sh " + quoteShell(scriptPath) + " " + quoteShell(tokenPath)
	payload := map[string]any{
		"mcpServers": map[string]any{
			"lgbperm": map[string]any{
				"type":          "http",
				"url":           strings.TrimRight(base, "/") + "/api/mcp/permission",
				"headersHelper": helper,
			},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		removePermFiles(dir)
		return "", err
	}
	if strings.Contains(string(raw), token) {
		removePermFiles(dir)
		return "", fmt.Errorf("mcp config would contain the permission token")
	}
	if err := writeOwnerFile(cfgPath, raw); err != nil {
		removePermFiles(dir)
		return "", err
	}
	return cfgPath, nil
}

// removePermMCP deletes one run's permission files and directory. The bot's
// state directory and CLI settings stay.
func (a *App) removePermMCP(botID, runID string) {
	root, err := filepath.Abs(a.cfg.DataDir)
	if err != nil {
		return
	}
	dir := filepath.Join(root, "cli", botID, "perm", runID)
	removePermFiles(dir)
	_ = os.Remove(dir)
}

func removePermFiles(dir string) {
	for _, name := range []string{"mcp-perm.token", "mcp-perm-headers", "mcp.json"} {
		_ = os.Remove(filepath.Join(dir, name))
	}
}

func writeOwnerFile(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(body)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is not private", filepath.Base(path))
	}
	return nil
}

func quoteShell(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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

func (a *App) permTokenList() []string {
	if a == nil {
		return nil
	}
	a.permMu.Lock()
	defer a.permMu.Unlock()
	out := make([]string, 0, len(a.permTokens))
	for token := range a.permTokens {
		out = append(out, token)
	}
	return out
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

// mcpPermToken prefers a 64-hex path segment. Otherwise it takes a Bearer
// token, which is how headersHelper authenticates without putting the
// secret on the CLI command line.
func mcpPermToken(r *http.Request) string {
	if tok := r.PathValue("token"); permTokenOK(tok) {
		return tok
	}
	if tok, ok := bearerToken(r); ok && permTokenOK(tok) {
		return tok
	}
	return ""
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
		Decision    string                     `json:"decision"`
		Answers     map[string]string          `json:"answers"`
		Annotations map[string]permission.Note `json:"annotations"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if a.perm == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	botID, runID, reqID := r.PathValue("id"), r.PathValue("run_id"), r.PathValue("req_id")
	var err error
	if strings.TrimSpace(body.Decision) == permission.Answer {
		err = a.perm.Answer(botID, runID, reqID, body.Answers, body.Annotations)
	} else {
		err = a.perm.DecideFor(botID, runID, reqID, body.Decision)
	}
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case errors.Is(err, permission.ErrDecision), errors.Is(err, permission.ErrAnswer):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	case errors.Is(err, permission.ErrDecided):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, permission.ErrSessionGrant):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
	case errors.Is(err, permission.ErrNotFound), errors.Is(err, permission.ErrMismatch):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}

func (a *App) handleMCPPermission(w http.ResponseWriter, r *http.Request) {
	token := mcpPermToken(r)
	bind, ok := a.lookupPerm(token)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	w.Header().Set("Mcp-Session-Id", token)
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
	out := a.perm.Evaluate(ctx, a.policy.Permission(), a.withUserRules(bind.botID, permission.Request{
		RunID:     bind.runID,
		BotID:     bind.botID,
		SessionID: bind.sessionID,
		Tool:      args.ToolName,
		Args:      args.Input,
		ToolUseID: args.ToolUseID,
		Transport: policy.TransportMCP,
	}))
	var text []byte
	if out.Behavior == "allow" {
		updated := args.Input
		if out.UpdatedInput != nil {
			updated = out.UpdatedInput
		}
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
