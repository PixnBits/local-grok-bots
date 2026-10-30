package daemon

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/permbroker"
)

func brokerAdminPath(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	p := r.URL.Path
	if p == "/api/permbroker/pending" || strings.HasPrefix(p, "/api/permbroker/pending/") || p == "/api/permbroker/hook/repin" || p == "/api/permbroker/rules" || strings.HasPrefix(p, "/api/permbroker/rules/") {
		return true
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	return len(parts) == 5 && parts[0] == "api" && parts[1] == "permbroker" && parts[2] == "bots" && parts[3] != "" && parts[4] == "git-baseline"
}

func (a *App) brokerPostOK(w http.ResponseWriter, r *http.Request) bool {
	if sttCrossSite(r) || !a.originAllowed(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return false
	}
	return true
}

func (a *App) handleBrokerRepin(w http.ResponseWriter, r *http.Request) {
	if !a.brokerPostOK(w, r) {
		return
	}
	if err := a.repinBrokerHook(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hook cannot be pinned"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleBrokerRules(w http.ResponseWriter, r *http.Request) {
	if a.broker == nil {
		writeJSON(w, http.StatusOK, map[string]any{"rules": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": a.broker.ListRules()})
}

func (a *App) handleBrokerConfirmRule(w http.ResponseWriter, r *http.Request) {
	if !a.brokerPostOK(w, r) {
		return
	}
	if a.broker == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
		return
	}
	id := r.PathValue("id")
	sum, err := a.broker.ConfirmRule(id)
	if err != nil {
		writeBrokerErr(w, err)
		return
	}
	if a.audit != nil && a.audit.Enabled() {
		a.audit.Write(map[string]any{
			"event": "permbroker", "action": "rule_confirm",
			"rule_id": id, "input_hash": sum,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleBrokerGitBaseline(w http.ResponseWriter, r *http.Request) {
	if !a.brokerPostOK(w, r) {
		return
	}
	if a.broker == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "pending item not found"})
		return
	}
	id := r.PathValue("id")
	if err := a.broker.RebaselineBot(id); err != nil {
		writeBrokerErr(w, err)
		return
	}
	if a.audit != nil && a.audit.Enabled() {
		a.audit.Write(map[string]any{
			"event": "permbroker", "action": "git_rebaseline", "bot_id": id,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleBrokerRevokeRule(w http.ResponseWriter, r *http.Request) {
	if !a.brokerPostOK(w, r) {
		return
	}
	if a.broker == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
		return
	}
	if err := a.broker.RevokeRule(r.PathValue("id")); err != nil {
		writeBrokerErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleBrokerPending(w http.ResponseWriter, r *http.Request) {
	if a.broker == nil {
		writeJSON(w, http.StatusOK, map[string]any{"pending": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pending": a.broker.ListPending()})
}

func (a *App) handleBrokerDenyAll(w http.ResponseWriter, r *http.Request) {
	if !a.brokerPostOK(w, r) {
		return
	}
	if a.broker == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "pending item not found"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	var req struct {
		IDs *[]string `json:"ids"`
	}
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
	}
	var ids []string
	if req.IDs != nil {
		ids = *req.IDs
	} else {
		ids = nil
	}
	if err := a.broker.DenyAll(ids); err != nil {
		writeBrokerErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleBrokerDecide(w http.ResponseWriter, r *http.Request) {
	if !a.brokerPostOK(w, r) {
		return
	}
	id := r.PathValue("id")
	if id == "deny-all" {
		a.handleBrokerDenyAll(w, r)
		return
	}
	if a.broker == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "pending item not found"})
		return
	}
	var req struct {
		Decision string `json:"decision"`
		Scope    string `json:"scope"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
	if err != nil || json.Unmarshal(body, &req) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if err := a.broker.Decide(id, strings.TrimSpace(req.Decision), strings.TrimSpace(req.Scope)); err != nil {
		writeBrokerErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func writeBrokerErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, permbroker.ErrStale):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, permbroker.ErrNotFound), errors.Is(err, permbroker.ErrRuleNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, permbroker.ErrScope), errors.Is(err, permbroker.ErrBadDecision), errors.Is(err, permbroker.ErrNotConfirmable):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
	}
}
