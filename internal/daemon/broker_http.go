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
	return p == "/api/permbroker/pending" || strings.HasPrefix(p, "/api/permbroker/pending/") || p == "/api/permbroker/hook/repin"
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
	case errors.Is(err, permbroker.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, permbroker.ErrScope), errors.Is(err, permbroker.ErrBadDecision):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
	}
}
