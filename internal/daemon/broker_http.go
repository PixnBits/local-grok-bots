package daemon

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/permbroker"
)

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
		writeJSON(w, http.StatusOK, map[string]any{"rules": []any{}, "task_grants": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rules": a.broker.ListRules(), "task_grants": a.broker.ListTaskGrants(),
	})
}

func (a *App) handleBrokerCreateRule(w http.ResponseWriter, r *http.Request) {
	if !a.brokerPostOK(w, r) {
		return
	}
	if a.broker == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	var body struct {
		Kind    string   `json:"kind"`
		Argv    []string `json:"argv"`
		Pattern string   `json:"pattern"`
		Scope   string   `json:"scope"`
		BotID   string   `json:"bot_id"`
		Effect  string   `json:"effect"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8192))
	if err != nil || json.Unmarshal(raw, &body) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	rule, err := a.broker.CreateRule(permbroker.RuleDraft{
		Kind: body.Kind, Argv: body.Argv, Pattern: body.Pattern,
		Scope: body.Scope, BotID: body.BotID, Effect: body.Effect,
	})
	if err != nil {
		writeBrokerErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rule": rule})
}

func (a *App) handleBrokerValidatePattern(w http.ResponseWriter, r *http.Request) {
	if !a.brokerPostOK(w, r) {
		return
	}
	var body struct {
		Pattern string `json:"pattern"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8192))
	if err != nil || json.Unmarshal(raw, &body) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	ok, code, msg := permbroker.PatternStatus(body.Pattern)
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "code": code, "message": msg})
}

func (a *App) handleBrokerPatternWrappers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"wrappers": permbroker.WrapperNames()})
}

func (a *App) handleBrokerPreview(w http.ResponseWriter, r *http.Request) {
	if !a.brokerPostOK(w, r) {
		return
	}
	if a.broker == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	var body struct {
		Kind    string   `json:"kind"`
		Argv    []string `json:"argv"`
		Pattern string   `json:"pattern"`
		Scope   string   `json:"scope"`
		BotID   string   `json:"bot_id"`
		Effect  string   `json:"effect"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8192))
	if err != nil || json.Unmarshal(raw, &body) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	prev, err := a.broker.Preview(permbroker.RuleDraft{
		Kind: body.Kind, Argv: body.Argv, Pattern: body.Pattern,
		Scope: body.Scope, BotID: body.BotID, Effect: body.Effect,
	})
	if err != nil {
		writeBrokerErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, prev)
}

func (a *App) handleBrokerRiskTables(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.broker.RiskTables())
}

func (a *App) handleBrokerRecent(w http.ResponseWriter, r *http.Request) {
	if a.broker == nil {
		writeJSON(w, http.StatusOK, map[string]any{"recent": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recent": a.broker.Recent()})
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
	id := r.PathValue("id")
	if err := a.broker.RevokeRule(id); err != nil {
		writeBrokerErr(w, err)
		return
	}
	if a.audit != nil && a.audit.Enabled() {
		a.audit.Write(map[string]any{
			"event": "permbroker", "action": "rule_revoke", "rule_id": id,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleBrokerPending(w http.ResponseWriter, r *http.Request) {
	if a.broker == nil {
		writeJSON(w, http.StatusOK, map[string]any{"pending": []any{}})
		return
	}
	items := a.broker.ListPending()
	for i := range items {
		items[i].BotName = a.brokerBotName(items[i].BotID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"pending": items})
}

func (a *App) brokerBotName(id string) string {
	if a == nil || a.st == nil || id == "" {
		return id
	}
	bot, err := a.st.GetBot(id)
	if err != nil || strings.TrimSpace(bot.Name) == "" {
		return id
	}
	return bot.Name
}

func (a *App) handleBrokerDenyAll(w http.ResponseWriter, r *http.Request) {
	if !a.brokerPostOK(w, r) {
		return
	}
	if a.broker == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "pending item not found"})
		return
	}
	ids, ok := brokerBatchIDs(w, r)
	if !ok {
		return
	}
	rep, err := a.broker.DenyAll(ids)
	if err != nil {
		writeBrokerErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (a *App) handleBrokerApproveAll(w http.ResponseWriter, r *http.Request) {
	if !a.brokerPostOK(w, r) {
		return
	}
	if a.broker == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "pending item not found"})
		return
	}
	ids, ok := brokerBatchIDs(w, r)
	if !ok {
		return
	}
	rep, err := a.broker.ApproveAll(ids)
	if err != nil {
		writeBrokerErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func brokerBatchIDs(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
	if err != nil || len(strings.TrimSpace(string(body))) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ids required"})
		return nil, false
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if json.Unmarshal(body, &req) != nil || len(req.IDs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ids required"})
		return nil, false
	}
	return req.IDs, true
}

func (a *App) handleBrokerReplaceRule(w http.ResponseWriter, r *http.Request) {
	if !a.brokerPostOK(w, r) {
		return
	}
	if a.broker == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	var body struct {
		Kind    string   `json:"kind"`
		Argv    []string `json:"argv"`
		Pattern string   `json:"pattern"`
		Scope   string   `json:"scope"`
		BotID   string   `json:"bot_id"`
		Effect  string   `json:"effect"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8192))
	if err != nil || json.Unmarshal(raw, &body) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	created, revoked, err := a.broker.ReplaceRule(r.PathValue("id"), permbroker.RuleDraft{
		Kind: body.Kind, Argv: body.Argv, Pattern: body.Pattern,
		Scope: body.Scope, BotID: body.BotID, Effect: body.Effect,
	})
	if created == "" {
		writeBrokerErr(w, err)
		return
	}
	status := http.StatusOK
	payload := map[string]any{"created": created, "revoked": revoked}
	if !revoked {
		status = http.StatusMultiStatus
		if err != nil {
			payload["error"] = err.Error()
		}
	}
	writeJSON(w, status, payload)
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
	if id == "approve-all" {
		a.handleBrokerApproveAll(w, r)
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
	var input *permbroker.InputError
	switch {
	case errors.As(err, &input):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": input.Error(), "code": input.Code})
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
