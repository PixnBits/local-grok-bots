package daemon

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// permApplyHook is a test injection point. Stage is before_files or after_files.
var permApplyHook func(stage string) error

var writeNativeRules = permission.WriteNativeRules

func (a *App) userRules(botID string) []permission.UserRule {
	if a == nil || a.st == nil || botID == "" {
		return nil
	}
	rows, err := a.st.ListUserPermRules(botID)
	if err != nil {
		return nil
	}
	out := make([]permission.UserRule, 0, len(rows))
	for _, r := range rows {
		out = append(out, permission.UserRule{ID: r.ID, Effect: r.Effect, Pattern: r.Pattern})
	}
	return out
}

func (a *App) botWorkspace(botID string) string {
	if a == nil {
		return ""
	}
	if a.ws == "" || botID == "" || strings.Contains(botID, "/") || strings.Contains(botID, `\`) || strings.Contains(botID, "..") {
		return a.ws
	}
	return filepath.Join(a.ws, "bots", botID)
}

func (a *App) withUserRules(botID string, req permission.Request) permission.Request {
	req.UserRules = a.userRules(botID)
	if req.Workspace == "" {
		req.Workspace = a.botWorkspace(botID)
	}
	return req
}

func (a *App) syncNativeRules(botID string) error {
	if a == nil || a.st == nil || a.cfg.DataDir == "" {
		return nil
	}
	if botID == "" || strings.Contains(botID, "/") || strings.Contains(botID, `\`) || strings.Contains(botID, "..") {
		return errors.New("invalid bot id")
	}
	rows, err := a.st.ListUserPermRules(botID)
	if err != nil {
		return err
	}
	return a.writeNativeFrom(botID, rows)
}

func (a *App) writeNativeFrom(botID string, rows []store.UserPermRule) error {
	if a == nil || a.cfg.DataDir == "" {
		return nil
	}
	if botID == "" || strings.Contains(botID, "/") || strings.Contains(botID, `\`) || strings.Contains(botID, "..") {
		return errors.New("invalid bot id")
	}
	rules := make([]permission.NativeRule, 0, len(rows))
	for _, r := range rows {
		rules = append(rules, permission.NativeRule{Effect: r.Effect, Pattern: r.Pattern})
	}
	return writeNativeRules(filepath.Join(a.cfg.DataDir, "cli", botID), rules)
}

func (a *App) nativeDir(botID string) string {
	if a == nil || a.cfg.DataDir == "" || botID == "" {
		return ""
	}
	return filepath.Join(a.cfg.DataDir, "cli", botID)
}

type nativeFileSnap struct {
	present bool
	data    []byte
}

type nativeSnap struct {
	dir   string
	files map[string]nativeFileSnap
}

func snapshotNative(dir string) nativeSnap {
	s := nativeSnap{dir: dir, files: map[string]nativeFileSnap{}}
	if dir == "" {
		return s
	}
	for _, name := range []string{"user-permissions.json", "grok-permission-rules"} {
		p := filepath.Join(dir, name)
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() {
			s.files[name] = nativeFileSnap{}
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			s.files[name] = nativeFileSnap{}
			continue
		}
		s.files[name] = nativeFileSnap{present: true, data: append([]byte(nil), b...)}
	}
	return s
}

func restoreNative(s nativeSnap) {
	if s.dir == "" {
		return
	}
	for name, f := range s.files {
		p := filepath.Join(s.dir, name)
		if !f.present {
			st, err := os.Lstat(p)
			if err == nil && st.Mode().IsRegular() {
				_ = os.Remove(p)
			}
			continue
		}
		_ = clisession.WriteFileInDir(s.dir, name, f.data, 0o600)
	}
}

func (a *App) applyNativeWrite(botID string, rows []store.UserPermRule) error {
	if permApplyHook != nil {
		if err := permApplyHook("before_files"); err != nil {
			return err
		}
	}
	if err := a.writeNativeFrom(botID, rows); err != nil {
		return err
	}
	if permApplyHook != nil {
		return permApplyHook("after_files")
	}
	return nil
}

func (a *App) noteAutoSuggest(botID string) {
	if a == nil || a.st == nil || botID == "" {
		return
	}
	samples, err := a.st.ListPermSamples(botID, 200)
	if err != nil {
		return
	}
	a.saveCards(botID, permission.Suggest(permSamples(samples), a.botWorkspace(botID)), permission.SuggestAfter)
}

func (a *App) saveCards(botID string, cards []permission.Card, min int) {
	active := map[string]bool{}
	if rows, err := a.st.ListUserPermRules(botID); err == nil {
		for _, r := range rows {
			active[r.Effect+"\x00"+r.Pattern] = true
		}
	}
	for _, c := range cards {
		if c.Count < min || c.Pattern == "" {
			continue
		}
		if active["allow\x00"+c.Pattern] {
			continue
		}
		status := "pending"
		if c.Refused {
			status = "refused"
		}
		_, _ = a.st.SaveSuggestion(store.PermSuggestion{
			BotID: botID, Pattern: c.Pattern, Effect: c.Effect,
			Classification: c.Class.Kind, Sensitivity: c.Class.Sensitivity, Risk: c.Class.Risk,
			Count: c.Count, Examples: c.Examples, Summary: c.Summary, Status: status,
		})
	}
}

func permSamples(rows []store.PermSample) []permission.Sample {
	out := make([]permission.Sample, 0, len(rows))
	for _, row := range rows {
		args := map[string]any{}
		if len(row.Arguments) > 0 {
			_ = json.Unmarshal(row.Arguments, &args)
		}
		out = append(out, permission.Sample{Tool: row.Tool, Args: args})
	}
	return out
}

func (a *App) handleListPermRules(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.st.GetBot(id); err != nil {
		writeErr(w, err)
		return
	}
	rules, err := a.st.ListUserPermRules(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func (a *App) handleCreatePermRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.st.GetBot(id); err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Effect  string `json:"effect"`
		Pattern string `json:"pattern"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	rule, ok := a.acceptPermRule(w, id, body.Effect, body.Pattern)
	if !ok {
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (a *App) handleDeletePermRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ruleID := r.PathValue("rule_id")
	if _, err := a.st.GetBot(id); err != nil {
		writeErr(w, err)
		return
	}
	if _, err := a.commitRevokePermRule(id, ruleID); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleListPermSuggestions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.st.GetBot(id); err != nil {
		writeErr(w, err)
		return
	}
	rows, err := a.st.ListPermSuggestions(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"suggestions": rows})
}

func (a *App) handleAnalyzePerms(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.st.GetBot(id); err != nil {
		writeErr(w, err)
		return
	}
	samples, err := a.st.ListPermSamples(id, 200)
	if err != nil {
		writeErr(w, err)
		return
	}
	a.saveCards(id, permission.Suggest(permSamples(samples), a.botWorkspace(id)), 1)
	rows, err := a.st.ListPermSuggestions(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"suggestions": rows})
}

func (a *App) handleAcceptSuggestion(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sug, err := a.st.GetPermSuggestion(id, r.PathValue("sug_id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	if sug.Status != "pending" && sug.Status != "refused" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "suggestion is not open"})
		return
	}
	body := struct {
		Effect  string `json:"effect"`
		Pattern string `json:"pattern"`
	}{Effect: sug.Effect, Pattern: sug.Pattern}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if v, ok := raw["effect"]; ok {
		_ = json.Unmarshal(v, &body.Effect)
	}
	if v, ok := raw["pattern"]; ok {
		_ = json.Unmarshal(v, &body.Pattern)
	}
	if sug.Status == "refused" && sameRulePattern(body.Pattern, sug.Pattern) && strings.EqualFold(strings.TrimSpace(body.Effect), "allow") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": sug.Summary})
		return
	}
	rule, ok := a.acceptPermRule(w, id, body.Effect, body.Pattern)
	if !ok {
		return
	}
	if _, err := a.st.DecidePermSuggestion(id, sug.ID, "accepted"); err != nil && !errors.Is(err, store.ErrNotFound) {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (a *App) handleDismissSuggestion(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.st.DecidePermSuggestion(id, r.PathValue("sug_id"), "dismissed"); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) acceptPermRule(w http.ResponseWriter, botID, effect, pattern string) (store.UserPermRule, bool) {
	class, err := permission.CheckUserRule(effect, pattern, a.botWorkspace(botID))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return store.UserPermRule{}, false
	}
	effect = strings.ToLower(strings.TrimSpace(effect))
	pattern = strings.TrimSpace(pattern)
	draft := store.UserPermRule{
		BotID: botID, Effect: effect, Pattern: pattern,
		Classification: class.Kind, Sensitivity: class.Sensitivity, Risk: class.Risk, Reason: class.Reason,
	}
	rule, err := a.commitAcceptPermRule(draft)
	if errors.Is(err, store.ErrConflict) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "rule already exists"})
		return store.UserPermRule{}, false
	}
	if err != nil {
		writeErr(w, err)
		return store.UserPermRule{}, false
	}
	return rule, true
}

func (a *App) commitAcceptPermRule(rule store.UserPermRule) (store.UserPermRule, error) {
	dir := a.nativeDir(rule.BotID)
	snap := snapshotNative(dir)
	audit := map[string]any{
		"action": "accept", "effect": rule.Effect, "pattern": rule.Pattern,
		"risk": rule.Risk, "classification": rule.Classification, "sensitivity": rule.Sensitivity,
	}
	out, err := a.st.AcceptUserPermRule(rule, audit, func(rows []store.UserPermRule) error {
		return a.applyNativeWrite(rule.BotID, rows)
	})
	if err != nil {
		restoreNative(snap)
		return store.UserPermRule{}, err
	}
	return out, nil
}

func (a *App) commitRevokePermRule(botID, ruleID string) (store.UserPermRule, error) {
	dir := a.nativeDir(botID)
	snap := snapshotNative(dir)
	out, err := a.st.RevokeUserPermRuleApply(botID, ruleID, nil, func(rows []store.UserPermRule) error {
		return a.applyNativeWrite(botID, rows)
	})
	if err != nil {
		restoreNative(snap)
		return store.UserPermRule{}, err
	}
	return out, nil
}

func sameRulePattern(a, b string) bool {
	return normRulePattern(a) == normRulePattern(b)
}

func normRulePattern(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Join(strings.Fields(s), " ")
	s = strings.ReplaceAll(s, "( ", "(")
	s = strings.ReplaceAll(s, " )", ")")
	return s
}
