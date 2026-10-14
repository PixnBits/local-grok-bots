package daemon

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/store"
	"github.com/PixnBits/local-grok-bots/web"
)

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", a.handleHealth)
	mux.HandleFunc("GET /api/bots", a.handleListBots)
	mux.HandleFunc("POST /api/bots", a.handleCreateBot)
	mux.HandleFunc("GET /api/bots/{id}", a.handleGetBot)
	mux.HandleFunc("PATCH /api/bots/{id}", a.handlePatchBot)
	mux.HandleFunc("DELETE /api/bots/{id}", a.handleDeleteBot)
	mux.HandleFunc("GET /api/bots/{id}/thread", a.handleThread)
	mux.HandleFunc("POST /api/bots/{id}/thread/messages", a.handlePostMessage)
	mux.HandleFunc("GET /api/bots/{id}/thread/stream", a.handleStream)
	mux.HandleFunc("POST /api/bots/{id}/runs/{run_id}/cancel", a.handleCancel)
	mux.HandleFunc("POST /api/bots/{id}/runs/{run_id}/continue", a.handleContinue)
	mux.HandleFunc("GET /api/bots/{id}/memory", a.handleListMemory)
	mux.HandleFunc("POST /api/bots/{id}/memory", a.handlePutMemory)
	mux.HandleFunc("DELETE /api/bots/{id}/memory/{key}", a.handleDeleteMemory)
	mux.HandleFunc("GET /api/bots/{id}/timers", a.handleListTimers)
	mux.HandleFunc("POST /api/bots/{id}/timers", a.handleCreateTimer)
	mux.HandleFunc("PATCH /api/timers/{id}", a.handlePatchTimer)
	mux.HandleFunc("DELETE /api/timers/{id}", a.handleDeleteTimer)
	mux.HandleFunc("GET /api/bots/{id}/dms", a.handleDMs)
	mux.HandleFunc("GET /api/dms/{bot_a}/{bot_b}", a.handleDMThread)
	mux.HandleFunc("GET /api/log", a.handleLog)
	mux.HandleFunc("GET /", a.handleIndex)
	mux.HandleFunc("GET /index.html", a.handleIndex)
	// A bot's page. The client reads the id from the path.
	mux.HandleFunc("GET /bots/{id}", a.handleIndex)
	return a.withAuth(mux)
}

func (a *App) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" || a.cfg.AuthToken == "" || authorized(r, a.cfg.AuthToken) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/index.html" || strings.HasPrefix(r.URL.Path, "/bots/")) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write(web.IndexHTML)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	})
}

func authorized(r *http.Request, token string) bool {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return false
	}
	got := h[len(prefix):]
	if len(got) != len(token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": a.cfg.Version})
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(web.IndexHTML)
}

func (a *App) handleListBots(w http.ResponseWriter, r *http.Request) {
	bots, err := a.st.ListBots()
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a.decorateBots(bots))
}

func (a *App) handleCreateBot(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name         string      `json:"name"`
		Label        string      `json:"label"`
		Description  *string     `json:"description"`
		Instructions *string     `json:"instructions"`
		Mark         *store.Mark `json:"mark"`
		Model        *string     `json:"model"`
		Grants       []string    `json:"grants"`
		NetAllow     []string    `json:"net_allow"`
		SSHAllow     []string    `json:"ssh_allow"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	name, err := cleanName(body.Name)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	description := firstText(body.Description, body.Instructions)
	if len(description) > 100_000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "description too long"})
		return
	}
	var modelPtr *string
	if body.Model != nil && strings.TrimSpace(*body.Model) != "" {
		m := strings.TrimSpace(*body.Model)
		modelPtr = &m
	}
	mark := store.Mark{}
	if body.Mark != nil {
		mark = *body.Mark
	}
	b, err := a.st.InsertBot(store.BotDraft{
		Name: name, Label: body.Label, Description: description, Mark: mark, Model: modelPtr,
		Grants: body.Grants, NetAllow: body.NetAllow, SSHAllow: body.SSHAllow,
	}, "user")
	if err != nil {
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, a.decorateBot(b))
}

func firstText(primary, alias *string) string {
	if primary != nil {
		return *primary
	}
	if alias != nil {
		return *alias
	}
	return ""
}

func (a *App) handleGetBot(w http.ResponseWriter, r *http.Request) {
	b, err := a.st.GetBot(r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a.decorateBot(b))
}

func (a *App) handlePatchBot(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	raw, err := readMap(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	patch := store.BotPatch{By: "user"}
	if v, ok := raw["name"]; ok {
		var name string
		if err := json.Unmarshal(v, &name); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid name"})
			return
		}
		name, err = cleanName(name)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		patch.Name = &name
	}
	if v, ok := raw["label"]; ok {
		var label string
		if err := json.Unmarshal(v, &label); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid label"})
			return
		}
		patch.Label = &label
	}
	if v, ok := raw["description"]; ok {
		desc, err := decodeText(v, "description")
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		patch.Description = &desc
	} else if v, ok := raw["instructions"]; ok {
		desc, err := decodeText(v, "description")
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		patch.Description = &desc
	}
	if v, ok := raw["mark"]; ok {
		var mark store.Mark
		if err := json.Unmarshal(v, &mark); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mark"})
			return
		}
		patch.Mark = &mark
	}
	if v, ok := raw["pinned"]; ok {
		var pinned bool
		if err := json.Unmarshal(v, &pinned); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid pinned"})
			return
		}
		patch.Pinned = &pinned
	}
	if v, ok := raw["hidden"]; ok {
		var hidden bool
		if err := json.Unmarshal(v, &hidden); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid hidden"})
			return
		}
		patch.Hidden = &hidden
	}
	if v, ok := raw["grants"]; ok {
		list, err := decodeStringList(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid grants"})
			return
		}
		patch.GrantsSet = true
		patch.Grants = list
	}
	if v, ok := raw["net_allow"]; ok {
		list, err := decodeStringList(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid net_allow"})
			return
		}
		patch.NetSet = true
		patch.NetAllow = list
	}
	if v, ok := raw["ssh_allow"]; ok {
		list, err := decodeStringList(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ssh_allow"})
			return
		}
		patch.SSHSet = true
		patch.SSHAllow = list
	}
	if v, ok := raw["model"]; ok {
		patch.ModelSet = true
		if string(v) != "null" {
			var m string
			if err := json.Unmarshal(v, &m); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid model"})
				return
			}
			m = strings.TrimSpace(m)
			if m != "" {
				patch.Model = &m
			}
		}
	}
	var archived *bool
	if v, ok := raw["archived"]; ok {
		var on bool
		if err := json.Unmarshal(v, &on); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid archived"})
			return
		}
		archived = &on
	}
	var setIdle bool
	if v, ok := raw["status"]; ok {
		var status string
		if err := json.Unmarshal(v, &status); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid status"})
			return
		}
		switch status {
		case "idle":
			setIdle = true
			patch.Status = &status
		case "paused":
			patch.Status = &status
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be idle or paused"})
			return
		}
	}
	b, err := a.st.UpdateBot(id, patch)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrConflict) {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if archived != nil {
		if _, err := a.st.SetArchived(id, *archived, "user"); err != nil {
			writeErr(w, err)
			return
		}
		if !*archived {
			a.kick(id)
		}
	}
	if patch.Status != nil && *patch.Status == "paused" {
		a.cancelBot(id)
	}
	if setIdle {
		a.kick(id)
	}
	b, _ = a.st.GetBot(id)
	writeJSON(w, http.StatusOK, a.decorateBot(b))
}

func (a *App) handleDeleteBot(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.cancelBot(id)
	if err := a.st.DeleteBot(id, "user"); err != nil {
		writeErr(w, err)
		return
	}
	a.dropResume(id)
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleThread(w http.ResponseWriter, r *http.Request) {
	if _, err := a.st.GetBot(r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	// The newest page, oldest first. before=<message id> pages back from that
	// message. One extra row is read to tell the client whether older
	// messages remain.
	limit := queryLimit(r, 50, 200)
	msgs, err := a.st.ListMessages(r.PathValue("id"), "user", r.URL.Query().Get("before"), limit+1)
	if err != nil {
		writeErr(w, err)
		return
	}
	hasMore := len(msgs) > limit
	if hasMore {
		msgs = msgs[1:]
	}
	// tools maps each listed reply's run_id to the tool calls that run made.
	var runIDs []string
	seen := map[string]bool{}
	for _, m := range msgs {
		if m.RunID != nil && !seen[*m.RunID] {
			seen[*m.RunID] = true
			runIDs = append(runIDs, *m.RunID)
		}
	}
	tools, err := a.st.RunTools(runIDs)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": msgs, "tools": tools, "has_more": hasMore})
}

func (a *App) handlePostMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.st.GetBot(id); err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Content string `json:"content"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	content := strings.TrimSpace(body.Content)
	if content == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "content required"})
		return
	}
	if len(content) > 100_000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "content too long"})
		return
	}
	msg, err := a.st.AddMessage(store.Message{BotID: id, Thread: "user", Role: "user", Content: content})
	if err != nil {
		writeErr(w, err)
		return
	}
	a.log(id, "user_message", map[string]any{"message_id": msg.ID})
	a.dropResume(id)
	runID := a.kick(id)
	resp := map[string]any{"message": msg, "run_id": nil}
	if runID != "" {
		resp["run_id"] = runID
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) handleStream(w http.ResponseWriter, r *http.Request) {
	botID := r.PathValue("id")
	runID := r.URL.Query().Get("run_id")
	if runID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "run_id required"})
		return
	}
	run, err := a.st.GetRun(runID)
	if err != nil || run.BotID != botID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	hist, ch := a.bus.Subscribe(runID)
	defer a.bus.Unsubscribe(runID, ch)
	for _, f := range hist {
		if _, err := w.Write(f.bytes()); err != nil {
			return
		}
		flusher.Flush()
		if terminal(f.event) {
			return
		}
	}
	if run.Status != "running" {
		// Finished before any subscriber; synthesize the terminal event.
		if run.Status == "done" || run.Status == "cancelled" {
			a.writeSSE(w, flusher, "done", map[string]any{"run_id": runID})
		} else {
			errText := ""
			if run.Error != nil {
				errText = *run.Error
			}
			a.writeSSE(w, flusher, "error", map[string]any{"run_id": runID, "error": errText})
		}
		return
	}
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case f := <-ch:
			if _, err := w.Write(f.bytes()); err != nil {
				return
			}
			flusher.Flush()
			if terminal(f.event) {
				return
			}
		}
	}
}

func (a *App) writeSSE(w http.ResponseWriter, flusher http.Flusher, event string, payload any) {
	raw, _ := json.Marshal(payload)
	_, _ = w.Write([]byte("event: " + event + "\ndata: " + string(raw) + "\n\n"))
	flusher.Flush()
}

func (a *App) handleCancel(w http.ResponseWriter, r *http.Request) {
	botID := r.PathValue("id")
	runID := r.PathValue("run_id")
	run, err := a.st.GetRun(runID)
	if err != nil || run.BotID != botID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if run.Status != "running" {
		writeJSON(w, http.StatusOK, map[string]string{"status": run.Status})
		return
	}
	a.cancelBot(botID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

func (a *App) handleContinue(w http.ResponseWriter, r *http.Request) {
	runID, code, err := a.continueRun(r.PathValue("id"), r.PathValue("run_id"))
	if err != nil {
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"run_id": runID})
}

func (a *App) handleListMemory(w http.ResponseWriter, r *http.Request) {
	if _, err := a.st.GetBot(r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	mem, err := a.st.ListMemory(r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, mem)
}

func (a *App) handlePutMemory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.st.GetBot(id); err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if strings.TrimSpace(body.Key) == "" || strings.Contains(body.Key, "/") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid memory key"})
		return
	}
	m, err := a.st.UpsertMemory(id, body.Key, body.Value)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (a *App) handleDeleteMemory(w http.ResponseWriter, r *http.Request) {
	if err := a.st.DeleteMemory(r.PathValue("id"), r.PathValue("key")); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleListTimers(w http.ResponseWriter, r *http.Request) {
	if _, err := a.st.GetBot(r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	timers, err := a.st.ListTimers(r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, timers)
}

func (a *App) handleCreateTimer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.st.GetBot(id); err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Name     string `json:"name"`
		Schedule string `json:"schedule"`
		Prompt   string `json:"prompt"`
		Enabled  *bool  `json:"enabled"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if strings.TrimSpace(body.Prompt) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "prompt required"})
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	t, err := a.st.CreateTimer(id, body.Name, body.Schedule, body.Prompt, enabled)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (a *App) handlePatchTimer(w http.ResponseWriter, r *http.Request) {
	raw, err := readMap(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var p store.TimerPatch
	if v, ok := raw["name"]; ok {
		var s string
		if json.Unmarshal(v, &s) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid name"})
			return
		}
		p.Name = &s
	}
	if v, ok := raw["schedule"]; ok {
		var s string
		if json.Unmarshal(v, &s) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid schedule"})
			return
		}
		p.Schedule = &s
	}
	if v, ok := raw["prompt"]; ok {
		var s string
		if json.Unmarshal(v, &s) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid prompt"})
			return
		}
		p.Prompt = &s
	}
	if v, ok := raw["enabled"]; ok {
		var b bool
		if json.Unmarshal(v, &b) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid enabled"})
			return
		}
		p.Enabled = &b
	}
	t, err := a.st.UpdateTimer(r.PathValue("id"), p)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (a *App) handleDeleteTimer(w http.ResponseWriter, r *http.Request) {
	if err := a.st.DeleteTimer(r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleDMs(w http.ResponseWriter, r *http.Request) {
	if _, err := a.st.GetBot(r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	dms, err := a.st.ListDMs(r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dms)
}

func (a *App) handleDMThread(w http.ResponseWriter, r *http.Request) {
	aID := r.PathValue("bot_a")
	bID := r.PathValue("bot_b")
	if _, err := a.st.GetBot(aID); err != nil {
		writeErr(w, err)
		return
	}
	if _, err := a.st.GetBot(bID); err != nil {
		writeErr(w, err)
		return
	}
	limit := queryLimit(r, 50, 200)
	msgs, err := a.st.ListMessages(aID, "dm:"+bID, r.URL.Query().Get("before"), limit)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": msgs})
}

func (a *App) handleLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := queryLimit(r, 100, 500)
	events, err := a.st.ListLog(q.Get("bot_id"), q.Get("kind"), q.Get("before"), limit)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func queryLimit(r *http.Request, def, max int) int {
	s := r.URL.Query().Get("limit")
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("invalid JSON")
	}
	return nil
}

func readMap(w http.ResponseWriter, r *http.Request) (map[string]json.RawMessage, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		return nil, errors.New("invalid body")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, errors.New("invalid JSON")
	}
	return raw, nil
}

func decodeStringList(v json.RawMessage) ([]string, error) {
	if string(v) == "null" {
		return []string{}, nil
	}
	var xs []string
	if err := json.Unmarshal(v, &xs); err != nil {
		return nil, err
	}
	if xs == nil {
		xs = []string{}
	}
	return xs, nil
}

func decodeText(v json.RawMessage, field string) (string, error) {
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", errors.New("invalid " + field)
	}
	if len(s) > 100_000 {
		return "", errors.New(field + " too long")
	}
	return s, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case errors.Is(err, store.ErrConflict):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "name already exists"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}
