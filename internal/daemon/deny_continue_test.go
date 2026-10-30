package daemon

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestGolden_DenyNeverStopsRun_Ollama(t *testing.T) {
	for _, mode := range []string{"deny", "deny-all"} {
		t.Run(mode, func(t *testing.T) {
			var n atomic.Int32
			release := make(chan struct{})
			modelSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/chat" {
					http.NotFound(w, r)
					return
				}
				_, _ = io.Copy(io.Discard, r.Body)
				_ = r.Body.Close()
				w.Header().Set("Content-Type", "application/x-ndjson")
				if n.Add(1) == 1 {
					_, _ = io.WriteString(w, `{"message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"run_shell","arguments":{"command":"echo hi"}}}]},"done":true}`+"\n")
					return
				}
				<-release
				_, _ = io.WriteString(w, `{"message":{"role":"assistant","content":"continued after deny"},"done":true}`+"\n")
			}))
			t.Cleanup(modelSrv.Close)
			app := newApp(t, "", model.NewOllama(modelSrv.URL))
			app.editPol(func(p *policy.Policy) { p.Broker = "hook" })
			const token = "lgbr_admintesttokenvalue"
			app.cfg.AuthToken = token
			srv := serve(t, app)
			res, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "IO", "instructions": "shell"}, token)
			if res.StatusCode != 201 && res.StatusCode != 200 {
				t.Fatalf("create %d %s", res.StatusCode, b)
			}
			var bot store.Bot
			decodeJSON(t, b, &bot)
			res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "go"}, token)
			if res.StatusCode != 200 {
				t.Fatalf("post %d %s", res.StatusCode, b)
			}
			var id string
			deadline := time.Now().Add(8 * time.Second)
			for id == "" && time.Now().Before(deadline) {
				res, b = do(t, "GET", srv.URL+"/api/permbroker/pending", nil, token)
				if res.StatusCode != 200 {
					t.Fatalf("pending %d %s", res.StatusCode, b)
				}
				var doc struct {
					Pending []struct {
						ID string `json:"id"`
					} `json:"pending"`
				}
				decodeJSON(t, b, &doc)
				if len(doc.Pending) > 0 {
					id = doc.Pending[0].ID
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if id == "" {
				t.Fatal("run did not ask")
			}
			if mode == "deny-all" {
				res, b = do(t, "POST", srv.URL+"/api/permbroker/pending/deny-all", map[string]any{}, token)
			} else {
				res, b = do(t, "POST", srv.URL+"/api/permbroker/pending/"+id, map[string]string{"decision": "deny"}, token)
			}
			if res.StatusCode != 200 {
				t.Fatalf("decide %d %s", res.StatusCode, b)
			}
			close(release)
			waitIdle(t, srv.URL, bot.ID, token)
			got, err := app.st.GetBot(bot.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.LastRunStatus != "done" || got.LastRunError != "" || strings.Contains(got.LastRunError, "stopped after denial") {
				t.Fatalf("run %s %q", got.LastRunStatus, got.LastRunError)
			}
			saw := false
			msgs, err := app.st.ListMessages(bot.ID, "user", "", 20)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range msgs {
				if m.Role == "bot" && strings.Contains(m.Content, "continued after deny") {
					saw = true
				}
				if strings.Contains(m.Content, "Stopped after denial") {
					t.Fatalf("notice %q", m.Content)
				}
			}
			if !saw {
				t.Fatal("final text missing")
			}
		})
	}
}

func TestGolden_DenyNeverStopsRun_Grok(t *testing.T) {
	f := cardTurn(t, false, 1)
	id, _ := f.waitCard()
	f.decide(id, "deny")
	got := f.waitDone()
	if got.LastRunStatus != "done" || got.LastRunError != "" || strings.Contains(got.LastRunError, "stopped after denial") {
		t.Fatalf("run %s %q", got.LastRunStatus, got.LastRunError)
	}
	saw := false
	msgs, err := f.app.st.ListMessages(f.bot.ID, "user", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if strings.Contains(m.Content, "Stopped after denial") {
			t.Fatalf("notice %q", m.Content)
		}
		if m.Role == "bot" && strings.Contains(m.Content, "continued after deny") {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("thread %+v", msgs)
	}
}

func TestGolden_DenyNeverStopsRun_Claude(t *testing.T) {
	t.Run("broker", func(t *testing.T) {
		h := startBrokerClaude(t, builtHook(t), "hook")
		ran := h.post(t)
		if ran.status != "done" || ran.errText != "" || strings.Contains(ran.errText, "stopped after denial") {
			t.Fatalf("run %s %q", ran.status, ran.errText)
		}
		if !strings.Contains(ran.reply, "continued") {
			t.Fatalf("reply %q", ran.reply)
		}
		const token = "lgbr_admintesttokenvalue"
		h.app.cfg.AuthToken = token
		res, body := do(t, "POST", h.srv.URL+"/api/permbroker/pending/deny-all", map[string]any{}, token)
		if res.StatusCode != 200 {
			t.Fatalf("deny-all %d %s", res.StatusCode, body)
		}
		got, err := h.app.st.GetBot(h.bot.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.LastRunStatus != "done" || strings.Contains(got.LastRunError, "stopped after denial") {
			t.Fatalf("after deny-all %s %q", got.LastRunStatus, got.LastRunError)
		}
	})
	t.Run("card", func(t *testing.T) {
		app, base, botID, runID := startPendingRun(t, 20*time.Second)
		tok := app.cfg.AuthToken
		var id string
		deadline := time.Now().Add(8 * time.Second)
		for id == "" && time.Now().Before(deadline) {
			list := getPending(t, base, botID, tok)
			if len(list.Pending) > 0 {
				id = list.Pending[0].ID
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if id == "" {
			t.Fatal("card did not open")
		}
		decide := base + "/api/bots/" + botID + "/runs/" + runID + "/permissions/" + id
		res, b := do(t, "POST", decide, map[string]any{"decision": "deny"}, tok)
		if res.StatusCode != 200 {
			t.Fatalf("deny %d %s", res.StatusCode, b)
		}
		waitIdle(t, base, botID, tok)
		got, err := app.st.GetBot(botID)
		if err != nil {
			t.Fatal(err)
		}
		if got.LastRunStatus != "done" || got.LastRunError != "" || strings.Contains(got.LastRunError, "stopped after denial") {
			t.Fatalf("run %s %q", got.LastRunStatus, got.LastRunError)
		}
		saw := false
		for _, m := range thread(t, base, botID, tok) {
			if strings.Contains(m.Content, "Stopped after denial") {
				t.Fatalf("notice %q", m.Content)
			}
			if m.Role == "bot" && strings.Contains(m.Content, "continued after deny") {
				saw = true
			}
		}
		if !saw {
			t.Fatal("reply missing")
		}
	})
}
