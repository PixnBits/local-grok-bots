package daemon

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestInterimChatSendsThinkAndNumCtx(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	modelSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			http.NotFound(w, r)
			return
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, append([]byte(nil), b...))
		n := len(bodies)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-ndjson")
		if n == 1 {
			_, _ = io.WriteString(w, `{"message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"run_shell","arguments":{"command":"echo hi"}}}]},"done":true}`+"\n")
			return
		}
		_, _ = io.WriteString(w, `{"message":{"role":"assistant","content":"interim"},"done":true}`+"\n")
	}))
	t.Cleanup(modelSrv.Close)

	clk := newManualClock()
	tool := newGateTool("shell-ok")
	app := newApp(t, "", model.NewOllama(modelSrv.URL))
	no := false
	app.editPol(func(p *policy.Policy) {
		p.EventLoop = true
		p.OllamaThink = &no
		p.OllamaNumCtx = 4242
	})
	app.eventClk = clk
	app.toolExec = tool.exec
	t.Cleanup(tool.letGo)
	base := serve(t, app).URL
	bot := createBot(t, base, "Interim")
	res, body := do(t, "PATCH", base+"/api/bots/"+bot.ID, map[string]any{"think": true, "num_ctx": 111}, "")
	if res.StatusCode != 200 {
		t.Fatalf("patch bot %d %s", res.StatusCode, body)
	}
	postUser(t, base, bot.ID, "go")
	waitCh(t, tool.started, "tool start")
	postUser(t, base, bot.ID, "while you run")
	clk.Advance(app.pol().EffectiveEventLoopQuiet())

	deadline := time.Now().Add(5 * time.Second)
	var raw []byte
	for time.Now().Before(deadline) {
		mu.Lock()
		for _, b := range bodies {
			var m map[string]any
			if json.Unmarshal(b, &m) != nil {
				continue
			}
			if _, ok := m["tools"]; ok {
				continue
			}
			raw = append([]byte(nil), b...)
		}
		mu.Unlock()
		if raw != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if raw == nil {
		t.Fatal("no interim /api/chat body")
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["think"] != false {
		t.Fatalf("interim think %#v body %s", got["think"], raw)
	}
	opts, _ := got["options"].(map[string]any)
	if opts == nil || opts["num_ctx"] != float64(4242) {
		t.Fatalf("interim options %#v body %s", got["options"], raw)
	}
}
