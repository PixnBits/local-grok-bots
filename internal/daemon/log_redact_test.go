package daemon

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestModelCallLogHidesTokens(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("A1b2", 9)
	ant := "sk-" + "ant-" + strings.Repeat("a1", 8)
	app := newApp(t, t.TempDir(), fakeModel{})
	bot, err := app.st.CreateBot("Ada", "help", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	callErr := fmt.Errorf("upstream rejected %s and %s", ghp, ant)
	app.logOllamaCall(bot.ID, "test-model", false, 1, false, 0, callErr, 0, "", "", nil)

	raw := map[string]any{
		"error": ghp + " " + ant,
		"nested": map[string]any{
			"note": ant,
			"list": []any{ghp},
		},
		"names": []string{ant},
	}
	app.log(bot.ID, "model_call", raw)
	if raw["error"] != ghp+" "+ant {
		t.Fatal("caller map was modified")
	}
	nested := raw["nested"].(map[string]any)
	if nested["note"] != ant || nested["list"].([]any)[0] != ghp || raw["names"].([]string)[0] != ant {
		t.Fatal("caller map was modified")
	}

	events, err := app.st.ListLog(bot.ID, "model_call", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("model_call rows %d", len(events))
	}
	var sawOllama bool
	for _, ev := range events {
		body := string(ev.Detail)
		if strings.Contains(body, ghp) || strings.Contains(body, ant) {
			t.Fatalf("stored row leaked %s", body)
		}
		var detail map[string]any
		if err := json.Unmarshal(ev.Detail, &detail); err != nil {
			t.Fatal(err)
		}
		errText, ok := detail["error"].(string)
		if !ok || errText == "" {
			t.Fatalf("missing error field %s", body)
		}
		if !strings.Contains(errText, "[redacted]") {
			t.Fatalf("error not redacted %q", errText)
		}
		if detail["model"] == "test-model" {
			sawOllama = true
			if !strings.Contains(errText, "upstream rejected") {
				t.Fatalf("ollama error %q", errText)
			}
		}
	}
	if !sawOllama {
		t.Fatal("model_call row from logOllamaCall missing")
	}

	srv := serve(t, app)
	res, body := do(t, "GET", srv.URL+"/api/log?kind=model_call&limit=20", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("status %d %s", res.StatusCode, body)
	}
	if strings.Contains(string(body), ghp) || strings.Contains(string(body), ant) {
		t.Fatalf("GET /api/log leaked %s", body)
	}
	var listed []store.LogEvent
	decodeJSON(t, body, &listed)
	if len(listed) != 2 {
		t.Fatalf("api rows %d %s", len(listed), body)
	}
}
