package daemon

import (
	"strings"
	"testing"
)

func TestBroadHostWarning(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	srv := serve(t, app)
	plain := createBot(t, srv.URL, "Plain")
	wide := createBot(t, srv.URL, "Wide")
	res, b := do(t, "PATCH", srv.URL+"/api/bots/"+wide.ID, map[string]any{
		"net_allow": []string{"storage.googleapis.com"},
	}, "")
	if res.StatusCode != 200 {
		t.Fatalf("patch %d %s", res.StatusCode, b)
	}
	const want = "storage.googleapis.com gives this bot access to all of Google Cloud Storage, not just your project. Remove it unless the bot needs it."
	const href = "https://github.com/PixnBits/local-grok-bots/issues/33"
	const label = "Why this matters (GitHub issue #33)"
	plainBot := fetchBot(t, srv.URL, plain.ID)
	if len(plainBot.Warnings) != 0 {
		t.Fatalf("plain warnings %+v", plainBot.Warnings)
	}
	_, plainBody := do(t, "GET", srv.URL+"/api/bots/"+plain.ID, nil, "")
	if strings.Contains(string(plainBody), `"warnings"`) {
		t.Fatalf("plain bot included warnings: %s", plainBody)
	}
	one := fetchBot(t, srv.URL, wide.ID)
	if len(one.Warnings) != 1 || one.Warnings[0].Field != "net_allow" || one.Warnings[0].Text != want || one.Warnings[0].Link == nil || one.Warnings[0].Link.Href != href || one.Warnings[0].Link.Label != label {
		t.Fatalf("get warnings %+v", one.Warnings)
	}
	if strings.Contains(one.Warnings[0].Text, "docs/sandbox.md") || strings.Contains(one.Warnings[0].Text, "https://") || strings.Contains(one.Warnings[0].Text, "Saving still works") {
		t.Fatalf("host text %q", one.Warnings[0].Text)
	}
	_, listBody := do(t, "GET", srv.URL+"/api/bots", nil, "")
	if !strings.Contains(string(listBody), want) || strings.Count(string(listBody), "gives this bot access to all of Google Cloud Storage") != 1 || strings.Count(string(listBody), href) != 1 {
		t.Fatalf("list %s", listBody)
	}
	_, stateBody := do(t, "GET", srv.URL+"/api/bots/"+wide.ID+"/state", nil, "")
	if !strings.Contains(string(stateBody), want) || !strings.Contains(string(stateBody), href) || !strings.Contains(string(stateBody), label) {
		t.Fatalf("state %s", stateBody)
	}
	_, plainState := do(t, "GET", srv.URL+"/api/bots/"+plain.ID+"/state", nil, "")
	if strings.Contains(string(plainState), "storage.googleapis.com") {
		t.Fatalf("plain state %s", plainState)
	}
}
