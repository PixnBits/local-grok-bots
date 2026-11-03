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
	const want = "storage.googleapis.com is on net_allow. It reaches all of Google Cloud Storage, not one project. See docs/sandbox.md and https://github.com/PixnBits/local-grok-bots/issues/33."
	if joined := strings.Join(fetchBot(t, srv.URL, plain.ID).Warnings, "\n"); strings.Contains(joined, "storage.googleapis.com") {
		t.Fatalf("plain warnings %q", joined)
	}
	one := fetchBot(t, srv.URL, wide.ID)
	if !strings.Contains(strings.Join(one.Warnings, "\n"), want) {
		t.Fatalf("get warnings %q", one.Warnings)
	}
	_, listBody := do(t, "GET", srv.URL+"/api/bots", nil, "")
	if !strings.Contains(string(listBody), want) || strings.Count(string(listBody), "storage.googleapis.com is on net_allow") != 1 {
		t.Fatalf("list %s", listBody)
	}
	_, stateBody := do(t, "GET", srv.URL+"/api/bots/"+wide.ID+"/state", nil, "")
	if !strings.Contains(string(stateBody), want) {
		t.Fatalf("state %s", stateBody)
	}
	_, plainState := do(t, "GET", srv.URL+"/api/bots/"+plain.ID+"/state", nil, "")
	if strings.Contains(string(plainState), "storage.googleapis.com") {
		t.Fatalf("plain state %s", plainState)
	}
}
