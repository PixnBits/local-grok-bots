package daemon

import (
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestAPINumCtxBound(t *testing.T) {
	app := newApp(t, "", &scriptModel{})
	srv := serve(t, app)
	const want = "num_ctx 1048577 must be from 1 to 1048576"
	res, body := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Big", "description": "be brief", "num_ctx": 1048577,
	}, "")
	if res.StatusCode != 400 || !strings.Contains(string(body), want) {
		t.Fatalf("create over max %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Big", "description": "be brief", "num_ctx": 1048576,
	}, "")
	if res.StatusCode != 201 {
		t.Fatalf("create max %d %s", res.StatusCode, body)
	}
	var bot store.Bot
	decodeJSON(t, body, &bot)
	if bot.NumCtx != 1048576 {
		t.Fatalf("stored %d", bot.NumCtx)
	}
	res, body = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"num_ctx": 1048577}, "")
	if res.StatusCode != 400 || !strings.Contains(string(body), want) {
		t.Fatalf("patch over max %d %s", res.StatusCode, body)
	}
	res, body = do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"num_ctx": 1048576}, "")
	if res.StatusCode != 200 {
		t.Fatalf("patch max %d %s", res.StatusCode, body)
	}
	if got := fetchBot(t, srv.URL, bot.ID); got.NumCtx != 1048576 {
		t.Fatalf("patched %d", got.NumCtx)
	}
}
