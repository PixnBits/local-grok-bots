package daemon

import (
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestRunSendsPolicyChatOptions(t *testing.T) {
	mdl := &scriptModel{}
	app := newApp(t, "", mdl)
	cli := false
	app.cfg.Think = &cli
	app.cfg.NumCtx = 111
	no := false
	setPolicy(app, func(p *policy.Policy) {
		yes := true
		p.OllamaThink = &yes
		p.OllamaNumCtx = 222
		p.OllamaModelOptions = map[string]policy.OllamaModelOption{
			"test-model": {Think: &no, NumCtx: 333},
		}
	})
	srv := serve(t, app)
	res, body := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Opt", "description": "be brief", "think": true, "num_ctx": 444,
	}, "")
	if res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, body)
	}
	var bot store.Bot
	decodeJSON(t, body, &bot)
	if bot.Think == nil || *bot.Think != true || bot.NumCtx != 444 {
		t.Fatalf("stored %+v", bot)
	}
	postUser(t, srv.URL, bot.ID, "hi")
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "done"
	})
	calls := mdl.snapshot()
	if len(calls) != 1 {
		t.Fatalf("calls %d", len(calls))
	}
	if calls[0].Think == nil || *calls[0].Think != false || calls[0].NumCtx != 333 {
		t.Fatalf("request think %v num %d", calls[0].Think, calls[0].NumCtx)
	}
}
