package daemon

import (
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestDispatchToolRejectsGitHubWithoutGrant(t *testing.T) {
	app := newApp(t, "", &scriptModel{})
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "NoHub")
	filtered := map[string]bool{}
	for _, tool := range toolsForGrant(toolDefs(), store.Bot{}) {
		filtered[tool.Name] = true
	}
	var github []string
	for _, tool := range toolDefs() {
		if !filtered[tool.Name] {
			github = append(github, tool.Name)
		}
	}
	if len(github) < 7 {
		t.Fatalf("github tools filtered: %v", github)
	}
	for _, name := range github {
		_, err := app.dispatchTool(t.Context(), bot, name, map[string]any{})
		if err == nil || err.Error() != "github grant required" {
			t.Fatalf("%s: %v", name, err)
		}
	}
	res, body := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"grants": []string{"github"}}, "")
	if res.StatusCode != 200 {
		t.Fatalf("grant %d %s", res.StatusCode, body)
	}
	_, err := app.dispatchTool(t.Context(), bot, github[0], map[string]any{})
	if err == nil || err.Error() == "github grant required" {
		t.Fatalf("granted %s: %v", github[0], err)
	}
	out, err := app.dispatchTool(t.Context(), bot, "list_bots", map[string]any{})
	if err != nil || !strings.Contains(out, bot.ID) {
		t.Fatalf("list_bots %v %s", err, out)
	}
}
