package daemon

import (
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestRuleWhitespaceIsOneRuleAndCatWarns(t *testing.T) {
	app := newApp(t, t.TempDir(), nil)
	bot, err := app.st.CreateBot("rules", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.st.AddRunTool("run-h", bot.ID, store.ToolRecord{
		Kind: "permission", Name: "Bash", OK: true,
		Arguments: []byte(`{"command":"cat -- notes.txt"}`),
		Result:    `{"decision":"allow_once","source":"ui"}`,
	}); err != nil {
		t.Fatal(err)
	}
	srv := serve(t, app)
	base := srv.URL + "/api/bots/" + bot.ID
	res, body := do(t, "POST", base+"/permission-suggestions/analyze", map[string]any{}, "")
	if res.StatusCode != 200 || !strings.Contains(string(body), "Bash(cat *)") || !strings.Contains(string(body), "cat -- file") {
		t.Fatalf("analyze %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", base+"/permission-rules", map[string]any{
		"effect": "allow", "pattern": "Bash(cat *)",
	}, "")
	if res.StatusCode != 201 || !strings.Contains(string(body), `"pattern":"Bash(cat *)"`) || !strings.Contains(string(body), "cat -- file") || !strings.Contains(string(body), `"match_form":"cat -- file"`) {
		t.Fatalf("create %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", base+"/permission-rules", map[string]any{
		"effect": "allow", "pattern": "Bash(cat  *)",
	}, "")
	if res.StatusCode != 409 || !strings.Contains(string(body), "rule already exists") {
		t.Fatalf("duplicate %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", base+"/permission-rules", map[string]any{
		"effect": "allow", "pattern": "Bash(cat\n*)",
	}, "")
	if res.StatusCode != 400 {
		t.Fatalf("newline %d %s", res.StatusCode, body)
	}
	res, body = do(t, "POST", base+"/permission-rules", map[string]any{
		"effect": "deny", "pattern": "Bash(cat  *)",
	}, "")
	if res.StatusCode != 201 || strings.Contains(string(body), "match_form") || strings.Contains(string(body), "unprefixed") {
		t.Fatalf("deny %d %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), `"pattern":"Bash(cat *)"`) {
		t.Fatalf("deny pattern %s", body)
	}
	res, body = do(t, "GET", base+"/permission-rules", nil, "")
	if res.StatusCode != 200 || strings.Count(string(body), "Bash(cat *)") != 2 || !strings.Contains(string(body), "cat -- file") {
		t.Fatalf("list %d %s", res.StatusCode, body)
	}
}
