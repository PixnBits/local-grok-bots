package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// Every tool sent to the model carries a full JSON Schema: an object with
// properties, each with a type and a description, and required fields that
// exist in properties.
func TestToolSchemasComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, tool := range toolDefs() {
		if seen[tool.Name] {
			t.Fatalf("duplicate tool %s", tool.Name)
		}
		seen[tool.Name] = true
		if len(tool.Description) < 20 {
			t.Errorf("%s: description too short", tool.Name)
		}
		p := tool.Parameters
		if p["type"] != "object" {
			t.Errorf("%s: schema type %v", tool.Name, p["type"])
		}
		props, ok := p["properties"].(map[string]any)
		if !ok {
			t.Fatalf("%s: no properties", tool.Name)
		}
		for k, v := range props {
			pm := v.(map[string]any)
			if pm["type"] == nil || len(pm["description"].(string)) < 8 {
				t.Errorf("%s.%s: missing type or description", tool.Name, k)
			}
		}
		for _, r := range p["required"].([]string) {
			if props[r] == nil {
				t.Errorf("%s: required %s not in properties", tool.Name, r)
			}
		}
		if toolUsage(tool.Name) == "" {
			t.Errorf("%s: no usage", tool.Name)
		}
	}
	for _, tool := range toolDefs() {
		if tool.Name != "create_bot" && tool.Name != "update_bot" {
			continue
		}
		props := tool.Parameters["properties"].(map[string]any)
		field, ok := props["server_tools"].(map[string]any)
		if !ok || field["type"] != "array" {
			t.Errorf("%s server_tools %#v", tool.Name, props["server_tools"])
			continue
		}
		desc, _ := field["description"].(string)
		low := strings.ToLower(desc)
		if !strings.Contains(low, "null") || !strings.Contains(low, "empty") || !strings.Contains(low, "inherit") {
			t.Errorf("%s server_tools description %q", tool.Name, desc)
		}
		if tool.Name == "update_bot" && !strings.Contains(low, "unchanged") {
			t.Errorf("update_bot omits the unchanged rule: %s", desc)
		}
	}
	for _, want := range []string{"set_timer", "list_timers", "clear_timer", "write_memory", "delete_memory", "read_file", "write_file", "run_shell", "list_bots", "read_bot", "send_dm", "create_bot", "update_bot"} {
		if !seen[want] {
			t.Errorf("tool %s missing", want)
		}
	}
	timer := toolDefs()[2]
	props := timer.Parameters["properties"].(map[string]any)
	for _, k := range []string{"prompt", "in", "at", "every"} {
		if props[k] == nil {
			t.Errorf("set_timer.%s missing", k)
		}
	}
}

func timerApp(t *testing.T) (*App, store.Bot) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "ok"}, nil
	}})
	bot, err := app.st.CreateBot("Timer", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	return app, bot
}

func checkOnce(t *testing.T, app *App, bot store.Bot, out string, want time.Duration) {
	t.Helper()
	if !strings.Contains(out, `"schedule":"once"`) {
		t.Fatalf("result %s", out)
	}
	ts, _ := app.st.ListTimers(bot.ID)
	last := ts[len(ts)-1]
	next, err := time.Parse(time.RFC3339Nano, last.NextFireAt)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(next); d < want-5*time.Second || d > want+time.Second {
		t.Fatalf("fires in %v, want %v", d, want)
	}
}

// The relative form fires once after the duration.
func TestSetTimerRelative(t *testing.T) {
	app, bot := timerApp(t)
	out, err := app.execTool(context.Background(), bot, "set_timer", map[string]any{"prompt": "Remind the user to walk the dog.", "in": "5m"})
	if err != nil {
		t.Fatal(err)
	}
	checkOnce(t, app, bot, out, 5*time.Minute)
}

// The shapes the model tried before the schema fix are accepted.
func TestSetTimerAliases(t *testing.T) {
	app, bot := timerApp(t)
	out, err := app.execTool(context.Background(), bot, "set_timer", map[string]any{"message": "walk the dog", "repeat": "false", "seconds": "300"})
	if err != nil {
		t.Fatal(err)
	}
	checkOnce(t, app, bot, out, 5*time.Minute)
	out, err = app.execTool(context.Background(), bot, "set_timer", map[string]any{"prompt": "walk the dog", "repeat": "false", "schedule": "5m"})
	if err != nil {
		t.Fatal(err)
	}
	checkOnce(t, app, bot, out, 5*time.Minute)
	at := time.Now().Add(time.Hour).Format(time.RFC3339)
	out, err = app.execTool(context.Background(), bot, "set_timer", map[string]any{"prompt": "walk the dog", "at": at})
	if err != nil {
		t.Fatal(err)
	}
	checkOnce(t, app, bot, out, time.Hour)
	if _, err := app.execTool(context.Background(), bot, "set_timer", map[string]any{"prompt": "daily", "every": "1d"}); err != nil {
		t.Fatal(err)
	}
}

// A wrong call is told the expected shape.
func TestToolErrorsShowUsage(t *testing.T) {
	app, bot := timerApp(t)
	_, err := app.execTool(context.Background(), bot, "set_timer", map[string]any{"prompt": "x"})
	if err == nil || !strings.Contains(err.Error(), "exactly one of in, at, or every") || !strings.Contains(err.Error(), "Expected set_timer arguments: {prompt: string") {
		t.Fatalf("err = %v", err)
	}
	_, err = app.execTool(context.Background(), bot, "set_timer", map[string]any{"in": "5m"})
	if err == nil || !strings.Contains(err.Error(), "missing required argument(s): prompt") {
		t.Fatalf("err = %v", err)
	}
	_, err = app.execTool(context.Background(), bot, "send_dm", map[string]any{"to": "x"})
	if err == nil || !strings.Contains(err.Error(), "Expected send_dm arguments") {
		t.Fatalf("err = %v", err)
	}
}
