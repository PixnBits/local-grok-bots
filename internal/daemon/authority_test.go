package daemon

import (
	"strings"
	"testing"
)

func TestSystemPromptSaysToolsAreAuthoritative(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	bot, err := app.st.CreateBot("Ada", "help", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := app.buildMessages(bot)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msgs[0].Content, toolAuthority) {
		t.Fatalf("system prompt lacks tool authority line:\n%s", msgs[0].Content)
	}
}

func TestSystemPromptListsAttachedTools(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	bot, err := app.st.CreateBot("Ada", "help", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := app.buildMessages(bot)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range toolDefs() {
		names = append(names, d.Name)
	}
	want := "\nAttached tools: " + strings.Join(names, ", ") + "\n"
	if !strings.Contains(msgs[0].Content, want) {
		t.Fatalf("system prompt lacks %q:\n%s", want, msgs[0].Content)
	}
}

func TestShellCommandArgAlias(t *testing.T) {
	cases := []struct {
		args    map[string]any
		want    string
		wantErr string
	}{
		{map[string]any{"cmd": "whoami"}, "whoami", ""},
		{map[string]any{"command": "whoami"}, "whoami", ""},
		{map[string]any{"command": "whoami", "cmd": "whoami"}, "whoami", ""},
		{map[string]any{"command": "whoami", "cmd": "id"}, "", "differ"},
		{map[string]any{}, "", `"command"`},
	}
	for _, c := range cases {
		got, err := shellCommandArg(c.args)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%v: err=%v, want containing %q", c.args, err, c.wantErr)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%v: got %q, %v; want %q", c.args, got, err, c.want)
		}
	}
}
