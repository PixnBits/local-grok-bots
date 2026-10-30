package daemon

import (
	"context"
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
	for _, d := range botTools(bot) {
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
		{map[string]any{"command": "  ", "cmd": "ls"}, "ls", ""},
		{map[string]any{"command": "ls", "cmd": " \t"}, "ls", ""},
		{map[string]any{"command": " \n", "cmd": " "}, "", `missing required "command"`},
		{map[string]any{"command": " \t "}, "", `missing required "command"`},
		{map[string]any{"cmd": "\n"}, "", `missing required "command"`},
		{map[string]any{"command": nil, "cmd": "ls"}, "ls", ""},
		{map[string]any{"command": float64(123)}, "", `"command" must be a string`},
		{map[string]any{"command": float64(1), "cmd": "ls"}, "", `"command" must be a string`},
		{map[string]any{"cmd": true}, "", `"cmd" must be a string`},
		{map[string]any{"cmd": []any{"touch", "x"}}, "", `"cmd" must be a string`},
		{map[string]any{"command": map[string]any{"x": "y"}}, "", `"command" must be a string`},
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

func TestExecToolRunShellCmdAlias(t *testing.T) {
	app := newApp(t, "", nil)
	bot, err := app.st.CreateBot("Ada", "help", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	out, err := app.execTool(context.Background(), bot, "run_shell", map[string]any{"cmd": "true"})
	if err != nil && strings.Contains(err.Error(), "missing required argument") {
		t.Fatalf("cmd alias stopped at required-arg check: %v\n%s", err, out)
	}
	if err != nil {
		t.Fatalf("run_shell cmd: %v\n%s", err, out)
	}
}
