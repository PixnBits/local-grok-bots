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
