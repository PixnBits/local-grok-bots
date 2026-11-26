package daemon

import (
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestGitHubToolsNeedGrant(t *testing.T) {
	without := toolNameList(botTools(store.Bot{}))
	for _, name := range []string{"create_pr", "pr_status", "list_issues", "read_issue", "read_pr", "create_issue", "create_comment"} {
		if strings.Contains(without, name) {
			t.Fatalf("no grant still has %s in %s", name, without)
		}
	}
	if !strings.Contains(without, "run_shell") || !strings.Contains(without, "read_file") {
		t.Fatalf("local tools dropped: %s", without)
	}
	with := toolNameList(botTools(store.Bot{Grants: []string{"github"}}))
	if !strings.Contains(with, "create_pr") || !strings.Contains(with, "list_issues") {
		t.Fatalf("grant missing tools: %s", with)
	}
	defs := toolNameList(toolDefs())
	if !strings.Contains(defs, "create_pr") {
		t.Fatal("toolDefs dropped create_pr")
	}
	app := newApp(t, "", &scriptModel{})
	live := toolNameList(app.botTools(store.Bot{}))
	if strings.Contains(live, "create_pr") {
		t.Fatalf("app tools include create_pr: %s", live)
	}
	live = toolNameList(app.botTools(store.Bot{Grants: []string{"GitHub"}}))
	if !strings.Contains(live, "create_comment") {
		t.Fatalf("app grant missing create_comment: %s", live)
	}
}

func toolNameList(tools []model.Tool) string {
	var names []string
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	return strings.Join(names, ",")
}
