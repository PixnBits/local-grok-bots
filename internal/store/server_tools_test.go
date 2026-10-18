package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestServerToolsRoundTrip(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bot, err := st.CreateBot("Ada", "stay", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	if bot.ServerTools != nil {
		t.Fatalf("new bot %#v", bot.ServerTools)
	}
	empty := []string{}
	blank, err := st.InsertBot(BotDraft{Name: "Blank", Description: "stay", ServerTools: &empty}, "user")
	if err != nil {
		t.Fatal(err)
	}
	if blank.ServerTools == nil || len(*blank.ServerTools) != 0 {
		t.Fatalf("empty %#v", blank.ServerTools)
	}
	again, err := st.GetBot(blank.ID)
	if err != nil || again.ServerTools == nil || len(*again.ServerTools) != 0 {
		t.Fatalf("reread %#v %v", again.ServerTools, err)
	}
	list := []string{" Web_Search ", "web_search", "x_search"}
	named, err := st.InsertBot(BotDraft{Name: "Named", Description: "stay", ServerTools: &list}, "user")
	if err != nil {
		t.Fatal(err)
	}
	if named.ServerTools == nil || strings.Join(*named.ServerTools, ",") != "web_search,x_search" {
		t.Fatalf("stored %#v", named.ServerTools)
	}
	events, err := st.ListLog(named.ID, "bot_created", "", 10)
	if err != nil || len(events) != 1 || strings.Contains(string(events[0].Detail), "web_search") {
		t.Fatalf("log %#v %v", events, err)
	}
	label := "kept"
	updated, err := st.UpdateBot(named.ID, BotPatch{Label: &label})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Label != "kept" || updated.ServerTools == nil || strings.Join(*updated.ServerTools, ",") != "web_search,x_search" {
		t.Fatalf("label patch %#v", updated)
	}
	cleared, err := st.UpdateBot(named.ID, BotPatch{ServerToolsSet: true})
	if err != nil {
		t.Fatal(err)
	}
	if cleared.ServerTools != nil {
		t.Fatalf("clear %#v", cleared.ServerTools)
	}
	none := []string{}
	setEmpty, err := st.UpdateBot(named.ID, BotPatch{ServerToolsSet: true, ServerTools: &none})
	if err != nil {
		t.Fatal(err)
	}
	if setEmpty.ServerTools == nil || len(*setEmpty.ServerTools) != 0 {
		t.Fatalf("set empty %#v", setEmpty.ServerTools)
	}
	bad := []string{"bad name"}
	if _, err := st.UpdateBot(named.ID, BotPatch{ServerToolsSet: true, ServerTools: &bad}); err == nil || !strings.Contains(err.Error(), "invalid server_tools") || strings.Contains(err.Error(), "bad name") {
		t.Fatalf("invalid err %v", err)
	}
	got, err := st.GetBot(named.ID)
	if err != nil || got.ServerTools == nil || len(*got.ServerTools) != 0 {
		t.Fatalf("invalid write stuck %#v %v", got.ServerTools, err)
	}
	if _, err := NormalizeServerTools([]string{"function"}); err == nil {
		t.Fatal("function accepted")
	}
	if _, err := st.InsertBot(BotDraft{Name: "Bad", Description: "stay", ServerTools: &bad}, "user"); err == nil {
		t.Fatal("insert accepted an invalid name")
	}
}
