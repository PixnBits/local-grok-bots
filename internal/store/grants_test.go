package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeGrantsAndAllow(t *testing.T) {
	got, err := NormalizeGrants([]string{"ssh", "browser", "net"})
	if err == nil || got != nil {
		t.Fatalf("browser grant accepted: %v %#v", err, got)
	}
	got, err = NormalizeGrants([]string{" build ", "git", "git", "net"})
	if err != nil || len(got) != 3 || got[0] != "net" || got[1] != "git" || got[2] != "build" {
		t.Fatalf("grants %#v %v", got, err)
	}
	got, err = NormalizeGrants([]string{"github", "git"})
	if err != nil || strings.Join(got, ",") != "git,github" {
		t.Fatalf("github grant %#v %v", got, err)
	}
	repos, err := NormalizeGitHubAllow([]string{"Acme/Widgets", "acme/widgets"})
	if err != nil || len(repos) != 1 || repos[0] != "acme/widgets" {
		t.Fatalf("github allow %#v %v", repos, err)
	}
	if _, err := NormalizeGitHubAllow([]string{"not a repo"}); err == nil {
		t.Fatal("bad github_allow accepted")
	}
	empty, err := NormalizeGitHubAllow(nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("nil github_allow %#v %v", empty, err)
	}
	hosts, err := NormalizeAllow([]string{"Allowed.Test.", "allowed.test", "bad host"})
	if err == nil {
		t.Fatal("space in host accepted")
	}
	hosts, err = NormalizeAllow([]string{"Allowed.Test.", "allowed.test"})
	if err != nil || len(hosts) != 1 || hosts[0] != "allowed.test" {
		t.Fatalf("hosts %#v %v", hosts, err)
	}
	if _, err := NormalizeAllow([]string{"*"}); err == nil {
		t.Fatal("wildcard accepted")
	}
}

func TestNeedsRunIgnoresNotices(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bot, err := st.CreateBot("Ada", "stay", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddMessage(Message{BotID: bot.ID, Thread: "user", Role: "user", Content: "go"}); err != nil {
		t.Fatal(err)
	}
	need, err := st.NeedsRun(bot.ID)
	if err != nil || !need {
		t.Fatalf("user message did not queue a turn: %v %v", need, err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := st.CreateRun(bot.ID); err != nil {
		t.Fatal(err)
	}
	need, err = st.NeedsRun(bot.ID)
	if err != nil || need {
		t.Fatalf("run did not cover the user message: %v %v", need, err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := st.AddMessage(Message{BotID: bot.ID, Thread: "user", Role: "system", Content: "Notice: Git push held for review"}); err != nil {
		t.Fatal(err)
	}
	need, err = st.NeedsRun(bot.ID)
	if err != nil || need {
		t.Fatalf("notice queued a turn: %v %v", need, err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := st.AddMessage(Message{BotID: bot.ID, Thread: "user", Role: "system", Content: "Message from Bob"}); err != nil {
		t.Fatal(err)
	}
	need, err = st.NeedsRun(bot.ID)
	if err != nil || !need {
		t.Fatalf("inbound DM did not queue a turn: %v %v", need, err)
	}
}
