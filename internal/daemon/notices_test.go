package daemon

import (
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

func TestUntrustedJailNoticesCollapse(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	var ev []sandbox.Event
	for i := 0; i < 64; i++ {
		ev = append(ev, sandbox.Event{
			Kind: "jail_report", Untrusted: true, Reported: "grant_use",
			Detail: "package install", Notice: "Untrusted jail report: Package install",
		})
	}
	app.recordSandboxEvents("bot_1", ev)
	msgs, err := app.st.ListMessages("bot_1", "user", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].Content != "Notice: Untrusted jail report: Package install (x64)" {
		t.Fatalf("notices %+v", msgs)
	}
	logs, err := app.st.ListLog("bot_1", "jail_report", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 64 {
		t.Fatalf("log rows %d", len(logs))
	}
}

func TestUntrustedJailNoticeIncludesDropped(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	ev := []sandbox.Event{
		{Kind: "jail_report", Untrusted: true, Reported: "grant_use", Detail: "package install", Notice: "Untrusted jail report: Package install"},
		{Kind: "jail_report", Untrusted: true, Reported: "grant_use", Detail: "package install", Notice: "Untrusted jail report: Package install"},
		{Kind: "jail_report_truncated", Detail: "dropped 8"},
	}
	app.recordSandboxEvents("bot_1", ev)
	msgs, err := app.st.ListMessages("bot_1", "user", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].Content != "Notice: Untrusted jail report: Package install (x2, dropped 8)" {
		t.Fatalf("notices %+v", msgs)
	}
}

func TestDroppedCountOncePerTurn(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	ev := []sandbox.Event{
		{Kind: "jail_report", Untrusted: true, Reported: "grant_use", Detail: "package install", Notice: "Untrusted jail report: Package install"},
		{Kind: "jail_report", Untrusted: true, Reported: "grant_use", Detail: "other", Notice: "Untrusted jail report: Other"},
		{Kind: "jail_report_truncated", Detail: "dropped 8"},
	}
	app.recordSandboxEvents("bot_1", ev)
	msgs, err := app.st.ListMessages("bot_1", "user", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("notices %+v", msgs)
	}
	if msgs[0].Content != "Notice: Untrusted jail report: Package install (dropped 8)" {
		t.Fatalf("first %q", msgs[0].Content)
	}
	if msgs[1].Content != "Notice: Untrusted jail report: Other" || strings.Contains(msgs[1].Content, "dropped") {
		t.Fatalf("second %q", msgs[1].Content)
	}
}

func TestTrustedNoticeStaysOnePerEvent(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	app.recordSandboxEvents("bot_1", []sandbox.Event{
		{Kind: "grant_use", Grant: "ssh", Host: "allowed.test", Notice: "SSH to allowed.test"},
		{Kind: "grant_use", Grant: "ssh", Host: "allowed.test", Notice: "SSH to allowed.test"},
	})
	msgs, err := app.st.ListMessages("bot_1", "user", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("notices %+v", msgs)
	}
	for _, m := range msgs {
		if m.Content != "Notice: SSH to allowed.test" || strings.Contains(m.Content, "(x") {
			t.Fatalf("notice %q", m.Content)
		}
	}
}
