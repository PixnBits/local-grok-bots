package daemon

import (
	"strings"
	"testing"
)

func TestExtractActions(t *testing.T) {
	text := "Sent.\n\n```action\n{\"tool\":\"send_dm\",\"to\":\"Bob\",\"content\":\"ping\"}\n```\n"
	visible, calls := extractActions(text)
	if visible != "Sent." || len(calls) != 1 || calls[0].Name != "send_dm" || calls[0].Args["to"] != "Bob" {
		t.Fatalf("visible %q calls %#v", visible, calls)
	}
	text = "```bot-action\n{\"name\":\"list_bots\",\"arguments\":{}}\n```"
	visible, calls = extractActions(text)
	if visible != "" || len(calls) != 1 || calls[0].Name != "list_bots" {
		t.Fatalf("visible %q calls %#v", visible, calls)
	}
	text = "```action\n{\"tool\":\"create_bot\",\"name\":\"Bea\",\"description\":\"helps\"}\n```"
	visible, calls = extractActions(text)
	if visible != "" || len(calls) != 1 || calls[0].Name != "create_bot" || calls[0].Args["name"] != "Bea" || calls[0].Args["description"] != "helps" {
		t.Fatalf("visible %q calls %#v", visible, calls)
	}
	visible, calls = extractActions("no fence")
	if visible != "no fence" || len(calls) != 0 {
		t.Fatalf("visible %q calls %#v", visible, calls)
	}
	visible, calls = extractActions("```action\nnot-json\n```")
	if !strings.Contains(visible, "not-json") || len(calls) != 0 {
		t.Fatalf("kept invalid fence %q %#v", visible, calls)
	}
}
