package permission

import (
	"strings"
	"testing"
)

func TestSuggestLowRiskAndMixed(t *testing.T) {
	ws := t.TempDir()
	clean := []Sample{
		{Tool: "Bash", Args: map[string]any{"command": "git status"}},
		{Tool: "Bash", Args: map[string]any{"command": "git status"}},
		{Tool: "Bash", Args: map[string]any{"command": "git status"}},
	}
	cards := Suggest(clean, ws)
	if len(cards) != 1 || cards[0].Refused || cards[0].Pattern != "Bash(git status)" || cards[0].Class.Risk != "low" || cards[0].Count != 3 {
		t.Fatalf("%+v", cards)
	}
	if !strings.Contains(cards[0].Summary, "Risk: low") || len(cards[0].Examples) != 1 {
		t.Fatalf("card %+v", cards[0])
	}

	mixed := append(clean, Sample{Tool: "Bash", Args: map[string]any{"command": "git status; rm -rf build"}})
	cards = Suggest(mixed, ws)
	if len(cards) != 1 || !cards[0].Refused || cards[0].Class.Kind != "mixed" {
		t.Fatalf("mixed %+v", cards)
	}
	if _, err := CheckUserRule("allow", cards[0].Pattern, ws); err != nil && !cards[0].Refused {
		t.Fatal("refused card must stay refused even when the pattern shape looks eligible")
	}
}

func TestSuggestSkipsNetworkClient(t *testing.T) {
	ws := t.TempDir()
	cards := Suggest([]Sample{
		{Tool: "Bash", Args: map[string]any{"command": "gh pr view 1"}},
		{Tool: "Bash", Args: map[string]any{"command": "gh pr view 2"}},
		{Tool: "Bash", Args: map[string]any{"command": "gh pr list"}},
	}, ws)
	for _, c := range cards {
		if !c.Refused && (c.Class.Risk == "low" || strings.Contains(c.Pattern, "gh")) {
			t.Fatalf("network client suggested as low-risk: %+v", c)
		}
	}
	if len(cards) != 0 {
		t.Fatalf("network client produced cards: %+v", cards)
	}
}

func TestSuggestDoesNotAllowSensitiveReads(t *testing.T) {
	ws := t.TempDir()
	cards := Suggest([]Sample{
		{Tool: "Bash", Args: map[string]any{"command": "cat -- ./src/main.go"}},
		{Tool: "Bash", Args: map[string]any{"command": "cat -- ~/.ssh/id_rsa"}},
	}, ws)
	if len(cards) != 1 || !cards[0].Refused {
		t.Fatalf("%+v", cards)
	}
}
