package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// toolEntry is one tool as recorded in a bot's tool snapshot.
type toolEntry struct {
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// toolSnapshot returns the tool list as stable JSON (map keys sort) and its
// SHA-256, so a change to any name, description, or schema changes the hash.
func toolSnapshot(defs []model.Tool) (hash, snapshot string) {
	m := make(map[string]toolEntry, len(defs))
	for _, t := range defs {
		m[t.Name] = toolEntry{Description: t.Description, Parameters: t.Parameters}
	}
	b, _ := json.Marshal(m)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), string(b)
}

// diffTools describes how the tool list changed, by tool name. It returns
// "" when nothing a bot would notice changed.
func diffTools(oldSnap, newSnap string) string {
	var oldM, newM map[string]toolEntry
	if json.Unmarshal([]byte(oldSnap), &oldM) != nil || json.Unmarshal([]byte(newSnap), &newM) != nil {
		return ""
	}
	var added, removed, changed []string
	for _, n := range sortedKeys(newM) {
		o, ok := oldM[n]
		if !ok {
			added = append(added, n)
			continue
		}
		if c := describeChange(o, newM[n]); c != "" {
			changed = append(changed, n+" ("+c+")")
		}
	}
	for _, n := range sortedKeys(oldM) {
		if _, ok := newM[n]; !ok {
			removed = append(removed, n)
		}
	}
	var parts []string
	if len(added) > 0 {
		parts = append(parts, "added "+strings.Join(added, ", "))
	}
	if len(changed) > 0 {
		parts = append(parts, "changed "+strings.Join(changed, ", "))
	}
	if len(removed) > 0 {
		parts = append(parts, "removed "+strings.Join(removed, ", "))
	}
	return strings.Join(parts, "; ")
}

// describeChange summarizes a changed tool. Prefer "now takes a/b/c" when
// the property set differs, matching the notice the model and UI show.
func describeChange(o, n toolEntry) string {
	norm := func(v map[string]any) map[string]any {
		b, _ := json.Marshal(v)
		var out map[string]any
		_ = json.Unmarshal(b, &out)
		return out
	}
	op, np := norm(o.Parameters), norm(n.Parameters)
	oProps, _ := op["properties"].(map[string]any)
	nProps, _ := np["properties"].(map[string]any)
	var bits []string
	if !reflect.DeepEqual(oProps, nProps) {
		if names := sortedKeys(nProps); len(names) > 0 {
			bits = append(bits, "now takes "+strings.Join(names, "/"))
		} else {
			bits = append(bits, "schema updated")
		}
	} else if !reflect.DeepEqual(op, np) {
		bits = append(bits, "schema updated")
	}
	if o.Description != n.Description {
		bits = append(bits, "description updated")
	}
	return strings.Join(bits, "; ")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// noteToolChanges runs at the start of a fresh run. When the tool list
// differs from the one the bot last saw, it posts a Notice line on the
// thread (which reaches the model as a user message) and records the new
// snapshot. A bot with no snapshot that has replied before gets a one-time
// list of current tools, since its history may claim otherwise; a brand-new
// bot just has the snapshot recorded.
func (a *App) noteToolChanges(bot store.Bot) {
	hash, snap := toolSnapshot(toolDefs())
	oldHash, oldSnap, err := a.st.ToolSnapshot(bot.ID)
	if err != nil || oldHash == hash {
		return
	}
	var notice string
	if oldSnap == "" {
		if a.hasReplied(bot.ID) {
			names := make([]string, 0)
			for _, t := range toolDefs() {
				names = append(names, t.Name)
			}
			notice = "Tools available now: " + strings.Join(names, ", ") + ". This list replaces any earlier statement about your tools."
		}
	} else if d := diffTools(oldSnap, snap); d != "" {
		notice = "Tools updated: " + d + "."
	}
	if notice != "" {
		if _, err := a.st.AddMessage(store.Message{BotID: bot.ID, Thread: "user", Role: "system", Content: "Notice: " + notice}); err != nil {
			return
		}
		a.log(bot.ID, "tools_changed", map[string]any{"notice": notice})
	}
	_ = a.st.SetToolSnapshot(bot.ID, hash, snap)
}

// hasReplied reports whether the bot has any reply in its recent history.
func (a *App) hasReplied(botID string) bool {
	hist, err := a.st.RecentContext(botID, 200)
	if err != nil {
		return false
	}
	for _, m := range hist {
		if m.Role == "bot" {
			return true
		}
	}
	return false
}
