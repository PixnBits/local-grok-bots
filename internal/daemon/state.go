package daemon

import (
	"encoding/json"
	"net/http"

	"github.com/PixnBits/local-grok-bots/internal/store"
)

// botState is everything the UI's state panel shows for one bot, read-only.
type botState struct {
	Timers   []store.Timer  `json:"timers"`
	Memory   []store.Memory `json:"memory"`
	Grants   []string       `json:"grants"`
	NetAllow []string       `json:"net_allow"`
	SSHAllow []string       `json:"ssh_allow"`
	Tools    stateTools     `json:"tools"`
	Runs     []store.Run    `json:"runs"`
	Warnings []string       `json:"warnings,omitempty"`
}

type stateTools struct {
	// Names the daemon sends now; Seen is what the bot was last told about.
	Current    []string       `json:"current"`
	Seen       []string       `json:"seen"`
	UpToDate   bool           `json:"up_to_date"`
	LastNotice *store.Message `json:"last_notice"`
}

func (a *App) handleBotState(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	bot, err := a.st.GetBot(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	out := botState{Grants: bot.Grants, NetAllow: bot.NetAllow, SSHAllow: bot.SSHAllow, Warnings: descriptionWarnings(bot.Description)}
	if out.Timers, err = a.st.ListTimers(id); err != nil {
		writeErr(w, err)
		return
	}
	if out.Memory, err = a.st.ListMemory(id); err != nil {
		writeErr(w, err)
		return
	}
	if out.Runs, err = a.st.RecentRuns(id, 5); err != nil {
		writeErr(w, err)
		return
	}
	for _, t := range toolDefs() {
		out.Tools.Current = append(out.Tools.Current, t.Name)
	}
	cur, _ := toolSnapshot(toolDefs())
	hash, snap, err := a.st.ToolSnapshot(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	out.Tools.UpToDate = hash == cur
	out.Tools.Seen = []string{}
	if snap != "" {
		var m map[string]json.RawMessage
		if json.Unmarshal([]byte(snap), &m) == nil {
			out.Tools.Seen = sortedKeys(m)
		}
	}
	if out.Tools.LastNotice, err = a.st.LastToolNotice(id); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
