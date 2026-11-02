package daemon

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestCallRecordDeniedStoresMarkerOnly(t *testing.T) {
	args := json.RawMessage(`{"command":"echo hi"}`)
	rec := callRecord("run_shell", args, "policy says no: details", &toolDeniedError{detail: "policy says no"})
	if rec.Kind != "call" || rec.Name != "run_shell" || rec.OK || rec.Result != toolDeniedMarker || string(rec.Arguments) != "{}" {
		t.Fatalf("denied record %+v %s", rec, rec.Arguments)
	}
	if got := toolUseSummary([]store.ToolRecord{rec}); got != toolSummaryPrefix+"run_shell(denied)]" {
		t.Fatalf("summary %q", got)
	}
	plain := callRecord("run_shell", args, "exit 1", errors.New("exit 1"))
	if plain.OK || plain.Result != "exit 1" || string(plain.Arguments) != string(args) {
		t.Fatalf("error record %+v", plain)
	}
	if ok := callRecord("run_shell", args, "hi", nil); !ok.OK || ok.Result != "hi" {
		t.Fatalf("ok record %+v", ok)
	}
}

func TestCLIToolEventDeniedStoresMarkerOnly(t *testing.T) {
	app, _, bot, _ := isolationApp(t, "claude", "")
	run, err := app.st.CreateRun(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	trace := &cliTrace{a: app, botID: bot.ID, runID: run.ID}
	trace.tool("Bash", map[string]any{"command": "rm -rf build"})
	body, ok := trace.toolEvent("Bash", "", false, true)
	if ok || body != toolDeniedMarker {
		t.Fatalf("live %q %v", body, ok)
	}
	trace.tool("Read", map[string]any{"file_path": "a"})
	if body, ok := trace.toolEvent("Read", "text", false, false); !ok || body != "text" {
		t.Fatalf("live ok %q %v", body, ok)
	}
	recs, err := app.st.RunTools([]string{run.ID})
	if err != nil {
		t.Fatal(err)
	}
	got := recs[run.ID]
	if len(got) != 2 || got[0].Name != "Bash" || got[0].OK || got[0].Result != toolDeniedMarker || string(got[0].Arguments) != "{}" {
		t.Fatalf("records %+v", got)
	}
	if !got[1].OK || got[1].Result != "text" {
		t.Fatalf("ok record %+v", got[1])
	}
}
