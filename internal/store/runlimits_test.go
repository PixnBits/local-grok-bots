package store

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompactDurationKeepsRemainder(t *testing.T) {
	if CompactDuration(1500*time.Millisecond) != "1.5s" {
		t.Fatalf("1500ms %q", CompactDuration(1500*time.Millisecond))
	}
	if CompactDuration(1001*time.Millisecond) != "1.001s" {
		t.Fatalf("1001ms %q", CompactDuration(1001*time.Millisecond))
	}
	if CompactDuration(90*time.Second+500*time.Millisecond) != "1m30.5s" {
		t.Fatalf("90.5s %q", CompactDuration(90*time.Second+500*time.Millisecond))
	}
	if CompactDuration(time.Hour+500*time.Millisecond) != "1h0.5s" {
		t.Fatalf("1h500ms %q", CompactDuration(time.Hour+500*time.Millisecond))
	}
	if CompactDuration(150*time.Millisecond) != "150ms" || CompactDuration(10*time.Minute) != "10m" || CompactDuration(90*time.Minute) != "1h30m" || CompactDuration(45*time.Second) != "45s" || CompactDuration(0) != "" {
		t.Fatal("whole-second formatting changed")
	}
	raw, err := json.Marshal(DurationMS(1500 * time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `"1.5s"` {
		t.Fatalf("json %s", raw)
	}
}

func TestBotLimitsRoundTripAndClear(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	bot, err := st.InsertBot(BotDraft{
		Name: "Ada", Description: "stay",
		RunTimeout: 10 * time.Minute, ShellTimeout: 30 * time.Second, ToolRounds: 3,
	}, "user")
	if err != nil {
		t.Fatal(err)
	}
	if bot.RunTimeout.Duration() != 10*time.Minute || bot.ShellTimeout.Duration() != 30*time.Second || bot.ToolRounds != 3 {
		t.Fatalf("insert %#v", bot)
	}
	raw, err := json.Marshal(bot)
	if err != nil {
		t.Fatal(err)
	}
	// JSON shape: duration strings, 0/"" inherit. Documented here so a
	// revert of MarshalJSON fails this test.
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body["run_timeout"] != "10m" || body["shell_timeout"] != "30s" {
		t.Fatalf("json durations %#v", body)
	}
	if body["tool_rounds"] != float64(3) {
		t.Fatalf("json rounds %#v", body["tool_rounds"])
	}

	got, err := st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RunTimeout.Duration() != 10*time.Minute || got.ShellTimeout.Duration() != 30*time.Second || got.ToolRounds != 3 {
		t.Fatalf("reread %#v", got)
	}

	cleared, _, err := st.UpdateBot(bot.ID, BotPatch{
		RunTimeoutSet: true, ShellTimeoutSet: true, ToolRoundsSet: true, By: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cleared.RunTimeout != 0 || cleared.ShellTimeout != 0 || cleared.ToolRounds != 0 {
		t.Fatalf("cleared %#v", cleared)
	}
	again, err := st.GetBot(bot.ID)
	if err != nil || again.RunTimeout != 0 || again.ShellTimeout != 0 || again.ToolRounds != 0 {
		t.Fatalf("clear reread %#v %v", again, err)
	}
	raw, err = json.Marshal(again)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body["run_timeout"] != "" || body["shell_timeout"] != "" || body["tool_rounds"] != float64(0) {
		t.Fatalf("inherited json %#v", body)
	}

	unchanged, _, err := st.UpdateBot(bot.ID, BotPatch{
		RunTimeoutSet: true, ShellTimeoutSet: true, ToolRoundsSet: true, By: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.RunTimeout != 0 {
		t.Fatalf("unchanged write %#v", unchanged)
	}

	events, err := st.ListLog(bot.ID, "bot_limits_changed", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	// create three + clear three. Unchanged patch writes nothing.
	if len(events) != 6 {
		t.Fatalf("log count %d %#v", len(events), events)
	}
	var sawSet, sawClear bool
	for _, e := range events {
		var d map[string]any
		if err := json.Unmarshal(e.Detail, &d); err != nil {
			t.Fatal(err)
		}
		if d["bot_id"] != bot.ID || d["by"] != "user" || d["field"] == nil {
			t.Fatalf("detail %#v", d)
		}
		if d["field"] == "run_timeout" && d["new"] == "10m" && d["old"] == "" {
			sawSet = true
		}
		if d["field"] == "run_timeout" && d["new"] == "" && d["old"] == "10m" {
			sawClear = true
		}
	}
	if !sawSet || !sawClear {
		t.Fatalf("missing set/clear rows %#v", events)
	}
}

func TestBotLimitsMigrateExistingDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	bot, err := st.CreateBot("Ada", "keep", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RunTimeout != 0 || got.ShellTimeout != 0 || got.ToolRounds != 0 || got.Description != "keep" {
		t.Fatalf("migrated %#v", got)
	}
	for _, col := range []string{"run_timeout_ms", "shell_timeout_ms", "tool_rounds"} {
		ok, err := st.hasColumn("bots", col)
		if err != nil || !ok {
			t.Fatalf("missing %s %v", col, err)
		}
	}
}

func TestRunErrorCode(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ok, err := st.hasColumn("runs", "error_code")
	if err != nil || !ok {
		t.Fatalf("missing error_code %v", err)
	}
	bot, err := st.CreateBot("Ada", "stay", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	run, err := st.CreateRun(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	ok, err = st.FinishRunCode(run.ID, "error", "The run used all 3 tool rounds (set on this bot).", ErrorToolRounds)
	if err != nil || !ok {
		t.Fatalf("finish %v %v", ok, err)
	}
	got, err := st.GetRun(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ErrorCode != ErrorToolRounds {
		t.Fatalf("stored %q", got.ErrorCode)
	}
	botGot, err := st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if botGot.LastRunCode != ErrorToolRounds {
		t.Fatalf("bot last_run_code %q", botGot.LastRunCode)
	}

	other, err := st.CreateRun(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	ok, err = st.FinishRun(other.ID, "error", "boom")
	if err != nil || !ok {
		t.Fatalf("other finish %v %v", ok, err)
	}
	gotOther, err := st.GetRun(other.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotOther.ErrorCode != "" {
		t.Fatalf("other stored %q", gotOther.ErrorCode)
	}
	botOther, err := st.GetBot(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if botOther.LastRunCode != "" {
		t.Fatalf("other bot last_run_code %q", botOther.LastRunCode)
	}
}

func TestBotLimitsJSONRoundTrip(t *testing.T) {
	in := Bot{Name: "Ada", RunTimeout: DurationMS(5 * time.Minute), ToolRounds: 2}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"run_timeout":"5m"`) || !strings.Contains(string(raw), `"tool_rounds":2`) {
		t.Fatalf("marshal %s", raw)
	}
	var out Bot
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.RunTimeout.Duration() != 5*time.Minute || out.ToolRounds != 2 || out.ShellTimeout != 0 {
		t.Fatalf("unmarshal %#v", out)
	}
}
