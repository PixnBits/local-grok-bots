package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestToolRoundWrapUpReservedRounds(t *testing.T) {
	if maxToolRounds < wrapUpMinRounds {
		t.Fatalf("default cap %d is below wrap-up minimum %d", maxToolRounds, wrapUpMinRounds)
	}
	mdl := &scriptModel{toolRounds: maxToolRounds}
	app := newApp(t, "", mdl)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Wrap")
	ws := app.botWorkspace(bot.ID)
	before := workspaceSnap(t, ws)
	capped := postUser(t, srv.URL, bot.ID, "look around")
	got := waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.ContinueRunID != ""
	})
	waitRunReleased(t, app, bot.ID)
	wantErr := toolRoundLimitBody(maxToolRounds, 0, maxToolRounds, "the built-in default")
	if got.LastRunError != wantErr || got.LastRunStatus != "error" {
		t.Fatalf("limit message = %q status %s", got.LastRunError, got.LastRunStatus)
	}
	calls := mdl.snapshot()
	if len(calls) != maxToolRounds {
		t.Fatalf("model calls = %d", len(calls))
	}
	reserve := wrapUpReserve(maxToolRounds)
	if reserve != 2 {
		t.Fatalf("default reserve = %d", reserve)
	}
	start := maxToolRounds - reserve
	for i, call := range calls {
		n := wrapUpCount(call.Messages)
		if i < start && n != 0 {
			t.Fatalf("call %d has wrap-up before the reserved rounds", i)
		}
		if i >= start && n != 1 {
			t.Fatalf("call %d wrap-up count = %d", i, n)
		}
	}
	run, err := app.st.GetRun(capped)
	if err != nil {
		t.Fatal(err)
	}
	if run.ErrorCode != store.ErrorToolRounds {
		t.Fatalf("error code = %q", run.ErrorCode)
	}
	if run.StopReason != store.StopReasonToolRounds {
		t.Fatalf("stop reason = %q", run.StopReason)
	}
	if after := workspaceSnap(t, ws); after != before {
		t.Fatalf("workspace changed\nbefore %q\nafter %q", before, after)
	}

	res, body := postContinue(t, srv.URL, bot.ID, capped)
	if res.StatusCode != 200 {
		t.Fatalf("continue %d %s", res.StatusCode, body)
	}
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "done" && b.ContinueRunID == ""
	})
	calls = mdl.snapshot()
	if len(calls) != maxToolRounds+1 {
		t.Fatalf("calls after continue = %d", len(calls))
	}
	cont := calls[maxToolRounds]
	if wrapUpCount(cont.Messages) != 1 {
		t.Fatal("continue dropped the wrap-up")
	}
	if toolCount(cont) != maxToolRounds {
		t.Fatalf("continue tool results = %d", toolCount(cont))
	}
}

func TestWrapUpReserveBands(t *testing.T) {
	cases := []struct {
		rounds int
		want   int
	}{
		{0, 0}, {1, 0}, {2, 0}, {3, 0},
		{4, 1}, {5, 1}, {6, 1}, {7, 1},
		{8, 2}, {9, 2}, {12, 2},
	}
	for _, c := range cases {
		if got := wrapUpReserve(c.rounds); got != c.want {
			t.Fatalf("wrapUpReserve(%d) = %d, want %d", c.rounds, got, c.want)
		}
	}
}

func TestToolRoundWrapUpNoteOnLastCallForMidBudget(t *testing.T) {
	for _, rounds := range []int{4, 7} {
		rounds := rounds
		t.Run(fmt.Sprintf("rounds%d", rounds), func(t *testing.T) {
			mdl := &scriptModel{toolRounds: rounds}
			app := newApp(t, "", mdl)
			srv := serve(t, app)
			res, body := do(t, "POST", srv.URL+"/api/bots", map[string]any{
				"name": "Mid", "description": "be brief", "tool_rounds": rounds,
			}, "")
			if res.StatusCode != 201 {
				t.Fatalf("create %d %s", res.StatusCode, body)
			}
			var bot store.Bot
			decodeJSON(t, body, &bot)
			postUser(t, srv.URL, bot.ID, "look")
			waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
				return b.Status != "running" && b.LastRunStatus == "error"
			})
			waitRunReleased(t, app, bot.ID)
			calls := mdl.snapshot()
			if len(calls) != rounds {
				t.Fatalf("calls = %d", len(calls))
			}
			if wrapUpReserve(rounds) != 1 {
				t.Fatalf("reserve = %d", wrapUpReserve(rounds))
			}
			for i, call := range calls {
				n := wrapUpCount(call.Messages)
				if i < rounds-1 && n != 0 {
					t.Fatalf("call %d has the note before the last call", i)
				}
				if i == rounds-1 && n != 1 {
					t.Fatalf("last call note count = %d", n)
				}
			}
		})
	}
}

func TestToolRoundWrapUpSkippedWhenBudgetTiny(t *testing.T) {
	mdl := &scriptModel{toolRounds: 3}
	app := newApp(t, "", mdl)
	srv := serve(t, app)
	res, body := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Tiny", "description": "be brief", "tool_rounds": 3,
	}, "")
	if res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, body)
	}
	var bot store.Bot
	decodeJSON(t, body, &bot)
	postUser(t, srv.URL, bot.ID, "look")
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.LastRunStatus == "error"
	})
	waitRunReleased(t, app, bot.ID)
	calls := mdl.snapshot()
	if len(calls) != 3 {
		t.Fatalf("calls = %d", len(calls))
	}
	for i, call := range calls {
		if n := wrapUpCount(call.Messages); n != 0 {
			t.Fatalf("call %d injected wrap-up on a 3-round budget", i)
		}
	}
}

func TestContinueFreshBudgetAfterWrapUp(t *testing.T) {
	mdl := &scriptModel{toolRounds: maxToolRounds * 2}
	app := newApp(t, "", mdl)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Again")
	first := postUser(t, srv.URL, bot.ID, "keep looking")
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.ContinueRunID == first
	})
	waitRunReleased(t, app, bot.ID)
	res, body := postContinue(t, srv.URL, bot.ID, first)
	if res.StatusCode != 200 {
		t.Fatalf("continue %d %s", res.StatusCode, body)
	}
	waitBot(t, srv.URL, bot.ID, func(b store.Bot) bool {
		return b.Status != "running" && b.ContinueRunID != "" && b.ContinueRunID != first
	})
	waitRunReleased(t, app, bot.ID)
	calls := mdl.snapshot()
	if len(calls) != maxToolRounds*2 {
		t.Fatalf("calls = %d", len(calls))
	}
	reserve := wrapUpReserve(maxToolRounds)
	for i, call := range calls {
		n := wrapUpCount(call.Messages)
		switch {
		case i < maxToolRounds-reserve:
			if n != 0 {
				t.Fatalf("call %d early wrap-up", i)
			}
		case i < maxToolRounds:
			if n != 1 {
				t.Fatalf("call %d first-run wrap-up = %d", i, n)
			}
		case i < maxToolRounds*2-reserve:
			if n != 1 {
				t.Fatalf("call %d should still carry the first wrap-up once, got %d", i, n)
			}
		default:
			if n != 2 {
				t.Fatalf("call %d second-run wrap-up count = %d", i, n)
			}
		}
	}
}

func wrapUpCount(msgs []model.Message) int {
	n := 0
	for _, m := range msgs {
		if strings.Contains(m.Content, toolRoundWrapUpMark) {
			n++
		}
	}
	return n
}

func workspaceSnap(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		b.WriteString(rel)
		b.WriteByte('\n')
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return b.String()
}
