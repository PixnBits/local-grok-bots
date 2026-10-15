package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/store"
)

func cliTimerApp(t *testing.T) (*App, store.Bot) {
	t.Helper()
	app, bot := timerApp(t)
	app.policy.Backend = "claude"
	app.policy.CLIPermitted = true
	return app, bot
}

func setEvery(t *testing.T, app *App, bot store.Bot, every string) error {
	t.Helper()
	_, err := app.execTool(context.Background(), bot, "set_timer", map[string]any{"prompt": "ping", "every": every})
	return err
}

func setIn(t *testing.T, app *App, bot store.Bot, in string) error {
	t.Helper()
	_, err := app.execTool(context.Background(), bot, "set_timer", map[string]any{"prompt": "ping", "in": in})
	return err
}

func TestCLIRepeatingTimerMinimum(t *testing.T) {
	app, bot := cliTimerApp(t)
	err := setEvery(t, app, bot, "1s")
	if err == nil || !strings.Contains(err.Error(), "shorter than the minimum 5m") || !strings.Contains(err.Error(), "cli.lgb.min_timer_interval") {
		t.Fatalf("err = %v", err)
	}
	err = setEvery(t, app, bot, "2m")
	if err == nil || !strings.Contains(err.Error(), "shorter than the minimum 5m") || !strings.Contains(err.Error(), "cli.lgb.min_timer_interval") {
		t.Fatalf("err = %v", err)
	}
	if timers, _ := app.st.ListTimers(bot.ID); len(timers) != 0 {
		t.Fatalf("stored a rejected timer: %+v", timers)
	}
	if err := setEvery(t, app, bot, "5m"); err != nil {
		t.Fatal(err)
	}
	err = setEvery(t, app, bot, "5m")
	if err == nil || !strings.Contains(err.Error(), "exceed 12 scheduled turns per hour") || !strings.Contains(err.Error(), "cli.lgb.max_scheduled_per_hour") {
		t.Fatalf("err = %v", err)
	}
	timers, _ := app.st.ListTimers(bot.ID)
	if len(timers) != 1 || timers[0].Schedule != "5m" {
		t.Fatalf("timers %+v", timers)
	}
	_, _, help, err := app.lgbParse(bot, []string{"help"})
	if err != nil || !strings.Contains(help, "at least 5m") || !strings.Contains(help, "At most 12 scheduled turns") {
		t.Fatalf("help %v\n%s", err, help)
	}
}

func TestCLIScheduledTurnCap(t *testing.T) {
	app, bot := cliTimerApp(t)
	for i := 0; i < 2; i++ {
		if err := setEvery(t, app, bot, "10m"); err != nil {
			t.Fatalf("timer %d: %v", i, err)
		}
	}
	if err := setEvery(t, app, bot, "10m"); err == nil || !strings.Contains(err.Error(), "exceed 12") {
		t.Fatalf("third every 10m: %v", err)
	}
	if err := setIn(t, app, bot, "1s"); err == nil || !strings.Contains(err.Error(), "exceed 12") {
		t.Fatalf("one-shot on a full repeating budget: %v", err)
	}

	app, bot = cliTimerApp(t)
	for i := 0; i < 12; i++ {
		if err := setIn(t, app, bot, "10m"); err != nil {
			t.Fatalf("one-shot %d: %v", i, err)
		}
	}
	if err := setIn(t, app, bot, "10m"); err == nil || !strings.Contains(err.Error(), "exceed 12") {
		t.Fatalf("13th one-shot: %v", err)
	}

	app, bot = cliTimerApp(t)
	for i := 0; i < 12; i++ {
		if err := app.st.AddLog(bot.ID, "timer_fired", map[string]any{"n": i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := setIn(t, app, bot, "5m"); err == nil || !strings.Contains(err.Error(), "exceed 12") {
		t.Fatalf("after 12 fires: %v", err)
	}
	if err := setEvery(t, app, bot, "1h"); err == nil || !strings.Contains(err.Error(), "exceed 12") {
		t.Fatalf("repeat after 12 fires: %v", err)
	}
}

func TestOllamaTimerUnchangedUnlessPolicy(t *testing.T) {
	app, bot := timerApp(t)
	if err := setEvery(t, app, bot, "1s"); err != nil {
		t.Fatalf("ollama every 1s: %v", err)
	}
	timers, _ := app.st.ListTimers(bot.ID)
	if len(timers) != 1 || timers[0].Schedule != "1s" {
		t.Fatalf("timers %+v", timers)
	}
	_, _, help, err := app.lgbParse(bot, []string{"help"})
	if err != nil || strings.Contains(help, "min_timer_interval") {
		t.Fatalf("ollama help mentions a floor: %v\n%s", err, help)
	}

	app.policy.LGBMinTimerSet = true
	app.policy.LGBMinTimer = 2 * time.Minute
	app.policy.LGBMaxSchedSet = true
	app.policy.LGBMaxSchedPerHour = 4
	other, err := app.st.CreateBot("Other", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	if err := setEvery(t, app, other, "30s"); err == nil || !strings.Contains(err.Error(), "minimum 2m") {
		t.Fatalf("policy floor: %v", err)
	}
	if err := setEvery(t, app, other, "20m"); err != nil {
		t.Fatal(err)
	}

	app, bot = cliTimerApp(t)
	app.policy.LGBMinTimerSet = true
	app.policy.LGBMinTimer = 0
	app.policy.LGBMaxSchedSet = true
	app.policy.LGBMaxSchedPerHour = 0
	if err := setEvery(t, app, bot, "1s"); err != nil {
		t.Fatalf("cli opt-out: %v", err)
	}
}
