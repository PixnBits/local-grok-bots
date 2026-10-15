package daemon

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSendDMCountsTowardHourlyTurnCap(t *testing.T) {
	app := newApp(t, "", &scriptModel{})
	app.policy.LGBMaxSchedSet = true
	app.policy.LGBMaxSchedPerHour = 3
	now := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	c := app.turnCounter()
	c.mu.Lock()
	c.now = func() time.Time { return now }
	c.mu.Unlock()
	a, err := app.st.CreateBot("Ping", "local", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	b, err := app.st.CreateBot("Pong", "local", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	send := func() error {
		_, err := app.dispatchTool(context.Background(), a, "send_dm", map[string]any{"to": b.ID, "content": "PING"})
		return err
	}
	// A timer turn and two DMs fill the cap of 3.
	app.noteScheduledTurn(b.ID)
	for i := 0; i < 2; i++ {
		if err := send(); err != nil {
			t.Fatalf("dm %d: %v", i, err)
		}
	}
	err = send()
	if err == nil || !strings.Contains(err.Error(), "max_scheduled_per_hour") {
		t.Fatalf("over cap: %v", err)
	}
	n, err := app.st.LogCount("bot_turn_cap")
	if err != nil || n != 1 {
		t.Fatalf("bot_turn_cap log = %d %v", n, err)
	}
	msgs, err := app.st.ListMessages(b.ID, "dm:"+a.ID, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	got := 0
	for _, m := range msgs {
		if m.Content == "PING" {
			got++
		}
	}
	if got != 2 {
		t.Fatalf("delivered %d DMs, want 2", got)
	}
	c.mu.Lock()
	now = now.Add(time.Hour + time.Second)
	c.mu.Unlock()
	if err := send(); err != nil {
		t.Fatalf("after the hour: %v", err)
	}
}
