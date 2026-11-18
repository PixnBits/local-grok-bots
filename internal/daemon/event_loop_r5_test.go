package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

// The interim error class is a fixed set. Each arm fails on its own when
// that case is removed.
func TestTesterEvR4ClassSet(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", err: nil, want: ""},
		{name: "model_error", err: errors.New("boom"), want: "model_error"},
		{name: "cancelled", err: fmt.Errorf("w: %w", context.Canceled), want: "cancelled"},
		{name: "deadline", err: fmt.Errorf("w: %w", context.DeadlineExceeded), want: "timeout"},
		{name: "timeout_error", err: &model.TimeoutError{Limit: "model_timeout", After: time.Second}, want: "timeout"},
		{name: "wrapped_timeout", err: fmt.Errorf("x: %w", &model.TimeoutError{Limit: "first_token"}), want: "timeout"},
		{name: "text_deadline", err: errors.New("context deadline exceeded"), want: "model_error"},
		{name: "text_token", err: errors.New("timeout sk-ant-api03-DUMMYCLASS12345"), want: "model_error"},
		{name: "join", err: errors.Join(context.Canceled, context.DeadlineExceeded), want: "timeout"},
	}
	allowed := map[string]bool{"": true, "model_error": true, "timeout": true, "cancelled": true}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			class, msg := interimAuditError(c.err)
			if !allowed[class] {
				t.Fatalf("class %q not in bounded set", class)
			}
			if class != c.want {
				t.Fatalf("class %q want %q (msg %q)", class, c.want, msg)
			}
			if strings.Contains(class, "DUMMY") || strings.Contains(class, "boom") {
				t.Fatalf("class carries error text %q", class)
			}
		})
	}
}

func TestInterimPathMarks(t *testing.T) {
	const leaf = "fixture-leaf"
	cases := []struct {
		name   string
		in     string
		banned []string
		mark   string
	}{
		{name: "equals", in: "key=/abs/" + leaf, banned: []string{leaf}, mark: "[path]"},
		{name: "quote", in: "\"/abs/" + leaf + "\"", banned: []string{leaf}, mark: "[path]"},
		{name: "semicolon", in: "note;/abs/" + leaf, banned: []string{leaf}, mark: "[path]"},
		{name: "second_path", in: "key=/abs/leaf-one;/abs/" + leaf, banned: []string{"leaf-one", leaf}, mark: "[path]"},
		{name: "brace", in: "cfg{/abs/" + leaf + "}", banned: []string{leaf}, mark: "[path]"},
		{name: "pipe", in: "pipe|/abs/" + leaf, banned: []string{leaf}, mark: "[path]"},
		{name: "bang", in: "bang!/abs/" + leaf, banned: []string{leaf}, mark: "[path]"},
		{name: "dot", in: "dot./abs/" + leaf, banned: []string{leaf}, mark: "[path]"},
		{name: "json_escaped", in: `\/abs\/` + leaf, banned: []string{leaf}, mark: "[path]"},
		{name: "percent_2f", in: "%2Fabs%2F" + leaf, banned: []string{leaf, "%2F"}, mark: "[path]"},
		{name: "unc", in: `\\server\share\` + leaf, banned: []string{leaf, `\\server`}, mark: "[path]"},
		{name: "tilde", in: "~/" + leaf + "/x", banned: []string{leaf}, mark: "[path]"},
		{name: "home_rel", in: "home/fixture-user/" + leaf, banned: []string{leaf, "fixture-user"}, mark: "[path]"},
		{name: "ipv4", in: "dial tcp 192.0.2.10:11434", banned: []string{"192.0.2.10"}, mark: "[host]"},
		{name: "ipv6", in: "dial tcp [2001:db8::1]:443", banned: []string{"2001:db8"}, mark: "[host]"},
		{name: "ipv6_bare", in: "see 2001:db8::1 now", banned: []string{"2001:db8"}, mark: "[host]"},
		{name: "lookup", in: "lookup dummy-host.example on 198.51.100.10:53", banned: []string{"dummy-host.example", "198.51.100.10"}, mark: "[host]"},
		{name: "at_host", in: "user@dummy-host.example", banned: []string{"dummy-host.example"}, mark: "[host]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, msg := interimAuditError(errors.New(c.in))
			if !utf8.ValidString(msg) {
				t.Fatalf("invalid utf-8 %q", msg)
			}
			if !strings.Contains(msg, c.mark) {
				t.Fatalf("message %q missing %s", msg, c.mark)
			}
			for _, ban := range c.banned {
				if strings.Contains(msg, ban) {
					t.Fatalf("message %q still has %q", msg, ban)
				}
			}
		})
	}
	// A slash between digits is not a path.
	_, ratio := interimAuditError(errors.New("ratio 1/2"))
	if ratio != "ratio 1/2" {
		t.Fatalf("ratio message %q", ratio)
	}
}

func TestInterimAuditErrorClipsUTF8(t *testing.T) {
	t.Run("ascii_limit", func(t *testing.T) {
		_, msg := interimAuditError(errors.New(strings.Repeat("q", 500)))
		if !utf8.ValidString(msg) {
			t.Fatal("invalid utf-8")
		}
		if len(msg) != 200 || msg != strings.Repeat("q", 200) {
			t.Fatalf("clipped len %d msg %q", len(msg), msg)
		}
		if interimErrorLimit != 200 {
			t.Fatalf("interimErrorLimit %d", interimErrorLimit)
		}
	})
	t.Run("rune_boundary", func(t *testing.T) {
		// 199 ASCII bytes, then a 2-byte rune, so a byte cut at 200 splits it.
		in := strings.Repeat("q", 199) + "ééé"
		_, msg := interimAuditError(errors.New(in))
		if !utf8.ValidString(msg) {
			t.Fatalf("invalid utf-8 %q", msg)
		}
		if len(msg) > 200 {
			t.Fatalf("len %d over 200", len(msg))
		}
		if msg != strings.Repeat("q", 199) {
			t.Fatalf("clipped %q", msg)
		}
	})
}

func TestInterimBudgetForEmptyRunID(t *testing.T) {
	app := newApp(t, "", nil)
	z := app.interimBudgetFor("bot-empty", "")
	if z == nil || !z.refuseAll {
		t.Fatalf("empty run id budget %#v", z)
	}
	app.rtMu.Lock()
	st := app.loops["bot-empty"]
	stored := st != nil && st.interim != nil && !st.interim.refuseAll
	app.rtMu.Unlock()
	if stored {
		t.Fatal("empty run id stored a counting budget")
	}
	z.starts = 9
	real := app.interimBudgetFor("bot-empty", "run-1")
	if real == nil || real.refuseAll || real.starts != 0 || real == z {
		t.Fatalf("real run budget %#v empty %#v", real, z)
	}
}

// A quiet window past the cap with no new input does not write a capped
// row and does not count toward the suppressed row.
func TestInterimCapWakeWithoutInput(t *testing.T) {
	m := newAsyncModel("run_shell", "mid", "final answer", true)
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	seen := make(chan int, 4)
	app := newApp(t, "", m)
	app.editPol(func(p *policy.Policy) { p.EventLoop = true })
	app.eventClk = clk
	app.eventLoopMaxInterim = 2
	app.interimCapSeen = func(n int) {
		seen <- n
	}
	app.toolExec = tool.exec
	t.Cleanup(tool.letGo)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "CapWake")
	postUser(t, srv.URL, bot.ID, "go")
	waitCh(t, tool.started, "tool")
	fireInterim(t, srv.URL, bot.ID, "a1", clk, m.entered, 1)
	fireInterim(t, srv.URL, bot.ID, "a2", clk, m.entered, 2)

	app.kick(bot.ID)
	clk.Advance(500 * time.Millisecond)
	select {
	case n := <-seen:
		if n != 0 {
			t.Fatalf("no-input window uncovered %d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no-input window was not observed")
	}
	if got := budgetSuppressed(app, bot.ID); got != 0 {
		t.Fatalf("no-input window counted suppressed %d", got)
	}
	if caps := eventLoopInterimCaps(t, app, bot.ID); len(caps) != 0 {
		t.Fatalf("no-input window wrote capped %+v", caps)
	}
	assertNoEntered(t, m.entered)

	postUser(t, srv.URL, bot.ID, "later")
	clk.Advance(500 * time.Millisecond)
	select {
	case n := <-seen:
		if n == 0 {
			t.Fatal("message after the cap was treated as no new input")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("capped window with input was not observed")
	}
	if got := budgetSuppressed(app, bot.ID); got != 1 {
		t.Fatalf("suppressed %d, want 1", got)
	}
	caps := waitInterimCaps(t, app, bot.ID, 1)
	if len(caps) != 1 || caps[0].Count != 2 || caps[0].Cap != 2 {
		t.Fatalf("caps %+v", caps)
	}
	assertNoEntered(t, m.entered)
	if batches := eventLoopBatchCounts(t, app, bot.ID); len(batches) != 2 {
		t.Fatalf("batches %#v, want 2", batches)
	}

	tool.letGo()
	waitIdle(t, srv.URL, bot.ID, "")
	supp := waitInterimSuppressed(t, app, bot.ID, 1)
	if len(supp) != 1 || supp[0].Suppressed != 1 || supp[0].Count != 2 || supp[0].Cap != 2 {
		t.Fatalf("suppressed row %+v", supp)
	}
	if got := eventLoopInterimCaps(t, app, bot.ID); len(got) != 1 {
		t.Fatalf("capped rows after finish %+v", got)
	}
}

func TestInterimNilRefusalAudit(t *testing.T) {
	app := newApp(t, "", nil)
	bot, err := app.st.CreateBot("Refuse", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	app.rtMu.Lock()
	app.loops[bot.ID] = &loopState{running: true, runID: "run-1", gen: 1}
	app.rtMu.Unlock()
	app.noteNilRefusal(bot.ID, "run-1")
	if nilRefusedCount(app, bot.ID) != 1 {
		t.Fatalf("nilRefused %d", nilRefusedCount(app, bot.ID))
	}
	ev, err := app.st.ListLog(bot.ID, "event_loop_interim_refused", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 {
		t.Fatalf("refused rows %d", len(ev))
	}
	var row struct {
		RunID string `json:"run_id"`
		Count int    `json:"count"`
	}
	if err := json.Unmarshal(ev[0].Detail, &row); err != nil {
		t.Fatal(err)
	}
	if row.RunID != "run-1" || row.Count != 1 {
		t.Fatalf("refused row %+v", row)
	}
}
