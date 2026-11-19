package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestTesterEvR5UTF8Cut(t *testing.T) {
	for _, r := range []string{"é", "€", "𝄞"} {
		for pre := 190; pre <= 201; pre++ {
			in := strings.Repeat("q", pre) + strings.Repeat(r, 40)
			_, msg := interimAuditError(errors.New(in))
			if !utf8.ValidString(msg) {
				t.Fatalf("rune %q pre %d: invalid utf-8", r, pre)
			}
			if len(msg) > 200 {
				t.Fatalf("rune %q pre %d: len %d", r, pre, len(msg))
			}
			if len(msg) < 200-(len(r)-1) {
				t.Fatalf("rune %q pre %d: over-trimmed len %d", r, pre, len(msg))
			}
			if !strings.HasPrefix(in, msg) {
				t.Fatalf("rune %q pre %d: not a prefix", r, pre)
			}
		}
	}
}

func TestTesterEvR5InvalidInput(t *testing.T) {
	for _, pos := range []int{0, 10, 150} {
		in := strings.Repeat("q", pos) + "\xff" + strings.Repeat("z", 400)
		_, msg := interimAuditError(errors.New(in))
		if !utf8.ValidString(msg) {
			t.Fatalf("pos %d: invalid utf-8 len %d", pos, len(msg))
		}
		if len(msg) > 200 {
			t.Fatalf("pos %d: len %d over 200", pos, len(msg))
		}
		if len(msg) < 150 {
			t.Fatalf("pos %d: message shrank to %d bytes", pos, len(msg))
		}
	}
}

func TestTesterEvR5WakeOnlyEnd(t *testing.T) {
	m := newAsyncModel("run_shell", "mid", "final answer", true)
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	seen := make(chan int, 8)
	app := newApp(t, "", m)
	app.editPol(func(p *policy.Policy) { p.EventLoop = true })
	app.eventClk = clk
	app.eventLoopMaxInterim = 2
	app.interimCapSeen = func(n int) { seen <- n }
	app.toolExec = tool.exec
	t.Cleanup(tool.letGo)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "WakeEnd")
	postUser(t, srv.URL, bot.ID, "go")
	waitCh(t, tool.started, "tool")
	fireInterim(t, srv.URL, bot.ID, "a1", clk, m.entered, 1)
	fireInterim(t, srv.URL, bot.ID, "a2", clk, m.entered, 2)
	for i := 0; i < 3; i++ {
		app.kick(bot.ID)
		clk.Advance(500 * time.Millisecond)
		select {
		case n := <-seen:
			if n != 0 {
				t.Fatalf("wake %d uncovered %d", i, n)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("wake %d not observed", i)
		}
	}
	tool.letGo()
	waitIdle(t, srv.URL, bot.ID, "")
	time.Sleep(200 * time.Millisecond)
	if c := eventLoopInterimCaps(t, app, bot.ID); len(c) != 0 {
		t.Fatalf("capped rows %+v", c)
	}
	if s := eventLoopInterimSuppressed(t, app, bot.ID); len(s) != 0 {
		t.Fatalf("suppressed rows %+v", s)
	}
	if b := eventLoopBatchCounts(t, app, bot.ID); len(b) != 2 {
		t.Fatalf("batches %v", b)
	}
}

func TestTesterEvR5CapOrdering(t *testing.T) {
	m := newAsyncModel("run_shell", "mid", "final answer", true)
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	seen := make(chan int, 8)
	app := newApp(t, "", m)
	app.editPol(func(p *policy.Policy) { p.EventLoop = true })
	app.eventClk = clk
	app.eventLoopMaxInterim = 2
	app.interimCapSeen = func(n int) { seen <- n }
	app.toolExec = tool.exec
	t.Cleanup(tool.letGo)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "CapOrder")
	postUser(t, srv.URL, bot.ID, "go")
	waitCh(t, tool.started, "tool")
	fireInterim(t, srv.URL, bot.ID, "a1", clk, m.entered, 1)
	fireInterim(t, srv.URL, bot.ID, "a2", clk, m.entered, 2)
	step := func(input string) int {
		if input == "" {
			app.kick(bot.ID)
		} else {
			postUser(t, srv.URL, bot.ID, input)
		}
		clk.Advance(500 * time.Millisecond)
		select {
		case n := <-seen:
			return n
		case <-time.After(5 * time.Second):
			t.Fatalf("window %q not observed", input)
		}
		return -1
	}
	if n := step(""); n != 0 {
		t.Fatalf("wake1 %d", n)
	}
	if n := step("b1"); n == 0 {
		t.Fatal("b1 not counted as input")
	}
	if n := step("b2"); n == 0 {
		t.Fatal("b2 not counted as input")
	}
	assertNoEntered(t, m.entered)
	tool.letGo()
	waitIdle(t, srv.URL, bot.ID, "")
	supp := waitInterimSuppressed(t, app, bot.ID, 1)
	caps := eventLoopInterimCaps(t, app, bot.ID)
	if len(caps) != 1 || caps[0].Count != 2 || caps[0].Cap != 2 {
		t.Fatalf("caps %+v", caps)
	}
	if len(supp) != 1 || supp[0].Suppressed != 2 || supp[0].Count != 2 || supp[0].Cap != 2 {
		t.Fatalf("supp %+v", supp)
	}
	assertCappedBeforeSuppressed(t, app, bot.ID)
}

func TestTesterEvR5WakeAfterCappedInput(t *testing.T) {
	m := newAsyncModel("run_shell", "mid", "final answer", true)
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	seen := make(chan int, 8)
	app := newApp(t, "", m)
	app.editPol(func(p *policy.Policy) { p.EventLoop = true })
	app.eventClk = clk
	app.eventLoopMaxInterim = 2
	app.interimCapSeen = func(n int) { seen <- n }
	app.toolExec = tool.exec
	t.Cleanup(tool.letGo)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "WakeAfter")
	postUser(t, srv.URL, bot.ID, "go")
	waitCh(t, tool.started, "tool")
	fireInterim(t, srv.URL, bot.ID, "a1", clk, m.entered, 1)
	fireInterim(t, srv.URL, bot.ID, "a2", clk, m.entered, 2)
	step := func(input string) int {
		if input == "" {
			app.kick(bot.ID)
		} else {
			postUser(t, srv.URL, bot.ID, input)
		}
		clk.Advance(500 * time.Millisecond)
		select {
		case n := <-seen:
			return n
		case <-time.After(5 * time.Second):
			t.Fatalf("window %q not observed", input)
		}
		return -1
	}
	if n := step(""); n != 0 {
		t.Fatalf("wake1 %d", n)
	}
	if n := step("b1"); n == 0 {
		t.Fatal("b1 not counted as input")
	}
	if n := step(""); n != 0 {
		t.Fatalf("wake2 %d", n)
	}
	if n := step("b2"); n == 0 {
		t.Fatal("b2 not counted as input")
	}
	assertNoEntered(t, m.entered)
	tool.letGo()
	waitIdle(t, srv.URL, bot.ID, "")
	supp := waitInterimSuppressed(t, app, bot.ID, 1)
	caps := eventLoopInterimCaps(t, app, bot.ID)
	if len(caps) != 1 || caps[0].Count != 2 || caps[0].Cap != 2 {
		t.Fatalf("caps %+v", caps)
	}
	if len(supp) != 1 || supp[0].Suppressed != 2 || supp[0].Count != 2 || supp[0].Cap != 2 {
		t.Fatalf("supp %+v", supp)
	}
	assertCappedBeforeSuppressed(t, app, bot.ID)
}

func assertCappedBeforeSuppressed(t *testing.T, app *App, botID string) {
	t.Helper()
	ev, err := app.st.ListLog(botID, "", "", 500)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for i := len(ev) - 1; i >= 0; i-- {
		k := ev[i].Kind
		if strings.HasPrefix(k, "event_loop_") {
			order = append(order, k)
		}
	}
	ci, si := -1, -1
	for i, k := range order {
		if k == "event_loop_interim_capped" && ci < 0 {
			ci = i
		}
		if k == "event_loop_interim_capped_suppressed" {
			si = i
		}
	}
	if ci < 0 || si < 0 || ci > si {
		t.Fatalf("capped at %d suppressed at %d: %v", ci, si, order)
	}
}

func TestInterimR6PathMarks(t *testing.T) {
	const leaf = "fixture-leaf"
	cases := []struct {
		name   string
		in     string
		banned []string
		mark   string
	}{
		{name: "percent_5c", in: `%5C%5Cserver%5Cshare\` + leaf, banned: []string{leaf, "%5C", "%5c", `\\server`}, mark: "[path]"},
		{name: "percent_5c_lower", in: `%5c%5cserver%5cshare\` + leaf, banned: []string{leaf, "%5c", "%5C"}, mark: "[path]"},
		{name: "at_abs", in: "loaded@/abs/" + leaf, banned: []string{leaf}, mark: "[path]"},
		{name: "at_home", in: "loaded@/home/fixture-user/" + leaf, banned: []string{leaf, "fixture-user"}, mark: "[path]"},
		{name: "tilde_user", in: "~fixture-user/" + leaf + "/x", banned: []string{leaf, "fixture-user"}, mark: "[path]"},
		{name: "space_posix", in: "/home/fixture-user/My Files/" + leaf, banned: []string{leaf, "My Files"}, mark: "[path]"},
		{name: "space_win", in: `C:\Users\fixture-user\My Documents\` + leaf, banned: []string{leaf, "My Documents"}, mark: "[path]"},
		{name: "space_quoted", in: `"/home/fixture-user/My Files/` + leaf + `"`, banned: []string{leaf, "My Files"}, mark: "[path]"},
		{name: "percent_252f", in: "%252Fabs%252F" + leaf, banned: []string{leaf, "%252F", "%2F"}, mark: "[path]"},
		{name: "percent_252f_lower", in: "%252fabs%252f" + leaf, banned: []string{leaf, "%252f", "%2f"}, mark: "[path]"},
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
}

func TestInterimR6HostMarks(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		banned []string
		mark   string
		exact  string
	}{
		{name: "ipv6_bracket", in: "see [2001:db8::1] now", banned: []string{"2001:db8", "[[host]]"}, mark: "[host]", exact: "see [host] now"},
		{name: "dial_hostname", in: "dial tcp dummy-host.example:11434", banned: []string{"dummy-host.example"}, mark: "[host]"},
		{name: "dial_label", in: "dial tcp dummy-svc:11434", banned: []string{"dummy-svc"}, mark: "[host]"},
		{name: "zone_bare", in: "see fe80::1%eth0 now", banned: []string{"fe80::1", "%eth0", "eth0"}, mark: "[host]"},
		{name: "zone_bracket", in: "see [fe80::1%eth0] now", banned: []string{"fe80::1", "%eth0", "eth0", "[[host]]"}, mark: "[host]", exact: "see [host] now"},
		{name: "bare_host_port", in: "refused dummy-host.example:22", banned: []string{"dummy-host.example"}, mark: "[host]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, msg := interimAuditError(errors.New(c.in))
			if !utf8.ValidString(msg) {
				t.Fatalf("invalid utf-8 %q", msg)
			}
			if c.exact != "" && msg != c.exact {
				t.Fatalf("message %q want %q", msg, c.exact)
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
}

func TestTesterEvR5HostAdjacent(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		banned []string
	}{
		{name: "v4-space", in: "peers 192.0.2.11 192.0.2.12 down", banned: []string{"192.0.2.11", "192.0.2.12"}},
		{name: "v4-comma", in: "peers 192.0.2.21,192.0.2.22", banned: []string{"192.0.2.21", "192.0.2.22"}},
		{name: "v4-start-end", in: "192.0.2.31", banned: []string{"192.0.2.31"}},
		{name: "v6-space", in: "peers 2001:db8::11 2001:db8::12 down", banned: []string{"2001:db8::11", "2001:db8::12"}},
		{name: "v4-port", in: "connect 192.0.2.41:11434 refused", banned: []string{"192.0.2.41"}},
		{name: "v4-mapped", in: "addr ::ffff:192.0.2.51 x", banned: []string{"192.0.2.51"}},
		{name: "hostname-url", in: "Get https://dummy-host.example:8443/x", banned: []string{"dummy-host.example"}},
		{name: "hostname-x509", in: "x509: certificate is valid for dummy-a.example, not dummy-b.example", banned: []string{"dummy-a.example", "dummy-b.example"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, msg := interimAuditError(errors.New(c.in))
			if !strings.Contains(msg, "[host]") && !strings.Contains(msg, "[path]") {
				t.Fatalf("message %q missing a mark", msg)
			}
			for _, ban := range c.banned {
				if strings.Contains(msg, ban) {
					t.Fatalf("message %q still has %q", msg, ban)
				}
			}
		})
	}
}

func TestInterimR6Readable(t *testing.T) {
	t.Run("url_http", func(t *testing.T) {
		_, msg := interimAuditError(errors.New(`Post "http://127.0.0.1:11434/api/chat"`))
		if strings.Contains(msg, "127.0.0.1") || strings.Contains(msg, "11434") {
			t.Fatalf("literal remains %q", msg)
		}
		if strings.Contains(msg, "[path]]") || strings.Contains(msg, "http:[path]]") {
			t.Fatalf("stray bracket %q", msg)
		}
		if !strings.Contains(msg, `Post "http:[path]"`) && !strings.Contains(msg, "http://[host]") {
			t.Fatalf("unreadably rewritten %q", msg)
		}
	})
	t.Run("lookup_colon", func(t *testing.T) {
		_, msg := interimAuditError(errors.New("lookup ollama: no such host"))
		if !strings.Contains(msg, "lookup [host]:") {
			t.Fatalf("lost the colon %q", msg)
		}
		if strings.Contains(msg, "lookup [host] no") {
			t.Fatalf("colon dropped %q", msg)
		}
		if strings.Contains(msg, "ollama") {
			t.Fatalf("host remains %q", msg)
		}
	})
	t.Run("dotted_version", func(t *testing.T) {
		in := "go1.22.3 runtime 1.2.3.4 build"
		_, msg := interimAuditError(errors.New(in))
		if msg != in {
			t.Fatalf("version rewritten %q", msg)
		}
	})
}

func TestInterimRedactBeforeClip(t *testing.T) {
	const secret = "sk-ant-api03-DUMMYR6PINVALUE99"
	if got := audit.RedactText("before " + secret + " after"); got != "before [redacted] after" {
		t.Fatalf("dummy is not a RedactText shape: %q", got)
	}
	// Non-word padding keeps a token boundary. A clip-then-redact swap
	// would keep the "sk-ant-" prefix inside the 200-byte cut.
	pre := 193
	in := strings.Repeat("=", pre) + secret
	_, msg := interimAuditError(errors.New(in))
	if strings.Contains(msg, secret) || strings.Contains(msg, "sk-ant") {
		t.Fatalf("secret prefix remains %q", msg)
	}
	if !utf8.ValidString(msg) {
		t.Fatalf("invalid utf-8 %q", msg)
	}
	if len(msg) > 200 {
		t.Fatalf("len %d over 200", len(msg))
	}
}

func TestExecShellAsyncNilBudgetWritesRefused(t *testing.T) {
	m := newAsyncModel("run_shell", "mid", "final answer", true)
	tool := newGateTool("shell-ok")
	clk := newManualClock()
	app := newApp(t, "", m)
	app.editPol(func(p *policy.Policy) { p.EventLoop = true })
	app.eventClk = clk
	app.toolExec = tool.exec
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "NilRefuseRow")
	run, err := app.st.CreateRun(bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	app.rtMu.Lock()
	app.loops[bot.ID] = &loopState{running: true, runID: run.ID, gen: 1}
	app.rtMu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = app.execShellAsync(context.Background(), bot, run.ID, "run_shell",
			map[string]any{"command": "echo hi"}, 0, nil, "", map[string]bool{},
			"test-model", app.pol(), nil)
	}()
	t.Cleanup(func() {
		tool.letGo()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	waitCh(t, tool.started, "shell")
	postUser(t, srv.URL, bot.ID, "m1")
	clk.Advance(500 * time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for nilRefusedCount(app, bot.ID) < 1 {
		select {
		case n := <-m.entered:
			t.Fatalf("nil budget started interim %d", n)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("nil refusals %d, want >= 1", nilRefusedCount(app, bot.ID))
		}
		time.Sleep(5 * time.Millisecond)
	}
	ev, err := app.st.ListLog(bot.ID, "event_loop_interim_refused", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) == 0 {
		t.Fatal("exec path wrote no event_loop_interim_refused row")
	}
	var row struct {
		RunID string `json:"run_id"`
		Count int    `json:"count"`
	}
	if err := json.Unmarshal(ev[0].Detail, &row); err != nil {
		t.Fatal(err)
	}
	if row.RunID != run.ID || row.Count < 1 {
		t.Fatalf("refused row %+v", row)
	}
	assertNoInterimCapStory(t, app, bot.ID)
	tool.letGo()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shell did not return")
	}
}

func TestInterimR6RatioUnchanged(t *testing.T) {
	_, ratio := interimAuditError(errors.New("ratio 1/2"))
	if ratio != "ratio 1/2" {
		t.Fatalf("ratio message %q", ratio)
	}
}

func TestInterimR6DialKeepsPort(t *testing.T) {
	_, msg := interimAuditError(errors.New("dial tcp dummy-host.example:11434"))
	if !strings.Contains(msg, "[host]:11434") {
		t.Fatalf("dial port lost %q", msg)
	}
	if strings.Contains(msg, "dummy-host.example") {
		t.Fatalf("host remains %q", msg)
	}
}
