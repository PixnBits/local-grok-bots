package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/coi"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// lgb gives a CLI bot the daemon's state tools (timers, memory, other bots,
// DMs) without MCP and without network. The CLI's sandbox blocks sockets
// (Grok's restrict_network refuses even a unix socket in the workspace), so
// the transport is a spool in the workspace, which both sandboxes let the
// CLI write: the lgb script drops a request file, the daemon answers it.
// A request carries a per-run token that is not the admin token, is valid
// only while the run lives, and reaches only lgbTools. Parsing happens here,
// in the daemon; the script only passes argv.

const (
	lgbDirName       = ".lgb"
	lgbMaxReq        = 64 << 10
	lgbPoll          = 100 * time.Millisecond
	lgbMaxCalls      = 200
	coiMaxConcurrent = 4
)

var errSpoolFile = errors.New("lgb: bad spool file")

// errRequestTooLarge is a spool file over lgbMaxReq. It is not the same as
// a link or a non-regular file, which stay "unreadable".
var errRequestTooLarge = errors.New("request too large (max 64 KiB)")

var lgbReqName = regexp.MustCompile(`^[0-9a-f]{16,64}$`)

// lgbScript is POSIX sh: it needs only sh, od, tr, mv, cat, and sleep, all of
// which both CLI sandboxes allow to read and run.
const lgbScript = `#!/bin/sh
# lgb: daemon state tools for this bot. Written by local-grok-bots each run.
d="${LGB_SPOOL:-}"
if [ -z "$d" ] || [ -z "${LGB_TOKEN:-}" ] || [ ! -d "$d/req" ]; then
  echo "lgb: not available in this run" >&2; exit 2
fi
id=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
tmp="$d/req/.$id"
{ printf '%s\0' "$LGB_TOKEN"; for a in "$@"; do printf '%s\0' "$a"; done; } > "$tmp" || exit 2
mv "$tmp" "$d/req/$id" || exit 2
i=0
while [ ! -f "$d/resp/$id" ]; do
  i=$((i+1))
  if [ "$i" -gt 600 ]; then echo "lgb: the daemon did not answer" >&2; exit 2; fi
  sleep 0.1
done
code=$(head -n 1 "$d/resp/$id")
tail -n +2 "$d/resp/$id"
rm -f "$d/resp/$id"
exit "$code"
`

// coiScript is the same spool client as lgb, with the command fixed to "coi".
// It waits up to an hour so a policy timeout inside that hour can finish.
const coiScript = `#!/bin/sh
# coi: host CLI broker for this bot. Written by local-grok-bots each run.
d="${LGB_SPOOL:-}"
if [ -z "$d" ] || [ -z "${LGB_TOKEN:-}" ] || [ ! -d "$d/req" ]; then
  echo "coi: not available in this run" >&2; exit 2
fi
id=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
tmp="$d/req/.$id"
{ printf '%s\0' "$LGB_TOKEN"; printf '%s\0' coi; for a in "$@"; do printf '%s\0' "$a"; done; } > "$tmp" || exit 2
mv "$tmp" "$d/req/$id" || exit 2
i=0
while [ ! -f "$d/resp/$id" ]; do
  i=$((i+1))
  if [ "$i" -gt 36000 ]; then echo "coi: the daemon did not answer" >&2; exit 2; fi
  sleep 0.1
done
code=$(head -n 1 "$d/resp/$id")
tail -n +2 "$d/resp/$id"
rm -f "$d/resp/$id"
exit "$code"
`

// lgbRun is one run's spool. stop() ends it and invalidates the token.
type lgbRun struct {
	a      *App
	bot    store.Bot
	runID  string
	token  string
	root   string
	req    *spoolDir
	resp   *spoolDir
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	calls  int
	coiWG  sync.WaitGroup
	coiSem chan struct{}
}

// startLGB prepares DATA_DIR/workspace/<bot>/.lgb and starts answering. It
// returns the env to add (PATH, LGB_SPOOL, LGB_TOKEN). Any failure leaves the
// bot without lgb; the turn still runs.
func (a *App) startLGB(ctx context.Context, bot store.Bot, runID, ws string) (*lgbRun, map[string]string, error) {
	if !a.policy.CLILGB || !lgbSupported {
		return nil, nil, nil
	}
	root := filepath.Join(ws, lgbDirName)
	// Rebuilt every run so nothing the bot left there (links, files) survives.
	if err := os.RemoveAll(root); err != nil {
		return nil, nil, err
	}
	for _, d := range []string{root, filepath.Join(root, "bin"), filepath.Join(root, "req"), filepath.Join(root, "resp")} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return nil, nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "lgb"), []byte(lgbScript), 0o700); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "coi"), []byte(coiScript), 0o700); err != nil {
		return nil, nil, err
	}
	req, err := openSpoolDir(filepath.Join(root, "req"))
	if err != nil {
		return nil, nil, err
	}
	resp, err := openSpoolDir(filepath.Join(root, "resp"))
	if err != nil {
		req.close()
		return nil, nil, err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		req.close()
		resp.close()
		return nil, nil, err
	}
	cctx, cancel := context.WithCancel(ctx)
	r := &lgbRun{a: a, bot: bot, runID: runID, token: "lgbr_" + hex.EncodeToString(buf), root: root,
		req: req, resp: resp, cancel: cancel, done: make(chan struct{}), coiSem: make(chan struct{}, coiMaxConcurrent)}
	a.noteRunToken(r.token, bot.ID, runID)
	go r.loop(cctx)
	env := map[string]string{
		"LGB_SPOOL": root,
		"LGB_TOKEN": r.token,
	}
	return r, env, nil
}

// lgbCred is the bot and run a live per-run token belongs to.
type lgbCred struct {
	botID string
	runID string
}

func (a *App) noteRunToken(token, botID, runID string) {
	if a == nil || token == "" {
		return
	}
	a.lgbMu.Lock()
	defer a.lgbMu.Unlock()
	if a.lgbLive == nil {
		a.lgbLive = map[string]lgbCred{}
	}
	a.lgbLive[token] = lgbCred{botID: botID, runID: runID}
}

func (a *App) forgetRunToken(token string) {
	if a == nil || token == "" {
		return
	}
	a.lgbMu.Lock()
	delete(a.lgbLive, token)
	a.lgbMu.Unlock()
}

// tokenOK reports whether tok is this run's live token for this bot.
func (r *lgbRun) tokenOK(tok string) bool {
	if r == nil || r.a == nil || r.token == "" || tok == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(tok), []byte(r.token)) != 1 {
		return false
	}
	r.a.lgbMu.Lock()
	defer r.a.lgbMu.Unlock()
	live, ok := r.a.lgbLive[tok]
	return ok && live.botID == r.bot.ID && live.runID == r.runID
}

func (a *App) lgbTokens() []string {
	if a == nil {
		return nil
	}
	a.lgbMu.Lock()
	defer a.lgbMu.Unlock()
	out := make([]string, 0, len(a.lgbLive))
	for token := range a.lgbLive {
		out = append(out, token)
	}
	return out
}

// stop ends the run's lgb: the token is dropped and pending requests are
// answered with an error by nobody (the script times out).
func (r *lgbRun) stop() {
	if r == nil {
		return
	}
	if r.a != nil {
		r.a.forgetRunToken(r.token)
	}
	r.cancel()
	<-r.done
	r.coiWG.Wait()
	r.token = ""
	r.req.close()
	r.resp.close()
	_ = os.RemoveAll(filepath.Join(r.root, "req"))
}

func (r *lgbRun) loop(ctx context.Context) {
	defer close(r.done)
	t := time.NewTicker(lgbPoll)
	defer t.Stop()
	for {
		r.drain(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (r *lgbRun) drain(ctx context.Context) {
	names, err := r.req.names()
	if err != nil {
		return
	}
	for _, name := range names {
		if !lgbReqName.MatchString(name) {
			continue
		}
		body, err := r.req.read(name, lgbMaxReq)
		r.req.remove(name)
		if err == nil && peekCOI(body) {
			r.spawnCOI(ctx, name, body)
			continue
		}
		var code int
		var out string
		if err != nil {
			code, out = 2, "lgb: unreadable request"
			if errors.Is(err, errRequestTooLarge) {
				code, out = 2, "lgb: "+errRequestTooLarge.Error()
			}
		} else {
			code, out = r.handle(ctx, body)
		}
		_ = r.resp.write(name, []byte(fmt.Sprintf("%d\n%s\n", code, strings.TrimRight(out, "\n"))))
	}
}

func peekCOI(body []byte) bool {
	parts := bytes.Split(bytes.TrimSuffix(body, []byte{0}), []byte{0})
	return len(parts) > 1 && string(parts[1]) == "coi"
}

func (r *lgbRun) spawnCOI(ctx context.Context, name string, body []byte) {
	r.coiWG.Add(1)
	go func() {
		defer r.coiWG.Done()
		select {
		case r.coiSem <- struct{}{}:
			defer func() { <-r.coiSem }()
		case <-ctx.Done():
			_ = r.resp.write(name, []byte("1\ncoi: timed out\n"))
			return
		}
		code, out := r.handle(ctx, body)
		_ = r.resp.write(name, []byte(fmt.Sprintf("%d\n%s\n", code, strings.TrimRight(out, "\n"))))
	}()
}

func (r *lgbRun) waitCOI() {
	r.coiWG.Wait()
}

// handle checks the token and runs one command. Every call is logged and
// audited with the run id.
func (r *lgbRun) handle(ctx context.Context, body []byte) (int, string) {
	parts := bytes.Split(bytes.TrimSuffix(body, []byte{0}), []byte{0})
	tok := string(parts[0])
	var args []string
	for _, p := range parts[1:] {
		args = append(args, string(p))
	}
	fields := map[string]any{"run_id": r.runID, "command": lgbCommand(args)}
	coiCall := len(args) > 0 && args[0] == "coi"
	if !r.tokenOK(tok) {
		if coiCall {
			r.auditCOI(coiName(args), coiRest(args), coi.StatusDenied, "bad token", "", nil, 0, false)
			return 2, "coi: not authorized"
		}
		fields["ok"] = false
		fields["error"] = "bad token"
		r.audit(fields)
		return 2, "lgb: not authorized"
	}
	r.mu.Lock()
	r.calls++
	n := r.calls
	r.mu.Unlock()
	if n > lgbMaxCalls {
		if coiCall {
			r.auditCOI(coiName(args), coiRest(args), coi.StatusDenied, "call limit", "", nil, 0, false)
			return 2, "coi: call limit for this turn reached"
		}
		fields["ok"] = false
		fields["error"] = "call limit"
		r.audit(fields)
		return 2, "lgb: call limit for this turn reached"
	}
	if coiCall {
		return r.execCOI(ctx, args[1:])
	}
	tool, targs, out, err := r.a.lgbParse(r.bot, args)
	if err == nil && tool != "" {
		fields["tool"] = tool
		fields["arguments"] = redactValue(targs)
		bot, gerr := r.a.st.GetBot(r.bot.ID)
		if gerr != nil {
			err = gerr
		} else {
			out, err = r.a.lgbExec(ctx, bot, tool, targs)
		}
	}
	fields["ok"] = err == nil
	if err != nil {
		fields["error"] = clip(err.Error(), 500)
		r.audit(fields)
		return 1, "lgb: " + err.Error()
	}
	r.audit(fields)
	return 0, out
}

func (r *lgbRun) audit(fields map[string]any) {
	r.a.log(r.bot.ID, "lgb_call", fields)
	if r.a.audit != nil && r.a.audit.Enabled() {
		rec := map[string]any{"event": "lgb_call", "bot_id": r.bot.ID}
		for k, v := range fields {
			rec[k] = v
		}
		r.a.audit.Write(rec)
	}
}

// lgbCommand is the first two words, for the log; arguments are logged
// redacted by tool.
func lgbCommand(args []string) string {
	if len(args) > 2 {
		args = args[:2]
	}
	return strings.Join(args, " ")
}

// lgbTools are the only daemon tools lgb reaches. No shell, file, grant, or
// permission tool is here, and none can be named through lgb.
var lgbTools = map[string]bool{
	"set_timer": true, "list_timers": true, "clear_timer": true,
	"write_memory": true, "delete_memory": true, "list_memory": true,
	"list_bots": true, "read_bot": true, "send_dm": true,
	"create_bot": true, "update_bot": true,
}

func (a *App) lgbExec(ctx context.Context, bot store.Bot, tool string, args map[string]any) (string, error) {
	if !lgbTools[tool] {
		return "", fmt.Errorf("%s is not an lgb tool", tool)
	}
	if (tool == "create_bot" || tool == "update_bot") && !a.policy.CLILGBManageBots {
		return "", errors.New("creating and updating bots is off by policy (cli.isolation.lgb_manage_bots)")
	}
	if tool == "list_memory" {
		mem, err := a.st.ListMemory(bot.ID)
		if err != nil {
			return "", err
		}
		var b strings.Builder
		for _, m := range mem {
			fmt.Fprintf(&b, "%s: %s\n", m.Key, m.Value)
		}
		if b.Len() == 0 {
			return "(no memory notes)", nil
		}
		return b.String(), nil
	}
	return a.execTool(ctx, bot, tool, args)
}

const lgbHelp = `lgb: daemon tools for this bot. Output is text; exit 0 on success.

  lgb timer in <duration> <prompt...> [--name NAME]   fire once after 90s, 5m, 2h, 1d
  lgb timer at <RFC3339 time> <prompt...> [--name NAME]
  lgb timer every <duration> <prompt...> [--name NAME]
  lgb timer list
  lgb timer cancel <id>
  lgb memory list
  lgb memory set <key> <value...>
  lgb memory delete <key>
  lgb bots                      list bots
  lgb bot <name|id>             read a bot's description and memory
  lgb dm <name|id> <message...> send a direct message
  lgb bot create <name> <description...> [--label LABEL]   if policy allows
  lgb bot update <name|id> [--name N] [--label L] [--description D]   if policy allows
  lgb coi <name> [args...]      run a granted host CLI; credentials stay on the host
  coi <name> [args...]          same command, from .lgb/bin

A timer's prompt comes back to you as a [scheduled] message.
Run each lgb command as its own shell call; a chained command (;, &&, |) asks for approval.`

// lgbUsage appends the bot-timer limits that are actually in force.
func (a *App) lgbUsage() string {
	min, perHour := a.policy.BotTimerLimits()
	if min == 0 && perHour == 0 {
		return lgbHelp
	}
	var b strings.Builder
	b.WriteString(lgbHelp)
	b.WriteString("\n")
	if min > 0 {
		fmt.Fprintf(&b, "Repeating timers must be at least %s apart (cli.lgb.min_timer_interval).\n", prettyDuration(min))
	}
	if perHour > 0 {
		fmt.Fprintf(&b, "At most %d scheduled turns per hour for this bot (cli.lgb.max_scheduled_per_hour).\n", perHour)
	}
	return strings.TrimRight(b.String(), "\n")
}

// guardBotTimer rejects a bot-created timer that would start too many paid
// turns. Ollama has no limit unless policy sets cli.lgb.*. User-created
// timers (the HTTP API) are not checked here.
func (a *App) guardBotTimer(botID string, every time.Duration, onceAt time.Time, oneShot bool) error {
	min, perHour := a.policy.BotTimerLimits()
	if !oneShot && min > 0 && every < min {
		return fmt.Errorf("repeating timer interval %s is shorter than the minimum %s (cli.lgb.min_timer_interval)", prettyDuration(every), prettyDuration(min))
	}
	if perHour <= 0 {
		return nil
	}
	rate, err := a.scheduledTurnRate(botID, every, onceAt, oneShot)
	if err != nil {
		return err
	}
	if rate > float64(perHour) {
		return fmt.Errorf("this bot would exceed %d scheduled turns per hour (cli.lgb.max_scheduled_per_hour)", perHour)
	}
	return nil
}

// scheduledTurnRate is the worse of two hourly counts: the steady rate of
// enabled repeating timers plus the busiest hour of pending one-shots, and
// timer fires already logged in the past hour plus this timer's own
// contribution. The past hour is included so a bot cannot refill the cap
// by creating another short timer after the previous ones have fired.
func (a *App) scheduledTurnRate(botID string, every time.Duration, onceAt time.Time, oneShot bool) (float64, error) {
	timers, err := a.st.ListTimers(botID)
	if err != nil {
		return 0, err
	}
	var repeat float64
	var once []time.Time
	for _, tm := range timers {
		if !tm.Enabled {
			continue
		}
		if tm.Schedule == store.OnceSchedule {
			when, perr := time.Parse(time.RFC3339Nano, tm.NextFireAt)
			if perr != nil {
				return 0, errors.New("scheduled turns could not be counted")
			}
			once = append(once, when)
			continue
		}
		d, perr := store.ParseInterval(tm.Schedule)
		if perr != nil || d <= 0 {
			return 0, errors.New("scheduled turns could not be counted")
		}
		repeat += float64(time.Hour) / float64(d)
	}
	var added float64
	if oneShot {
		once = append(once, onceAt)
		if onceAt.Before(time.Now().Add(time.Hour)) {
			added = 1
		}
	} else if every > 0 {
		added = float64(time.Hour) / float64(every)
		repeat += added
	}
	fired, err := a.st.CountLogSince(botID, "timer_fired", time.Now().Add(-time.Hour))
	if err != nil {
		return 0, err
	}
	projected := repeat + float64(busiestHour(once))
	recent := float64(fired) + added
	if recent > projected {
		return recent, nil
	}
	return projected, nil
}

// busiestHour is the most one-shots that fall inside any one-hour window.
func busiestHour(times []time.Time) int {
	if len(times) == 0 {
		return 0
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	best, j := 0, 0
	for i := range times {
		if j < i {
			j = i
		}
		for j < len(times) && times[j].Sub(times[i]) < time.Hour {
			j++
		}
		if n := j - i; n > best {
			best = n
		}
	}
	return best
}

func prettyDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// lgbParse maps argv to a tool and its arguments. help returns text and no tool.
func (a *App) lgbParse(bot store.Bot, args []string) (tool string, targs map[string]any, out string, err error) {
	usage := errors.New("unknown command; run lgb help")
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		return "", nil, a.lgbUsage(), nil
	}
	rest, flags := lgbFlags(args[1:])
	switch args[0] {
	case "timer", "timers":
		if len(rest) == 0 {
			return "", nil, "", usage
		}
		switch rest[0] {
		case "in", "at", "every":
			if len(rest) < 3 {
				return "", nil, "", fmt.Errorf("usage: lgb timer %s <when> <prompt...>", rest[0])
			}
			t := map[string]any{rest[0]: rest[1], "prompt": strings.Join(rest[2:], " ")}
			if n := flags["name"]; n != "" {
				t["name"] = n
			}
			return "set_timer", t, "", nil
		case "list", "ls":
			return "list_timers", map[string]any{}, "", nil
		case "cancel", "clear", "rm", "delete":
			if len(rest) != 2 {
				return "", nil, "", errors.New("usage: lgb timer cancel <id>")
			}
			return "clear_timer", map[string]any{"id": rest[1]}, "", nil
		}
	case "memory", "mem":
		if len(rest) == 0 {
			return "", nil, "", usage
		}
		switch rest[0] {
		case "list", "ls":
			return "list_memory", map[string]any{}, "", nil
		case "set", "write":
			if len(rest) < 3 {
				return "", nil, "", errors.New("usage: lgb memory set <key> <value...>")
			}
			return "write_memory", map[string]any{"key": rest[1], "value": strings.Join(rest[2:], " ")}, "", nil
		case "delete", "rm":
			if len(rest) != 2 {
				return "", nil, "", errors.New("usage: lgb memory delete <key>")
			}
			return "delete_memory", map[string]any{"key": rest[1]}, "", nil
		}
	case "bots":
		return "list_bots", map[string]any{}, "", nil
	case "bot":
		if len(rest) == 0 {
			return "", nil, "", errors.New("usage: lgb bot <name|id>")
		}
		switch rest[0] {
		case "create":
			if len(rest) < 3 {
				return "", nil, "", errors.New("usage: lgb bot create <name> <description...>")
			}
			t := map[string]any{"name": rest[1], "description": strings.Join(rest[2:], " ")}
			if l := flags["label"]; l != "" {
				t["label"] = l
			}
			return "create_bot", t, "", nil
		case "update":
			if len(rest) != 2 || len(flags) == 0 {
				return "", nil, "", errors.New("usage: lgb bot update <name|id> [--name N] [--label L] [--description D]")
			}
			t := map[string]any{}
			if other, ferr := a.st.FindBot(rest[1]); ferr == nil {
				t["id"] = other.ID
			} else {
				t["name"] = rest[1]
			}
			for _, k := range []string{"name", "label", "description"} {
				if v, ok := flags[k]; ok {
					t[k] = v
				}
			}
			return "update_bot", t, "", nil
		}
		if len(rest) != 1 {
			return "", nil, "", errors.New("usage: lgb bot <name|id>")
		}
		return "read_bot", map[string]any{"name": rest[0]}, "", nil
	case "dm":
		if len(rest) < 2 {
			return "", nil, "", errors.New("usage: lgb dm <name|id> <message...>")
		}
		return "send_dm", map[string]any{"to": rest[0], "content": strings.Join(rest[1:], " ")}, "", nil
	}
	return "", nil, "", usage
}

// lgbFlags splits --key value pairs from positional arguments.
func lgbFlags(args []string) ([]string, map[string]string) {
	flags := map[string]string{}
	var rest []string
	for i := 0; i < len(args); i++ {
		if k, ok := strings.CutPrefix(args[i], "--"); ok && k != "" {
			if key, v, eq := strings.Cut(k, "="); eq {
				flags[key] = v
				continue
			}
			if i+1 < len(args) {
				flags[k] = args[i+1]
				i++
				continue
			}
		}
		rest = append(rest, args[i])
	}
	return rest, flags
}
