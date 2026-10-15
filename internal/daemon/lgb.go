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
	"strings"
	"time"

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
	lgbDirName  = ".lgb"
	lgbMaxReq   = 64 << 10
	lgbPoll     = 100 * time.Millisecond
	lgbMaxCalls = 200
)

var errSpoolFile = errors.New("lgb: bad spool file")

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
	calls  int
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
		req: req, resp: resp, cancel: cancel, done: make(chan struct{})}
	go r.loop(cctx)
	env := map[string]string{
		"LGB_SPOOL": root,
		"LGB_TOKEN": r.token,
	}
	return r, env, nil
}

// stop ends the run's lgb: the token is dropped and pending requests are
// answered with an error by nobody (the script times out).
func (r *lgbRun) stop() {
	if r == nil {
		return
	}
	r.cancel()
	<-r.done
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
		var code int
		var out string
		if err != nil {
			code, out = 2, "lgb: unreadable request"
		} else {
			code, out = r.handle(ctx, body)
		}
		_ = r.resp.write(name, []byte(fmt.Sprintf("%d\n%s\n", code, strings.TrimRight(out, "\n"))))
	}
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
	if r.token == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(r.token)) != 1 {
		fields["ok"] = false
		fields["error"] = "bad token"
		r.audit(fields)
		return 2, "lgb: not authorized"
	}
	r.calls++
	if r.calls > lgbMaxCalls {
		fields["ok"] = false
		fields["error"] = "call limit"
		r.audit(fields)
		return 2, "lgb: call limit for this turn reached"
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

A timer's prompt comes back to you as a [scheduled] message.`

// lgbParse maps argv to a tool and its arguments. help returns text and no tool.
func (a *App) lgbParse(bot store.Bot, args []string) (tool string, targs map[string]any, out string, err error) {
	usage := errors.New("unknown command; run lgb help")
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		return "", nil, lgbHelp, nil
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
