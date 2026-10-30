# Permission broker

The broker decides whether one tool call may run. The jail is still the
security boundary. The broker is the ask path. It fails closed: a down,
late, or ambiguous answer is a deny. A non-admin path cannot approve a
call or create a rule.

The flag is off unless policy sets it.

```toml
[cli.permission]
broker = "hook"   # off (default) or hook
# broker_bots = ["bot-id"]   # optional; empty means every bot
# hook_path = "/usr/local/bin/lgb-permhook"  # optional absolute path
```

`hook` arms two paths: Claude Code, through `cmd/lgb-permhook`, and the
daemon's `run_shell` tool. Anything else keeps today's behaviour, including
Grok's permission card. If the hook binary is missing or not safe to run,
that Claude turn stays on the locked-down settings (`disableAllHooks`)
instead of failing closed into a weaker mode.

A policy value other than `off` or `hook` is a startup error. A risk row
that lowers a shipped level, or names an unknown level, is a startup error.
Policy may raise a level or repeat it.

## Claude launch

Checked against the Claude Code docs on 2026-10-29:

- https://code.claude.com/docs/en/hooks
- https://code.claude.com/docs/en/hooks-guide
- https://code.claude.com/docs/en/settings
- https://code.claude.com/docs/en/managed-settings

When the hook is armed, the daemon writes `--settings` with one PreToolUse
command hook. The matcher is `*`. The command timeout is 30 seconds,
`onFailure` is `block`, and `continueOnBlock` is true. The file has no
allow rules. `disableAllHooks` is omitted. `--setting-sources=` is still
passed, so project `settings.json`, `settings.local.json`, and user
settings are not loaded. `allowManagedHooksOnly` in this file does not
lock hooks; that key applies only in managed settings. Installing
`/etc/claude-code/managed-settings.json` is out of scope.

The launch refuses bypass flags, `acceptEdits`, `dontAsk`,
`bypassPermissions`, and `--allowedTools`. `--disallowedTools` may stay.
Headless asks, including stream-json control, are denied and do not open a
card.

Claude is not inside the daemon's bubblewrap jail, so the hook command uses
the host socket path. The hook talks to a per-bot Unix socket under
`DATA_DIR/permbroker/<bot-id>/sock`. The directory is mode 0700 and the
socket is mode 0600. The peer's uid must be the daemon's uid. The socket
path has to fit in the platform's Unix address (108 bytes on Linux,
including the trailing NUL). A path that does not fit leaves the turn
locked down.

The hook is stdlib only. It waits at most 2.5 seconds, under the 30 second
settings timeout. Exit 0 with a verdict of exactly `allow` is the only
allow. Every doubt exits 2 and prints a PreToolUse deny. Exit 2 blocks the
tool even if the JSON says allow. The hook never waits for a person.

On an ask, the daemon records a pending item and the hook denies with
`pending approval <id>; retry the identical command after approval`. A
human approves that item, then the same command may be retried once. A
second retry, a different argv, a different cwd, or a different session
does not use that approval.

A deny does not stop the run. The model keeps the reason. The run stays
`done`. "Stopped after denial" remains the Grok card path.

## Decisions

The engine evaluates in this order: a deny rule (including a deny on any
part of a compound), a one-time human token, then a critical level or a
command that is not one eligible argv. Those ask, unless a task grant
covers every part. Otherwise: per-bot rules, global rules when the level
is low or medium, a task grant, then ask. An ask beats an allow at the
same scope. Empty bot or session is a deny. The whole command is allowed
or it asks. A prefix is not allowed on its own.

An exact argv rule matches one normalized literal simple command. The
key is the argv vector, shared by Claude Bash and `run_shell`. A
compound is not a rule. Critical commands cannot be saved as a rule.
Unclassified and high stop at per-bot. Global rules are only for low
and medium. One approval can be once, for the task, for the bot, or
global, within that ladder. The once token is bound to the bot, the
session, the input hash, and the cwd, and it is consumed on first use.

Shipped tables set levels for git, gh, path classes, and non-Bash tool
kinds. They do not allow a call. Policy may raise a level or repeat it.
A task grant may cover a compound only when every part is granted and
each part still passes critical and deny at request time. The grant is
bound to the bot, the session, and the user-message id. It ends on the
next user message for that bot, when the session ends, or after 4 hours.

Daemon-run shells use a pinned PATH of root-owned directories and an
environment allowlist. A rule names a command only when argv0 resolves
to an allowlisted binary on that PATH. An assignment prefix is never
eligible. The jail git wrapper forces a safe config for `run_shell`,
including an empty fsmonitor, no external diff, and a protocol list of
https and ssh. http is added only while the loopback credential proxy
is on. Claude is not rewritten. The daemon records `.git/config` and
`.gitattributes` at startup; a later change makes a Claude git command
ask until the daemon restarts.

Pending items do not expire. They are cancelled when the session ends,
when the bot is deleted or the daemon restarts, or when the ruleset
changes. Approving a cancelled item is refused (HTTP 409). Identical asks
collapse, including a repeat after a human deny.

`git push` as a literal simple command still uses the existing push
approval card. The broker does not rewrite git arguments. The jail
ignores the user's git config. A compound command that contains a push
goes through the broker instead. The audit row includes the shipped
table version.

`run_shell` calls the same engine in-process. A deny is the tool error.
The model can continue. The shell is not started.

The classifier stub can only raise a level. It cannot allow a call, and
it makes no model request.

## Admin API

These routes use the existing admin token, the host allowlist, and the
same cross-site check as other mutating admin routes (`Sec-Fetch-Site`
and `Origin`). A live run token is 403 even when the admin token is unset.

- `GET /api/permbroker/pending` lists open items. Command text is redacted.
- `POST /api/permbroker/pending/{id}` with `{"decision":"approve","scope":"once"}`
  or `"decision":"deny"`. `scope` is `once`, `task`, `bot`, or `global`.
- `POST /api/permbroker/pending/deny-all` denies every current item.
  `{"ids":["..."]}` denies that set, or nothing if any id is missing.
  `{"ids":[]}` denies none.

The socket accepts only `evaluate`. Approve, deny, and create-rule on the
socket are denies and do not change state.

## Audit

The daemon appends redacted rows to `DATA_DIR/permbroker/audit.jsonl`
(mode 0600) with a hash chain. Hook transport failures are not rows,
because the daemon did not make the decision. The mirror row in the
daemon audit log, when that log is enabled, is a short `permbroker`
event. Secrets in commands are redacted before they are stored.

## How to test

From the repo root:

```sh
gofmt -l .
go vet ./...
go test -race ./...
go test -v ./web/... | grep -i skip
```

`gofmt -l` prints nothing. The fail-closed tests are named `TestGolden_*`:

- daemon stopped
- daemon hangs past the hook deadline
- hook killed (the fake CLI treats SIGKILL as a non-blocking hook error,
  then the launch config denies, and the tool marker is absent)
- hook over the CLI timeout (same fall-through, without waiting 30 seconds)
- garbage, empty, unknown, and oversized verdicts
- ask, approve, identical retry once
- second retry, and a different argv, cwd, or session, blocked
- project and user Claude settings ignored
- jail socket cannot approve or create a rule
- deny lets the run continue
- classifier only escalates
- policy cannot lower a shipped level
- critical and compound commands cannot be saved as bot or global rules
- parsing bypasses stay denied when a literal allow rule or task grant exists
- a task grant covers a compound only when every part is granted
- a task grant ends on the next user message and after 4 hours
- one argv rule applies to Claude Bash and run_shell
- a deny rule beats a task grant
- a critical part inside a granted compound still asks

The fake Claude enters hook mode only when `--settings` contains a
PreToolUse command. Launches that still set `disableAllHooks` keep the
previous permission-host behaviour.
