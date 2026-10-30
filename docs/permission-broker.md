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
Grok's permission card. If the broker is on for a bot and the hook binary
is missing or not safe to run, the socket cannot be created, or the hook
path is unknown, that Claude turn is refused before the CLI starts. The
run error names the reason. When the broker is off for the bot, the turn
stays on the locked-down settings (`disableAllHooks`). When `broker` is
`hook` and the hook binary is not safe to run, startup prints a warning
with the other policy warnings.

While `broker` is `hook`, policy load records the hook binary: a content
hash, device, inode, owner, mode, size, and mtime. Every armed launch
compares the file again. A difference refuses the turn and appends an
audit row. If the hook was missing or not usable when policy loaded, the
turn is refused even when the file is usable later. The refusal says the
hook was not pinned when the policy loaded. Publishing policy again
records the file as it is then. The
binary must be owned by the daemon user or root. Each directory from the
file up to `/` must not be group or world writable, including a sticky
directory. A symlink component is resolved and those directories are
checked the same way. The path must not sit inside a jail-writable root.

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

The settings deny list also names the hook binary, that settings file and
its directory, and `DATA_DIR/permbroker`. A tool call that touches one of
those paths is critical: it always asks, and it is never a rule, a grant,
or a once-token. The Claude deny list is a second layer. Before that
check, each argv token and each redirect target is resolved: the working
directory after a leading `cd`, a short option glued to its value,
`--name=value`, and redirect targets. A relative path is joined to that
directory. Symlinks are resolved on the longest prefix that exists. `~`
and `$HOME` expand to the bot home and the user home. Other variables
expand from the bot's managed environment. A token whose base name is the
hook file, `permbroker`, or a settings file name is critical, and so is a
glob that can match one of those names. Command substitution is not run;
that text stays lexical. Writes under `.git/info/`, `.gitmodules`, and
`~/.config/git/` (the bot home and the user home) ask at high or above.

The launch refuses bypass flags, `acceptEdits`, `dontAsk`,
`bypassPermissions`, `--allowedTools`, `--add-dir`, and `--plugin-dir`.
It requires this settings file and exactly one empty `--setting-sources`.
An MCP config is refused unless it is the daemon's own file.
`--disallowedTools` may stay. Headless asks, including stream-json
control, are denied and do not open a card.

The broker arms only when the Claude binary the launch will run prints at
least 2.1.295. That binary is resolved the same way the launch resolves
it, using the launch environment's PATH, and the check runs that file
with `--version`. The first stdout line must be `N.N.N (Claude Code)`,
with trailing whitespace allowed. Stderr is ignored. A non-zero exit, any
other text, or an older release refuses the turn before the CLI starts.
The result is cached for that binary's path, size, and mtime. A hook
failure other than a normal allow or an exit-2 deny
blocks the tool because `onFailure` is `block`. Without that field, a
Read, Glob, or Grep would run and Bash would follow the locked-down
permission flow.

Claude is not inside the daemon's bubblewrap jail, so the hook command uses
the host socket path. The hook talks to a per-bot Unix socket under
`DATA_DIR/permbroker/<bot-id>/sock`. The directory is mode 0700 and the
socket is mode 0600. The peer's uid must be the daemon's uid. On Linux
the peer must also be the pinned hook binary: the device and inode of
`/proc/<pid>/exe` match the pinned file or a daemon-owned copy, and the
process is the CLI the daemon launched for that bot or a descendant of
it (parent walk, at most 64 steps). Other systems keep the uid check. A
platform that cannot name the peer still denies. Any other peer is
denied with `permission broker unavailable`, audited, and does not use a
token or open a pending item. The socket
path has to fit in the platform's Unix address (108 bytes on Linux,
including the trailing NUL). A path that does not fit refuses the turn.

The hook is stdlib only. It waits at most 2.5 seconds, under the 30 second
settings timeout. The socket evaluate itself stops at 2 seconds and the
deadline is a deny. A deadline deny does not spend a one-time approval or
a task grant. Exit 0 with a verdict of exactly `allow` is the only
allow. Every doubt exits 2 and prints a PreToolUse deny. Exit 2 blocks the
tool even if the JSON says allow. The hook never waits for a person.

On an ask, the daemon records a pending item and the hook denies with
`pending approval <id>; retry the identical command after approval`. A
human approves that item, then the same command may be retried once. A
second retry, a different argv, a different cwd, or a different session
does not use that approval. The once token is also bound to the tool
name, and it expires. The default lifetime is 15 minutes.
`[cli.permission] approval_ttl` sets it, bounded to 1 minute through 24
hours. The cwd compared at use is the cleaned path, with symlinks
resolved when the directory exists. A trailing slash, a `.` or `..`
component, and a symlink to the same directory match. A different
directory does not. Claude Bash and `run_shell` share one shell name. A token for a
Read does not allow an Edit of the same bytes. A command that is critical
at retry time is not allowed by a token issued earlier; it asks again.
The same is true when the command's git config is a hard ask.

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
session, the tool name, the input hash, and the cwd, and it is consumed
on first use. A policy reload bumps the ruleset. That cancels pending
items, once-tokens, and task grants, and the cancel is audited.

Shipped tables set levels for git, gh, path classes, and non-Bash tool
kinds. They do not allow a call. Policy may raise a level or repeat it.
A task grant may cover a compound only when every part is granted and
each part still passes critical and deny at request time. The grant is
bound to the bot, the session, and the user-message id. It ends on the
next user message for that bot, when the session ends, or at the shorter
of 4 hours and `approval_ttl`. Grant cwd stays the raw string.

Daemon-run shells use a pinned PATH of root-owned directories and an
environment allowlist. A rule names a command only when argv0 resolves
to an allowlisted binary on that PATH. An assignment prefix is never
eligible. The jail git wrapper forces a safe config for `run_shell`,
including an empty fsmonitor, no external diff, and a protocol list of
https and ssh. http is added only while the loopback credential proxy
is on. Claude is not rewritten. Inside-workspace checks and the git
baseline use that bot's directory (`<workspace>/bots/<id>`), not the
shared root. Another bot's tree is outside. The daemon records the
baseline when the bot context is set; a later change makes a Claude git
command ask until the daemon restarts. A Claude git command also asks,
and cannot be covered by a once-token, a task grant, or an allow rule,
when that bot's git config contains `core.hooksPath`, `core.fsmonitor`,
`filter.*`, `include` or `includeIf`, `core.sshCommand`, `core.pager`,
`core.editor`, `diff.external`, or `credential.helper`. The scan covers
the repo config and include targets that resolve, `.git/info/attributes`,
`.gitattributes`, the bot home's git config, and `GIT_*` variables in
the managed CLI environment. The reason is recorded. `run_shell` keeps
the jail git wrapper and does not use that ask.

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
it makes no model request. `ClassifierMayAllow` is false unless that bot
has a workspace and a git baseline. A later classifier contribution to
an allow has to pass that guard.

## Rule migration

On startup the daemon copies each active profile permission rule into
the broker rules file. An exact command becomes an exact broker rule
with the same effect. A glob that is one literal first word, `*` only
inside a word, and an optional trailing `**` for the remaining words is
stored as a pattern. Anything else is stored as a legacy record. Allow
patterns and legacy allows never cover a critical path or a compound.
Deny and ask patterns still apply. Each new row records source
`migrated` and the original text, and one audit row is written. The
ruleset bumps once per batch. The profile source is not deleted. A
second start does not add duplicates.

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
because the daemon did not make the decision. An approve, a deny, and
each item of a deny-all append a row when the decision is stored. A rule
save does the same. The row records the actor, the decision, the scope
when there is one, and the pending id when there is one. The mirror row
in the daemon audit log, when that log is enabled, is a short
`permbroker` event. Secrets in commands are redacted before they are stored.

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
- an unusable hook refuses the turn before the CLI starts
- daemon hangs past the hook deadline
- hook killed (the fake CLI treats SIGKILL as a non-blocking hook error;
  `onFailure` `block` denies a Read, and the tool marker is absent)
- hook over the CLI timeout (same block, without waiting 30 seconds)
- an older Claude release refuses the turn before the CLI starts
- the version check uses the Claude binary on the launch PATH
- a hook binary that changes after startup refuses the turn before the CLI starts
- a hook that was not pinned when policy loaded refuses the turn
- with the daemon critical paths set, a benign command can be approved once, granted for the task, or saved as a bot rule
- a command that touches a critical path stays critical
- a deadline deny leaves a one-time approval unused
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
- another bot's workspace is outside this bot
- risky git config is a hard ask for Claude git
- writes under `.git/info/`, `.gitmodules`, and `~/.config/git/` ask
- a classifier allow does not allow, and the guard is false without per-bot context
- resolved critical-path forms, including a relative `cd`, a symlink, and a glob
- once-tokens and task grants expire at `approval_ttl`; pending items do not
- a same-uid process that is not the hook under the launched CLI is denied
- a once-token cwd matches the canonical directory
- profile rules migrate once and do not allow a critical command

The fake Claude enters hook mode only when `--settings` contains a
PreToolUse command. Launches that still set `disableAllHooks` keep the
previous permission-host behaviour.
