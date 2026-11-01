# Permission broker

The broker decides whether one tool call may run. The jail is still the
security boundary. The broker is the ask path. It fails closed: a down,
late, or ambiguous answer is a deny. A non-admin path cannot approve a
call or create a rule.

The flag is off unless policy sets it. An ask exists only when `broker`
is `hook`. With the broker off there is no permission policy: the daemon
does not classify the command, does not open a card, and does not suspend
the run.

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

While `broker` is `hook`, the first policy load that finds a usable hook
records it: a content hash, device, inode, owner, mode, size, and mtime.
A later publish does not record a new pin. An unchanged path whose file
still matches the pin keeps it. A different `hook_path`, or a file that
no longer matches, keeps the old pin, audits `hook changed; re-pin required`,
and refuses later launches until an admin repin. Every armed launch
compares the file again. A difference refuses the turn and appends an
audit row. If the hook was missing or not usable when policy loaded, the
turn is refused even when the file is usable later. The refusal says the
hook was not pinned when the policy loaded. The
binary must be owned by the daemon user or root. Each directory from the
file up to `/` must not be group or world writable, including a sticky
directory. A symlink component is resolved and those directories are
checked the same way. The path must not sit inside a jail-writable root.

## Install the hook

Build both binaries from this repo. The script takes the repo and the
output directory from the environment or from its arguments. It does not
fetch, and it does not install.

```sh
LGB_REPO=. LGB_OUT_DIR=/var/tmp/lgb-build-placeholder bash deploy/build.sh
```

Install `lgb-permhook` as `root:root` mode `0755` at
`/usr/local/bin/lgb-permhook`. The directory and every parent up to `/`
must not be group or world writable. A mode `0775` directory fails that
check even when the file itself is `0755` and owned by root. The error
is `hook parent directory is group or world writable`. Set
`[cli.permission] hook_path` to that absolute path. An empty `hook_path`
uses `lgb-permhook` in the same directory as the daemon binary
(`os.Executable`). After the hook file is replaced, an admin calls
`POST /api/permbroker/hook/repin`. Publish does not record a new pin.

Each armed launch runs a copy of the pinned hook. The copy is mode 0500
in a mode 0700 directory under `DATA_DIR/permbroker/<bot-id>/launch/<run-id>/`.
Its sha256 is checked against the pin immediately after the copy. That
directory is on the critical set and the Claude deny list, with the
original hook path. Every evaluate, and every tool call seen on the CLI
stream, checks the pin and the copy again. A change denies that call,
ends the run with `hook changed`, and refuses further launches until the
admin repin.

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
glob that can match one of those names. Writes under `.git/info/`, `.gitmodules`, and
`~/.config/git/` (the bot home and the user home) ask at high or above.

The launch refuses bypass flags, `acceptEdits`, `dontAsk`,
`bypassPermissions`, `--dangerously-skip-permissions`, and the
allowed-tools spellings `--allowedTools`, `--allowed-tools`, and
`--allowed_tools`, including the `=` forms. It also refuses `--add-dir`
and `--plugin-dir`. It requires this settings file and exactly one empty
`--setting-sources`. An MCP config is refused unless it is the daemon's
own file. `--disallowedTools` may stay. Headless asks, including
stream-json control, are denied and do not open a card.

The broker arms only when the Claude binary the launch will run prints at
least 2.1.295. That check resolves the name with the launch environment's
PATH and runs that file with `--version`. The launch executes that same
absolute path. It does not look the name up again. The first stdout line must be `N.N.N (Claude Code)`,
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
it (parent walk, at most 64 steps). A
platform that cannot name the peer still denies. Any other peer is
denied with `permission broker unavailable`, audited, and does not use a
token or open a pending item. The socket
path has to fit in the platform's Unix address (108 bytes on Linux,
including the trailing NUL). A path that does not fit refuses the turn.

The hook is stdlib only. It waits at most 2.5 seconds, under the 30 second
settings timeout. The socket evaluate itself stops at 2 seconds. A result
that is already ready is the reply. If the deadline wins before that
result is stored, a once-token taken for the call is put back and the
reply is a deny. Exit 0 with a verdict of exactly `allow` is the only
allow. Every doubt exits 2 and prints a PreToolUse deny. Exit 2 blocks the
tool even if the JSON says allow. The hook never waits for a person.

On an ask, the daemon records a pending item and the hook denies with
`pending approval <id>; retry the identical command after approval`. The
hook does not wait. Its audit row is decision `ask`, actor `policy`.

For a native `run_shell` ask, the run stays `waiting`: it is paused until
a person approves or denies the pending card, and nothing runs meanwhile.
Approve resumes the same run once. Deny tells the model `denied by user`
and the run continues. A new user message, Stop, or deleting the bot
cancels a waiting run. A run that cannot be resumed is failed and the bot
returns to idle.

Paused calls are saved under `DATA/permbroker/checkpoints/`. They are
signed with a key at `DATA/permbroker/checkpoint.key` (mode 0600 in a
0700 directory). The key is kept with the daemon's other data and is not
mounted into the sandbox. Finished checkpoints and related markers are
removed after 7 days. Consumed decision records live beside those
checkpoints, signed with that key. A record is removed after 7 days
once its checkpoint file is gone.

A hook once-token is bound to the bot, session, tool, input hash, and cwd,
and it expires. The default lifetime is 15 minutes. A once-token kept
from a task, bot, or global approval stays held for that task. After the
task id changes, that token can still allow one call within the same
lifetime.
`[cli.permission] approval_ttl` sets it. The accepted range is 1 minute
to 24 hours inclusive. A value outside that range makes the policy fail
to load. The failure is fail closed: the jail stays on and CLI backends
are off. The value is not clamped into range. The cwd compared at use is the cleaned path, with symlinks
resolved when the directory exists. A trailing slash, a `.` or `..`
component, and a symlink to the same directory match. A different
directory does not. Claude Bash and `run_shell` share one shell name. A token for a
Read does not allow an Edit of the same bytes. A command that is critical
at retry time is not allowed by a token issued earlier; it asks again.
The same is true when the command's git config is a hard ask.

A deny does not stop the run, on any backend. The model keeps the reason
and the run stays `done`. Only an explicit stop stores `cancelled`.
A row stored earlier may still display "Stopped after denial." Nothing
new writes that status.

## Decisions

The engine evaluates in this order: a deny rule (including a deny on any
part of a compound), a one-time human token, then a critical level or a
command that is not one eligible argv. Those ask, unless a task grant
covers every part. Otherwise: per-bot rules, global rules when the level
is low or medium, a task grant, then ask. An ask beats an allow at the
same scope. Empty bot or session is a deny. The whole command is allowed
or it asks. A prefix is not allowed on its own.

A saved allow, a task grant, and a confirmed legacy allow are used only
on Linux, and only when the command and every compound part are literal
words. Anything else asks, including when a saved allow or a task grant
would otherwise match. A command that is not literal words can be
approved only once. Task, bot, and global are refused for that item. A
deny rule still denies. A human one-time approval is a separate path.

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
of 4 hours and `approval_ttl`. Grant cwd stays the raw string. A grant
made in one directory does not cover a subdirectory, the parent, or
another workspace. A trailing slash and a `.` segment are different
strings. The same session with a different task id does not use the
grant.

Daemon-run shells use a pinned PATH of root-owned directories and an
environment allowlist. A rule names a command only when argv0 resolves
to an allowlisted binary on that PATH. An assignment prefix is never
eligible. The jail git wrapper sets a narrow config for `run_shell`,
including an empty fsmonitor, no external diff, and a protocol list of
https and ssh. http is added only while the loopback credential proxy
is on. That wrapper is not treated as proof that every git invocation
inside the jail has those keys forced off. Claude is not rewritten.
Inside-workspace checks and the git baseline use that bot's directory
(`<workspace>/bots/<id>`), not the shared root. The shell jail binds
that same directory at `/work`. Another bot's tree is outside. The
baseline is `DATA_DIR/permbroker/git-baseline.json` (mode `0600`,
directory mode `0700`). Startup loads it. A bot with no stored baseline
is recorded once, at boot or on the first turn or shell that has a
workspace. A later turn does not record it again. A stored baseline in
the older piece set (no system git config piece, and one root
`.gitattributes` piece) is re-recorded in the current format when that
old digest still matches the current files and the home paths match.
The write is audited with actor `upgrade`. If a file differs, the old
record stays and the git command asks. Drift from the baseline makes a
git command ask, for Claude and for `run_shell`, even when an allow
rule matches. The pending item includes `git_reason`: `Git config
changed since it was last reviewed`, `A .gitattributes file changed`,
or `System git config changed`.
`POST /api/permbroker/bots/{id}/git-baseline` records a new baseline
after review. An unreadable baseline file makes those git commands ask
until an admin records one for that bot.

A Claude git command and a `run_shell` git command also ask, and cannot
be covered by a once-token, a task grant, or an allow rule, when the
scan finds any of the following. Config keys, in any subsection, are
`core.hooksPath`, `core.fsmonitor`, `core.sshCommand`, `core.pager`,
`core.editor`, `core.attributesFile`, `core.askPass`, `core.gitProxy`,
`diff.external`, `diff.<name>.textconv`, `diff.<name>.command`,
`merge.<name>.driver`, `alias.*`, `credential.helper`, `filter.*`,
`gpg.program`, `gpg.<format>.program`, `sequence.editor`,
`uploadpack.packObjectsHook`, `protocol.allow` set to `always`, and
`protocol.ext.allow` set to anything other than `never`. A
`url.<base>.insteadOf` or `pushInsteadOf` whose value starts with
`ext::` asks as well. `include` and `includeIf` still ask. Attribute
files ask when `diff`, `merge`, or `filter` is set to a driver name. A
bare `diff`, `-diff`, or `binary` does not. The scan reads the repo
config and include targets that resolve, every `.gitattributes` file in
the worktree, `<git-dir>/info/attributes`, the system git config, each home's `.gitconfig`,
`~/.config/git/config`, and `~/.config/git/attributes`, the file named
by `core.attributesFile`, and `GIT_*` variables in the environment
stored for that bot. A nested `.gitattributes` is read the same way as
the one at the worktree root. A directory reached by a symlink inside
the worktree that contains a `.gitattributes` file asks, and that file
is not added to the baseline. The walk skips the contents of `.git`
except `info/attributes`, which is read on its own. Too many attribute
files, or a tree that is too deep to finish, asks. A hook in
`<git-dir>/hooks` asks when it is a symlink or an executable file and
its name does not end in `.sample`. `core.hooksPath` is not followed.
The baseline covers the repo config, a digest of that hooks directory,
those attribute files, the system git config, and each home's git
config and attributes. The system git config path is resolved at
startup: the first file reported by `git config --system --list
--show-origin` when that file exists, otherwise `<prefix>/etc/gitconfig`
taken from `git --exec-path` when that file exists, otherwise
`/etc/gitconfig`. A change in any covered file asks until an admin
records a new baseline for that bot. The reason is recorded.

If the managed isolation environment has no PATH, the daemon fills one
and logs a single startup warning naming the PATH used to resolve the
CLI: the process PATH, or `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`
when the process PATH is empty. A non-empty managed PATH is kept.

Pending items do not expire. They are cancelled when the session ends,
when the bot is deleted or the daemon restarts, or when the ruleset
changes. Approving a cancelled item is refused (HTTP 409). Identical asks
collapse, including a repeat after a human deny.

`git push` as a literal simple command still uses the existing push
approval card. The broker does not rewrite git arguments. Risky git
config still asks, for Claude and for `run_shell`. A compound command
that contains a push goes through the broker instead. The audit row includes the shipped
table version.

`run_shell` calls the same engine in-process. A deny is the tool error.
The model can continue. The shell is not started.

The optional local classifier is off unless policy turns it on.

```toml
[cli.permission.classifier]
enabled = false
endpoint = "http://127.0.0.1:11434"
model = "local"
# timeout = "4s"   # default when enabled and unset
```

The endpoint, when set, must be loopback `http` or `https`: the host
`localhost`, or an address that is a loopback IP. A userinfo part is
refused. A non-loopback URL is a config error even when `enabled` is
false. An enabled classifier with an empty endpoint is the same error.
The daemon calls it only when `enabled` is true. The default timeout is
4 seconds.

The request body is the tool name, the redacted argv, and the model
name. The environment and file contents are not sent. The reply is one
JSON object, `{"level":"...","advisory":"..."}`, and nothing after it.
A timeout, a transport error, an unknown level, or a reply that is not
that object leaves the table level unchanged and sets the advisory to
`Not checked`. An empty level does not raise. Advisory text is stored
on the item with control characters removed and cut at 300 characters.
The note source is `table`, or `local model raised this to {level}`
when the rank goes up. The classifier can only raise a level or add
that note. It cannot lower a level and it cannot allow the call. When
the model raises a command to high or above relative to the table, an
existing bot or global allow asks.

A classifier result is eligible to contribute to an allow only for a
literal, eligible, non-compound command that is not critical and has
no git risk, on Linux, for a bot whose workspace and git baseline still
match. That guard does not itself allow the call.

## Risk levels

The shipped table is `builtin-2026-10-29.2`. The five levels are
`critical`, `high`, `medium`, `unclassified`, and `low`. Policy may
raise a level or repeat it. A lower level, or an unknown name, is a
startup error. A command the table does not list is `unclassified`.

| Level | What the table ships | Saved rule |
| --- | --- | --- |
| critical | `git config`, `git remote`, `gh auth`, `gh secret`, `gh ssh-key`, and a protected path | once only |
| high | `git push`, `gh pr merge`, and `gh` `api`, `alias`, `extension`, `config`, `variable`, `gpg-key`, `browse`. Non-shell `WebFetch`, `WebSearch`, `Task`, and `mcp__*` | bot, not global. `gh` rows above that are hard are once only |
| medium | git writes (`add`, `commit`, `checkout`, and the other write subcommands) and gh writes (`pr create`, `issue comment`, and the other write subcommands). Non-shell `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | bot or global |
| low | git reads (`status`, `log`, `diff`, `show`, and the other read subcommands), gh reads (`pr view`, `issue list`, and the other read subcommands), and `head`, `tail`, `wc`, `sort`, `uniq`, `cut`, `grep`, `jq` when the flags are in the table. Non-shell `Read`, `Glob`, `Grep` | bot or global |
| unclassified | any other command, including `ls`, `pwd`, and `echo` | once only. Not a task grant |

`ls`, `pwd`, and `echo` are unclassified. They are a hard ask, once
only. They are not task-grantable and not eligible for a bot or global
allow. The profile auto-allow list in `docs/cli-permissions.md` is a
different classifier.

A stricter row is:

```toml
[[cli.permission.risk]]
tool = "run_shell"   # shell, bash, and run_shell are the same name; empty means shell
argv = ["git", "status"]
level = "high"
```

## Rules file

Saved rules are `DATA_DIR/permbroker/rules.json` (mode `0600`, directory
mode `0700`). A row has an id, effect, scope, bot, argv or pattern,
kind (`exact`, `pattern`, or `legacy`; empty means exact), source,
whether an imported allow is still inactive, and created, last used,
and use count. `GET /api/permbroker/rules` lists them.
`DELETE /api/permbroker/rules/{id}` revokes one, including a
migrated legacy row. Revoke writes an audit row of ids and hashes,
bumps the ruleset, and the next evaluation asks again. The per-bot hook
socket cannot list or revoke.

## Rule migration

On startup the daemon copies each active profile permission rule into
the broker rules file. An exact command becomes an exact broker rule
with the same effect. A glob becomes a pattern only when every argv
that pattern matches also matched the original glob, and only when the
pattern syntax accepts it: the same number of tokens, `*` is one whole
token and is not a flag or a path separator, the first and last tokens
are literal, `*` is not inside a word, and the first token is not a
wrapper or interpreter. Anything else is a read-only legacy row. The
legacy allow keeps the original glob and does not grow to a longer
argv. Confirmed legacy allows match less than before: a legacy glob such as `git log*` now matches `git log` but not `git log --oneline`; add a pattern rule to cover more. An allow, whether pattern or legacy, never covers a critical
command, a compound, or a wrapper. A legacy or pattern allow copied
from a profile rule is stored inactive (`active` false,
`needs_confirm` true) and does not allow. A matching call asks until
an admin confirms that row with
`POST /api/permbroker/rules/{id}/confirm`. An exact command copied from
a profile rule, and an exact rule the broker saved, stays active.
Confirm writes an audit row with the id and a hash and bumps the
ruleset. A legacy deny or ask still matches, and its `*` may cross a
slash. Pattern syntax is unchanged: `*` is one non-flag token and does
not cross a slash. A task grant may cover a compound only when every
part is granted and none of those parts is a hard ask. A saved rule
does not. Each new row records source `migrated` and the original
text, and one audit row is written. The ruleset bumps once per batch.
The profile source is not deleted. A second start does not add
duplicates.

## Admin API

These routes require an admin token. When none is configured the
response is 403 `{"error":"admin token required"}`. Live mode with a
CLI backend and no `AUTH_TOKEN` writes `DATA_DIR/admin-token` and uses
that token. When a token is configured, a missing credential is 401 and
a live run token is 403. The same gate covers the non-broker permission
routes (the decision, the pending lists, and the durable
permission-rule routes). Auth is the registered route. A path that is
not one of those routes is not a broker handler. Routes that are not
permission routes stay open when no admin token is configured. Every
state-changing `/api` route (POST, PUT, PATCH, DELETE) uses the host
allowlist and the same cross-site check (`Sec-Fetch-Site` and
`Origin`). Those routes require `Content-Type: application/json` (a
parameter such as `charset` is allowed). Another type, or a missing
type on a request with a body, is 415. A DELETE with an empty body may
omit Content-Type. Non-broker permission writes still require a JSON
body: empty or non-JSON is 400. `POST /api/mcp/permission` and
`POST /api/mcp/permission/{token}` authenticate by token for the CLI
MCP client and do not require JSON Content-Type. `POST /api/stt`
accepts `application/octet-stream` audio and keeps its origin check.

- `GET /api/permbroker/pending` lists open items. Command text is redacted.
  Each item includes `bot_name`, `level`, `hard_ask`, `eligible`,
  `compound`, `allowed_scopes`, `parts`, `operators`, `advisory`,
  `task_text`, `suggest_always`, `critical_reason`, and `git_reason`.
  `allowed_scopes` is the subset of `once`, `task`, `bot`, and `global`
  that this item can take. Critical is `once`. A hard compound is
  `once`. A command that is not literal words is `once` only. High and
  unclassified omit `global`. `git_reason` is set when a git baseline
  changed. `parts` lists each
  command with `argv`, `raw`, `granted_for_task`, and `has_bot_rule`.
  `advisory` is `{text, source, checked}`. `task_text` is the user
  message that started the task, redacted and cut at 200 characters.
  `suggest_always` is true on a low or medium, non-compound command
  after two earlier human approvals of that same command within 24
  hours. Those approvals are `once`, `task`, `bot`, or `global`. The
  open item is not counted. The count is kept in memory.
  `critical_reason` is card copy when a path made the level critical,
  for example `Reads outside the workspace: /` or `Touches your home
  directory`. The level stays critical. `created_at` is the age.
- `POST /api/permbroker/pending/{id}` with `{"decision":"approve","scope":"once"}`
  or `"decision":"deny"`. `scope` is `once`, `task`, `bot`, or `global`.
  A deny does not end the run.
- `POST /api/permbroker/pending/deny-all` with `{"ids":["..."]}` denies
  those items. An empty body or `{"ids":[]}` is 400 and denies nothing.
  A stale or unknown id is skipped. The response is 200 with `results`
  (`id`, `ok`, `error`), `ok_count`, `skipped`, and `denied`. One stale
  id does not refuse the rest.
- `POST /api/permbroker/pending/approve-all` uses the same body and the
  same per-item result, with `approved` instead of `denied`. Each
  accepted id is approved once.
- `POST /api/permbroker/hook/repin` records the current hook file as the
  pin. Policy publish does not do this. The call is audited. A hook that
  is missing or not safe to run is refused and the old pin stays.
- `POST /api/permbroker/rules/{id}/confirm` activates one imported allow
  that is waiting for review. The call is audited with the id and a
  hash, and it bumps the ruleset. A row that is already active is refused.
  A legacy allow that can never match returns 400
  `{"error":"...","code":"never_matches"}`. The rules list includes
  `confirmable`, and `never_reason` when the row cannot match.
- `POST /api/permbroker/bots/{id}/git-baseline` records that bot's git
  baseline again. It does not bump the ruleset. The call is audited
  with the bot id.
- `GET /api/permbroker/rules` lists saved rules and current task grants.
  A rule includes `kind` (`exact`, `pattern`, or `legacy`), `effect`,
  `scope`, `bot_id`, `source_line`, `last_used_at`, `confirmable`, and
  `never_reason` when set. `task_grants`
  lists each live grant with `argv`, `raw`, `task_text`, and `expires`.
- `POST /api/permbroker/rules` creates a rule.
  `{"kind":"exact"|"pattern","argv":[...],"pattern":"...","scope":"bot"|"global","bot_id":"...","effect":"allow"|"ask"|"deny"}`.
  An exact rule that contains a shell operator is 400
  `{"error":"...","code":"operators"}`. A pattern uses the same checks
  as validate and returns 400 with `code` one of `trailing_wildcard`,
  `wrapper`, `flag_star`, `star_in_word`, `star_first`, or `operators`.
  An allow pattern does not cover a critical command or a compound when
  it matches. An exact or pattern allow whose command cannot be allowed
  by a rule returns 400 with `code` `never_matches`. A deny of a
  critical command is stored. The call uses the same origin check as
  the other broker posts.
- `POST /api/permbroker/rules/{id}/replace` stores the new rule, then
  revokes the old one. The body is the same shape as create. When both
  succeed the response is 200 with `created` and `revoked` true. When
  the new rule is stored and the revoke fails, both rules stay and the
  response is 207 with `created`, `revoked` false, and `error`.
- `POST /api/permbroker/patterns/validate` with `{"pattern":"..."}`
  returns `{"ok":true|false,"code":"...","message":"..."}`. A pattern
  that fails is still HTTP 200.
- `GET /api/permbroker/patterns/wrappers` returns the wrapper and
  interpreter names the validator uses.
- `POST /api/permbroker/patterns/preview` scores the last 50 evaluated
  requests in that scope against a draft. The body is the same shape as
  create. A bot scope uses that bot's ring. A global scope merges the
  rings and keeps the newest 50. Each row has redacted `argv`, `level`,
  `compound`, `time`, and `outcome`: `would_allow`, `would_ask`,
  `would_deny`, `still_asks_compound`, `still_asks_critical`, or
  `no_match`. A miss may set `reason` to `flag_in_star`, `extra_word`,
  or `missing_word`. `summary` counts every outcome, including zeros.
- `GET /api/permbroker/risk-tables` returns `{version, builtin, stricter}`.
  Each builtin row is `{level, matches, applies_to}`. A stricter row
  also has `raised_from`. The call does not write.
- `GET /api/permbroker/recent` returns the last 50 finished outcomes,
  newest first, redacted. `kind` is `allowed_by_rule` (with the rule
  id), `allowed_by_task_grant` (with a parts count), `denied_by_rule`,
  `approved`, `denied`, or `expired`. An open ask is not in this list.
- `DELETE /api/permbroker/rules/{id}` revokes one saved rule, including a
  read-only legacy row. The call is audited with the action and the id.

The socket accepts only `evaluate`. Approve, deny, create-rule, list, and
revoke on the socket are denies and do not change state.

`GET /api/permbroker/pending` returns the open items. Command text is
redacted. One item looks like:

```json
{
  "pending": [
    {
      "id": "p_example",
      "bot_id": "bot-id",
      "session_id": "sess",
      "run_id": "run",
      "task_id": "task",
      "tool": "shell",
      "argv": ["git", "status"],
      "command": "git status",
      "cwd": "/work",
      "level": "low",
      "hard_ask": false,
      "eligible": true,
      "allowed_scopes": ["once", "task", "bot", "global"],
      "parts": [
        {
          "argv": ["git", "status"],
          "raw": "git status",
          "granted_for_task": false,
          "has_bot_rule": false
        }
      ],
      "operators": [],
      "advisory": {"text": "", "source": "table", "checked": false},
      "task_text": "",
      "suggest_always": false,
      "critical_reason": "",
      "bot_name": "Ada",
      "input_hash": "0123456789abcdef",
      "created_at": "2026-10-30T00:00:00Z",
      "ruleset": 1
    }
  ]
}
```

On a host that is already on the allowlist, with the admin token in
`LGB_ADMIN_TOKEN`:

```sh
curl -sS -H "Authorization: Bearer $LGB_ADMIN_TOKEN" \
  "https://myhost.tailnet-example.ts.net/api/permbroker/pending"
curl -sS -X POST -H "Authorization: Bearer $LGB_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"decision":"approve","scope":"once"}' \
  "https://myhost.tailnet-example.ts.net/api/permbroker/pending/p_example"
curl -sS -H "Authorization: Bearer $LGB_ADMIN_TOKEN" \
  "https://myhost.tailnet-example.ts.net/api/permbroker/rules"
curl -sS -X DELETE -H "Authorization: Bearer $LGB_ADMIN_TOKEN" \
  "https://myhost.tailnet-example.ts.net/api/permbroker/rules/r_example"
curl -sS -X POST -H "Authorization: Bearer $LGB_ADMIN_TOKEN" \
  -H "Content-Type: application/json" -d '{}' \
  "https://myhost.tailnet-example.ts.net/api/permbroker/rules/r_example/confirm"
curl -sS -X POST -H "Authorization: Bearer $LGB_ADMIN_TOKEN" \
  -H "Content-Type: application/json" -d '{}' \
  "https://myhost.tailnet-example.ts.net/api/permbroker/bots/bot-id/git-baseline"
```

The broker flag is daemon-wide. `broker_bots` only limits which bots use
it. An empty list means every bot.

## Pages

HTML responses, including `/`, `/rules`, `/login`, and the signed-out
page, send `Content-Security-Policy: default-src 'self'; frame-ancestors
'none'; base-uri 'none'; form-action 'self'` and `X-Content-Type-Options: nosniff`. Scripts
and styles are same-origin files: `/theme.js`, `/app.css`, and
`/app.js`. The theme script loads from `/theme.js` before the page
paints. A `*` in a pattern stands for exactly one word and cannot be
last.

Browser notifications are sent only for a critical pending item, and
only when the tab is hidden and notification permission is on.

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
- a deadline that wins before the result is stored leaves a one-time approval unused
- a deadline after the token was taken either returns that result or puts the token back
- risky git config is a hard ask for run_shell as well as Claude git
- the shell jail binds the bot directory, and the Claude deny list names the hook, settings, permbroker, and the token file
- only an admin repin records a changed hook
- a hook that changes during a turn ends the run
- the launch executes the Claude path the version check accepted
- allowed-tools aliases are refused on a broker launch
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
- a non-literal command still asks when a bot allow or a task grant matches
- a non-literal command can be approved only once
- an old git baseline whose files still match is re-recorded and audited as upgrade; a real change asks with git_reason
- a task grant matches the raw cwd and the same task id
- deny-all and approve-all take an ids list, skip a stale id, and return per-item results
- confirming a legacy allow that cannot match returns never_matches; an ineligible allow is refused the same way; a deny of a critical command is stored
- a model raise to high makes an existing bot or global allow ask
- a symlinked directory that contains .gitattributes asks
- pages send the content security policy and nosniff headers
- replacing a rule keeps both when the revoke fails
- auto-allow asks when the OS is not Linux; a deny still denies
- a classifier reply cannot lower a level, and it cannot allow a compound, critical, git-risk, non-literal, or ineligible command
- a nested `.gitattributes` or the system git config asks the same way as the root attributes file
- broker routes and the other permission routes require an admin token, including when none is configured
- resolved critical-path forms, including a relative `cd`, a symlink, and a glob
- once-tokens and task grants expire at `approval_ttl`; pending items do not
- a same-uid process that is not the hook under the launched CLI is denied
- a once-token cwd matches the canonical directory
- profile rules migrate once and do not allow a critical command
- a pattern is token for token; a star is one argv token and is not a flag
- migration stores a pattern only when it is a subset of the original glob
- a legacy or pattern allow does not cover a wrapper, a critical command, or a compound
- a task grant covers a compound only when every part is granted and none is a hard ask
- a single deny and deny-all leave the run `done` on Ollama, Grok, and Claude
- listing and revoking rules is admin-only and takes effect on the next evaluation
- native file tools stay inside that bot's directory

The fake Claude enters hook mode only when `--settings` contains a
PreToolUse command. Launches that still set `disableAllHooks` keep the
previous permission-host behaviour.
