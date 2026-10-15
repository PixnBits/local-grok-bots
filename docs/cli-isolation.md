# CLI config isolation

Policy is the only configuration a Claude or Grok turn should obey. Both CLIs
also read user, project, and local files and environment variables. The daemon
launches them so that those sources do not apply, and refuses the turn when it
cannot guarantee that.

## Policy

```toml
[cli.isolation]
# ignore (default): the CLI is told not to load workspace config files.
# refuse: any workspace override file fails the turn closed.
overrides = "ignore"
# isolated (default): per-bot HOME under DATA_DIR/cli/<bot>/home.
# user: the daemon user's HOME for every backend. Only managed policy can set this.
home = "isolated"
# Claude only. auto (default): the user's HOME on macOS, isolated elsewhere.
# isolated: per-bot HOME on every OS. user: managed policy only.
# home = "user" overrides this.
claude_home = "auto"
# Claude only. required (default): Claude's Bash sandbox on, fail closed.
# off: the daemon writes no sandbox block. Managed policy only.
claude_sandbox = "required"
# lgb: daemon state tools for CLI bots (default true).
lgb = true
# Let lgb create and update other bots (default false).
lgb_manage_bots = false
# Added to the scrubbed environment. Only managed policy can set this.
# env = { ANTHROPIC_BASE_URL = "https://gateway.corp.example" }
```

## Launch

Every CLI turn gets a fresh environment. Nothing is inherited except
`PATH`, `LANG`, `LC_*`, `TERM`, `TZ`, `USER`, `LOGNAME`, `SHELL`, `TMPDIR`,
the proxy variables, `SSL_CERT_FILE`/`SSL_CERT_DIR`/`NODE_EXTRA_CA_CERTS`,
the daemon's own `LGB_*`, and the backend credential
(`ANTHROPIC_API_KEY`/`CLAUDE_CODE_OAUTH_TOKEN` for Claude, `XAI_API_KEY` for
Grok). Every other `ANTHROPIC_*`, `CLAUDE_*`, and `GROK_*` variable is dropped,
including `ANTHROPIC_BASE_URL`, `CLAUDE_CONFIG_DIR`, `GROK_CONFIG`, and
`GROK_SANDBOX`. Managed `cli.isolation.env` is applied last.

With `home = "isolated"`, `HOME` is `DATA_DIR/cli/<bot>/home`. The only file
shared with the user's home is a symlink to the login credential
(`~/.claude/.credentials.json`, `~/.grok/auth.json`). Settings, hooks, MCP
servers, skills, memory, and folder-trust grants stay behind. Sessions live in
the per-bot home, so a session started before this change cannot be resumed;
the bot starts a fresh one.

### Claude home per OS

Claude on macOS keeps its login in the Keychain, and a different
`CLAUDE_CONFIG_DIR` or `HOME` may keep it from finding that login. So under
`claude_home = "auto"`:

| OS | HOME | CLAUDE_CONFIG_DIR | Login |
| --- | --- | --- | --- |
| darwin | the user's | not set (an inherited value is dropped) | Keychain / `~/.claude` as normal |
| linux and others | `DATA_DIR/cli/<bot>/home` | `<home>/.claude` | symlinked `.credentials.json` |

On macOS, isolation then rests on `--setting-sources=`, the daemon
`--settings` file, `--strict-mcp-config`, and the scrubbed environment. User
settings, `~/.claude/CLAUDE.md`, user hooks, and `~/.claude.json` MCP servers
still exist on disk but are not loaded, given the setting sources and strict MCP
config. Claude can still write session transcripts and other state under the
user's `~/.claude`. Grok is unchanged and always gets its own `GROK_HOME`.

### Login source record

On each bot's first Claude turn after the daemon starts, the daemon writes a
`cli_login` entry to the bot log and the audit sink with:

- `source`: what the launch provides. In order: `env_api_key`,
  `env_oauth_token` (variable names only), then `credentials_symlink` or
  `none_found` for an isolated home, or `keychain_or_user_home` (darwin) /
  `user_home` for the user's home;
- `os` and `own_home`;
- from `claude auth status` run with the same environment and cwd (10 s
  limit): `auth_method`, `logged_in`, and `config_directory`. Nothing else
  from its output is kept.

### Claude

- `--setting-sources=`: no user, project, or local settings, and so no
  `CLAUDE.md`, hooks, or `settings*.json` from them. This is the form the Agent
  SDK passes for `setting_sources=[]`. The daemon still reads the real user
  home's `~/.claude/settings.json` and copies that file's sandbox keys into
  the `--settings` file, as described under [Sandbox and tools](#sandbox-and-tools).
  Allow rules, hooks, and the rest of the user file are not copied.
- `--settings DATA_DIR/cli/<bot>/claude-settings.json`: daemon-written,
  `disableAllHooks`, `enableAllProjectMcpServers: false`, and the restrictions
  under [Sandbox and tools](#sandbox-and-tools).
- `--strict-mcp-config`: only the daemon's `--mcp-config` (the permission tool
  on the mcp transport), never `.mcp.json` or `~/.claude.json`.
- `CLAUDE_CONFIG_DIR=<home>/.claude`.
- Enterprise `managed-settings.json` still applies and still wins. That is
  intended.

### Grok

Grok has no flag to skip setting sources. The daemon:

- never passes `--trust`; with an isolated `GROK_HOME` there is no prior folder
  grant, so project `.grok/config.toml`, `.claude/settings*.json`, `AGENTS.md`,
  `CLAUDE.md`, project skills, and project hooks are not loaded;
- sets `GROK_HOME` to a daemon-owned directory, so `~/.grok/config.toml`,
  `~/.grok/rules`, user hooks and plugins do not load. With the default
  isolated home that directory is `<home>/.grok`. With managed `home = "user"`
  it is `DATA_DIR/cli/<bot>/grok-home`, and `HOME` stays the user's home;
- runs `--sandbox lgb`, a custom profile it writes into that `GROK_HOME` as
  `sandbox.toml` (see [Sandbox and tools](#sandbox-and-tools)). It does not
  write the user's `~/.grok/sandbox.toml`. A launch with no profile, or with
  a built-in name (`off`, `workspace`, `devbox`, `read-only`, `strict`), is
  refused before the process starts: those profiles run unenforced, with a
  warning, when Grok cannot apply them;
- hard links `~/.grok/auth.json` into that `GROK_HOME` (Grok 1.0.52 says
  "Not signed in" when it is a symlink); it relinks when the user's file is
  replaced, and falls back to a symlink across filesystems, so keep DATA_DIR
  on the same filesystem as HOME;
- sets every `GROK_CLAUDE_*_ENABLED` and `GROK_CURSOR_*_ENABLED` to `false`;
- drops `GROK_CONFIG`/`GROK_CONFIG_PATH`.

`/etc/grok/requirements.toml`, `/etc/grok/managed_config.toml`, and the synced
managed config still apply.

## Sandbox and tools

The daemon jail is off for CLI backends, so each CLI's own sandbox is the
boundary. The daemon configures it per turn from the bot's grants (`net` with
its host list, `git`, `ssh`). The settings only add restrictions.

### Claude

The `--settings` file adds:

- `permissions.deny`: `Skill`, `SlashCommand`; `WebFetch`, `WebSearch` unless
  `net`; `Bash(git push)`/`Bash(git push *)` unless `git`; `ssh`, `scp`,
  `sftp`, `rsync` unless `ssh`; `Read`/`Edit` of credential paths under the real
  HOME (`.ssh`, `.aws`, `.gnupg`, `.config/gh`, `.netrc`, `.docker/config.json`,
  `.kube`, `.config/gcloud`, `.azure`, both CLIs' login files) and of the
  daemon's `admin-token` and `state.db*`. Paths are written `//abs/path`
  because `~` would name the per-bot HOME.
- `permissions.blockReadsOutsideWorkingDirectories: true`.
- With `claude_sandbox = "required"` (default), a `sandbox` block:
  `enabled: true`, `failIfUnavailable: true`, `allowUnsandboxedCommands: false`,
  `autoAllowBashIfSandboxed: false` (Bash still asks through the daemon),
  `network.strictAllowlist: true` with `allowedDomains` = the bot's `net` hosts
  (empty without `net`), and `credentials.files` deny entries for the same
  paths.

Claude's sandbox needs `bwrap` and `socat` on Linux (Seatbelt is built into
macOS). Before launch the daemon checks for both; if one is missing, or Claude
exits with a sandbox error, the turn fails with a notice naming what is
missing and a `cli_sandbox_unavailable` entry in the bot log and audit. A
managed policy can set `claude_sandbox = "off"`; a local one can't (warning).

How this combines with sandbox settings a user already has (from Claude's
settings and sandboxing docs, Claude Code v2.1.285+):

- Managed settings: highest precedence. A managed boolean (`enabled`,
  `failIfUnavailable`, `allowUnsandboxedCommands`) wins over the daemon's
  value, and arrays merge. The daemon's own sandbox block never sets
  `enabled: false`. A user's `enabled: false` is copied only when the daemon
  is not writing its own block (`claude_sandbox = "off"`). Managed settings
  still win, so a managed sandbox stays on. If managed sets
  `allowUnsandboxedCommands: true`, managed wins; the daemon can't tighten
  that key. Deny rules from every scope are evaluated first, so the daemon's
  deny rules can't be undone by an allow elsewhere, and managed deny rules
  still apply.
- User `~/.claude/settings.json` is not loaded by Claude (`--setting-sources=`).
  The daemon reads it from the real user home and copies its `sandbox` keys
  into the `--settings` file. `permissions.deny` and `sandbox.credentials.files`
  are unions, so a user deny is kept and the daemon's denies are added. On one
  credential path, `deny` wins over `allow`. Other user sandbox keys are kept,
  including `allowedDomains`, `excludedCommands`, and `allowWrite`. The daemon
  does not add entries to those allowlists. Where the daemon also sets a
  boolean, the stricter value is written: `enabled`, `failIfUnavailable`, and
  `network.strictAllowlist` are true if either side says true;
  `allowUnsandboxedCommands` and `autoAllowBashIfSandboxed` are false if
  either side says false. If the user did not set `allowedDomains`, the
  daemon's grant list is used when the daemon writes a sandbox block. Allow
  rules, hooks, and the rest of the user file are not copied. A missing file
  means there is nothing to carry. If the file exists and cannot be read or
  parsed, the turn is refused and audited as `cli_sandbox_unavailable`,
  because a sandbox may be configured there.
- `--settings` with `allowUnsandboxedCommands: false` makes the sandbox
  "admin-required", so a repository's settings can't loosen it either.
- Orgs that already run the sandbox through managed settings and want the
  daemon to add no sandbox block of its own: managed `claude_sandbox = "off"`.
  The daemon's deny rules and the read block stay, the user's sandbox keys
  are still copied, and managed settings still win.

### Grok

The daemon writes this into the turn's `GROK_HOME` (`<home>/.grok`, or
`DATA_DIR/cli/<bot>/grok-home` when managed `home = "user"`):

```toml
[profiles.lgb]
extends = "strict"           # reads: workspace, system paths, GROK_HOME
restrict_network = true      # false with a net grant
deny = ["/home/u/.ssh", ...]  # existing credential paths, admin-token, state.db*
```

and passes `--sandbox lgb` plus `--disallowed-tools web_fetch,web_search`
unless `net`. A custom profile fails closed: Grok refuses to start if it can't
apply it (unknown profile, bad `sandbox.toml`, or no `bwrap` for a deny list on
Linux). Only existing paths are listed, since Grok also refuses a deny path it
can't bind. A `ssh` grant drops `~/.ssh` from the list. Grok's own
`auth.json` is not denied.

A profile pinned in `requirements.toml` (`/etc/grok` or signed) outranks
`--sandbox`, so a stricter managed pin still wins. The user's
`~/.grok/config.toml` sandbox profile and `~/.grok/sandbox.toml` are not read
under the isolated home; the daemon's profile extends `strict`, the strictest
built-in.

Under managed `home = "user"` the daemon still does not write the user's
`~/.grok/sandbox.toml`. `GROK_HOME` points at the per-bot `grok-home`
directory, which holds the same `lgb` profile, and the turn passes
`--sandbox lgb`. `HOME` stays the user's. A profile pinned in
`requirements.toml` still outranks `--sandbox`. If Grok cannot apply `lgb`,
it refuses to start and the daemon audits `cli_sandbox_unavailable`, the same
event as Claude's missing sandbox.

### lgb: daemon state tools without MCP

Each CLI turn gets an `lgb` command on its PATH. It reaches only these daemon
tools: `set_timer` (in/at/every), `list_timers`, `clear_timer`,
`write_memory`, `delete_memory`, memory list, `list_bots`, `read_bot`,
`send_dm`, and `create_bot`/`update_bot` only with `lgb_manage_bots = true`.
There is no route to `run_shell`, `read_file`, `write_file`, grants, or
permission decisions; argv is parsed by the daemon and anything else is
"unknown command". `lgb help` prints usage.

Transport. Both sandboxes block the network, and live with Grok 1.0.52 the
`lgb` profile (`restrict_network = true`) refused a connect to a unix socket
both in `/tmp` and in the workspace. So lgb uses a spool in the workspace,
which both sandboxes let the CLI write:

- Before each turn the daemon deletes and recreates
  `<workspace>/.lgb/{bin,req,resp}` (0700) and writes `bin/lgb`, a POSIX `sh`
  script (needs `sh`, `od`, `tr`, `mv`, `head`, `tail`, `sleep`).
- The script writes `token\0arg\0arg…` to `req/.<id>`, renames it to
  `req/<id>`, and waits up to 60 s for `resp/<id>` (first line exit code).
- The daemon polls `req` every 100 ms through directory file descriptors it
  opened at setup, with `O_NOFOLLOW` for every read and `O_EXCL|O_NOFOLLOW` plus
  `renameat` for every write. A bot that swaps `req`/`resp` for a symlink, or
  plants a link as a request, can't make the daemon read or write outside the
  spool (tested). Names must be hex; requests over 64 KiB are refused.
- The CLI gets `PATH=<workspace>/.lgb/bin:…`, `LGB_SPOOL`, and `LGB_TOKEN`.

Token. `lgbr_` plus 32 random bytes, made per run, never the admin token, and
only accepted by the spool. The HTTP API returns 401 for it. The permission
decision route is the exception: a live `lgbr_` token, or the turn's MCP
permission token, is 403 there. After the run the token is forgotten, so that
route returns 401 again. When the run ends the poller stops, the token is
cleared, and `req` is removed, so a later call fails with "not available in
this run" (live). At most 200 calls per turn. Every call, including a bad
token, is written as `lgb_call` to the bot log and the audit sink with
`run_id`, the command, the tool, redacted arguments, and the result.

Approval. The daemon adds allow rules `Bash(lgb)` and `Bash(lgb *)`
(`--allowedTools` for Claude, `--allow` for Grok). Other shell commands still
ask as before. A chained command (`lgb … ; echo $?`) is not covered and asks;
the preamble tells the bot to run each lgb call alone. Live, Grok's headless
ask for such a command cancelled the turn.

Claude sandbox users: nothing else changes. The settings file, deny rules,
sandbox block and managed-settings behavior are as above. lgb runs inside
Claude's sandbox (writes to the workspace, no network) and adds one allow rule.

### Daemon API

With a CLI backend the HTTP API requires a token. `AUTH_TOKEN` wins; otherwise
the daemon generates one at `DATA_DIR/admin-token` (0600) and prints its path
at startup. Paste it in the UI, or open `/login?token=<token>` once to get an
HttpOnly, SameSite=Strict cookie. The token is never in the CLI environment:
`AUTH_TOKEN` and any variable whose value contains the token are dropped, and
both CLIs are denied the file. Without the token a CLI's shell can't call the
API, including `POST .../permissions/{id}`. `GET /api/health` stays open, as
does the per-run MCP permission route, which only asks the broker. Ollama-only
setups need no token unless `AUTH_TOKEN` is set.

## Interactive tools

Claude's built-in question and plan tools are specified in
`@anthropic-ai/claude-agent-sdk` 0.3.300 `sdk-tools.d.ts`
(`AskUserQuestionInput`, `AskUserQuestionOutput`, `ExitPlanModeInput`).
The daemon is headless. This is what each interactive path does.

### AskUserQuestion

Handled. The broker keeps a small case-sensitive set, and today the only name
in it is `AskUserQuestion`. Hooks, then deny rules, still run first, so a deny
rule on that tool wins. Otherwise it is always a UI question. A bypass mode,
an allow rule, a hook allow, and a session grant do not answer it, because
there is no answer yet. Malformed input (not 1–4 questions, or a question
missing its text, header, boolean `multiSelect`, or 2–4 options with a label
and a description) is a deny, rule `malformed`, with no card.

`permission_request` carries `kind: "question"` and the validated questions.
Question text is redacted with the usual redactor; `multiSelect` stays a
boolean. The page shows a header chip, the question, radios or checkboxes
with their descriptions, an Other text field, Submit, Skip, and the countdown.
Submit posts `{"decision":"answer","answers":{<question text>: <value>}}`.
Skip posts `{"decision":"deny"}`. Text is set with `textContent`.

Answer keys Claude receives are the original question text. The page may send
the redacted text it was shown; the broker maps that back to the original and
maps a redacted option label back to the original label. A single choice is
the option label, or the typed string when the user picks Other. A multi-select
value is the chosen labels joined by `", "` (a label that itself contains
`", "` is kept whole). Optional `annotations` (`preview`, `notes`), keyed by
question text, are copied into `updatedInput` only when the client sent some.

Both transports return the same body. Allow is `{"behavior":"allow","updatedInput":{...original input, answers}}`.
A Skip, a timeout, `no_ui`, or a cancel that writes a response is
`{"behavior":"deny","message":"The user did not answer the question (<reason>)."}`.
A hook or policy deny keeps the ordinary deny message. `stream_control`'s
`control_cancel_request` still writes no response. A daemon restart drops the
in-memory ask and sends nothing. A shutdown cancel uses source `cancel` when
a response is written.

`allow_once` or `allow_session` on a question, or `answer` on any other
request, is 400 and leaves the request pending. A second decision is 409.
A live `lgbr_` token or the turn's MCP permission token is 403 on
`POST /api/bots/{id}/runs/{run_id}/permissions/{req_id}` only. The admin
token, Bearer or the `lgb_auth` cookie, is what decides. One decision is
stored per request. The audit record has `kind: "question"`, `answered`
(how many questions), `source`, and the answers after redaction. The
`updatedInput` sent back to Claude is not redacted.

### ExitPlanMode

A normal allow/deny card. The broker does not special-case the tool. When
`arguments.plan` is a string, the card shows that text above the argument
dump, then Allow once, Deny, and Allow for session when the policy offers it.
In SDK 0.3.300, `ExitPlanModeInput` is `allowedPrompts` plus unknown keys.
`plan` is not a required field. The card shows it when the call includes it.

### MCP elicitation

Declined. The daemon sets `disableAllHooks` and does not implement Claude's
elicitation dialog or Elicitation hooks. An unrecognized `control_request`
subtype, including `mcp_message` and `hook_callback`, gets
`Unsupported control request subtype: ...` and a deny audit. There is no form.

### requiresUserInteraction

Claude treats `AskUserQuestion`, and MCP tools whose
`_meta["anthropic/requiresUserInteraction"]` is true, as something it will not
auto-approve before it calls the host. That annotation is not on the
`can_use_tool` payload this daemon sees. The broker forces a question only
for the case-sensitive name `AskUserQuestion`. Any other tool that reaches
the broker follows the normal order.

### Grok

Grok has no permission host on this branch. A headless TUI prompt fails the
turn with `permission prompt requires a TTY or an explicit permission_mode`
(`ErrPermissionPrompt`). It does not open a card.

## Override files

Before each turn the daemon scans the bot workspace (three levels, skipping
`.git` and `node_modules`) for `.claude/settings.json`,
`.claude/settings.local.json`, `.claude/CLAUDE*.md`, `.mcp.json`, `CLAUDE.md`,
`CLAUDE.local.md`, `AGENTS.md`, anything under `.grok/`, and `.cursor/mcp.json`
or `.cursor/hooks.json`. A hit is written to the bot log and the audit sink as
`cli_override` with the files, the mode, and the action.

| Backend, home | Neutralized | Not neutralized (refused even under `ignore`) |
| --- | --- | --- |
| Claude, either | all of the above | none |
| Grok, isolated | all but `.mcp.json` | `.mcp.json` |
| Grok, user | none | all, since a folder-trust grant may exist |

Under `overrides = "refuse"` every hit fails the turn with
`workspace CLI config override refused: <files>`, and the CLI is not started.

## Verified, and not

- lgb live with Grok 1.0.52 and a real daemon on a test port (2026-10-14):
  a Grok bot set a 10-minute timer and wrote `favorite_color=teal` through lgb;
  `lgb run_shell id` gave "unknown command" and `lgb bot create` gave "off by
  policy"; all four calls were logged as `lgb_call` with the run id; the run
  token got 401 on `/api/bots` and, in that build, on the permission decision
  route, and failed after the run. A live run token on the decision route is
  now 403. `curl` and `cat admin-token` were asked for, which cancelled
  the headless turn.
- lgb with Claude is tested only with the fake CLI (argv has `--allowedTools
  Bash(lgb *)`, the script ran, the memory and timer landed). That Claude's
  sandbox allows the workspace spool and `/dev/urandom` needs a real run.

- Fake-CLI tests check argv, the child environment, the per-bot home,
  credential links, the scan, and refuse/ignore.
- Real Grok 1.0.52 on Linux, 2026-10-14: a symlinked `auth.json` gave "Not
  signed in"; a hard link authenticated. Through `PrepareIsolation` and
  `Args`, the `lgb` profile blocked `curl https://example.com` (could not
  resolve host), denied `cat` of the admin token and `ls ~/.ssh`, denied a
  write outside the workspace, allowed one inside, and `web_fetch`/`web_search`
  were not in the tool list. An unknown `--sandbox` profile refused to start.
  Under strict, `read_file` of `~/.bashrc` was denied.
- Earlier, with an isolated `GROK_HOME`, a headless `-p` turn authenticated, reported the folder
  untrusted, and ignored an `AGENTS.md` instruction. `grok inspect` still lists
  a workspace `.mcp.json` with every compat cell off, which is why it is refused.
- Claude's sandbox block, deny rules, the bwrap/socat check, the copy of
  the user's `sandbox` keys, and the merge with managed settings are tested
  only against the settings JSON and a fake CLI. The merge rules are from
  Claude's docs. A real run should confirm that
  `failIfUnavailable` exits as expected, that `//abs` Read/Edit rules match,
  and that a managed sandbox still applies alongside `--settings`.
- Claude was not installed on the test machine. The flags come from the CLI
  reference and the Agent SDK source; that `--setting-sources=` with an empty
  list also skips project `CLAUDE.md`, and that the credential symlink works
  with `CLAUDE_CONFIG_DIR`, need a live run.
- macOS is compile-checked and tested only through an OS seam on Linux
  (fake CLI). On a real Mac, check that under `claude_home = "auto"`:
  - `claude auth status` reports a logged-in Keychain method;
  - a turn authenticates without an API key;
  - user `~/.claude/settings.json` hooks and allow rules and `~/.claude.json`
    MCP servers really don't apply;
  - `cli_login` shows `keychain_or_user_home` with the expected
    `config_directory`.
  Also check whether `claude_home = "isolated"` on macOS loses the Keychain
  login, as expected, and whether `claude auth status` JSON has the
  `configDirectory` field (CLI v2.1.268 or later).
