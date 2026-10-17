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

## Timeouts

Every limit on a run is a policy key. Precedence is the same as other keys:
managed settings, then `policy.toml`, then the default. Managed policy can
also set a ceiling (`max_*`); the effective value is the smaller of the
setting (or default) and the ceiling. A `max_*` key in `policy.toml` is
ignored with a warning. Values are seconds or a Go duration, at most 24h.
A bad value fail-closes like any other parse error.

```toml
[cli]
# Wall clock for one CLI turn (claude or grok). Default 2h. On expiry the
# turn ends with error turn_timeout.
turn_timeout = "2h"
# Kill a CLI turn that produced no output (tokens, tool calls, results,
# decisions) and got no user message for this long. A turn waiting on a
# permission card is never idle-killed; prompt_timeout governs it.
idle_timeout_minutes = 30
# max_turn_timeout = "4h"          # managed only

[cli.permission]
# How long a permission or AskUserQuestion card waits, with or without a
# page open. Expiry denies (source timeout). Default 10m. With the mcp
# transport the daemon sets MCP_TOOL_TIMEOUT for Claude to this plus 1m.
prompt_timeout = "10m"
# max_prompt_timeout = "30m"       # managed only

[ollama]
# Whole Ollama run, all tool rounds. Default 10m.
run_timeout = "10m"
# One model call inside a run. Default 3m.
model_timeout = "3m"
# max_run_timeout = "1h"           # managed only
# max_model_timeout = "10m"        # managed only
```

Before this, a CLI turn also ran under a fixed 10-minute run deadline that
was not configurable, and the idle kill counted only from the turn start, so
a busy turn was cut at `idle_timeout_minutes`.

A run that fails, times out, is interrupted, or is cancelled keeps what it
did. Text streamed after the last tool call is stored as the bot's reply,
earlier text and every tool call with its result and every permission or
question decision stay in the run's tool records, and a `Notice: Run ...`
thread message tied to the run carries the error. The page shows the run's
tool summary on that notice when there is no reply. Notices are not turn
input and do not start a run. This holds for claude, grok, and Ollama.

## Launch

Every CLI turn gets a fresh environment. Nothing is inherited except
`PATH`, `LANG`, `LC_*`, `TERM`, `TZ`, `USER`, `LOGNAME`, `SHELL`, `TMPDIR`,
the proxy variables, `SSL_CERT_FILE`/`SSL_CERT_DIR`/`NODE_EXTRA_CA_CERTS`,
and the backend credential
(`ANTHROPIC_API_KEY`/`CLAUDE_CODE_OAUTH_TOKEN` for Claude). For Grok the
daemon sets `XAI_API_KEY` to a per-run proxy secret, not a host key, and
points the chat base URLs at its loopback proxy. Grok does not keep the
rest of that inherited list. Its launch environment is `PATH`, `LANG`,
`TERM`, `HOME`, the per-run `XAI_API_KEY`, the proxy base URLs,
`LGB_SPOOL`, `LGB_TOKEN`, and the `GROK_*` variables this isolation sets.
`LGB_*` from the daemon process is not copied. The daemon sets
`LGB_SPOOL` and `LGB_TOKEN` for that run. Every other `ANTHROPIC_*`,
`CLAUDE_*`, and `GROK_*` variable is dropped, including
`ANTHROPIC_BASE_URL`, `CLAUDE_CONFIG_DIR`, `GROK_CONFIG`, and
`GROK_SANDBOX`. Managed `cli.isolation.env` is applied last.

With `home = "isolated"`, `HOME` is `DATA_DIR/cli/<bot>/home`. For Claude,
the only file shared with the user's home is a symlink to
`~/.claude/.credentials.json`. Grok does not link or copy
`~/.grok/auth.json`. It writes a placeholder and sends chat traffic to a
daemon reverse proxy on `127.0.0.1`
([Grok CLI login live check](cred-hardlink-check.md)). Settings, hooks, MCP
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
  Permission prompts on the mcp transport depend on MCP. If managed policy
  disables MCP, set `claude_transport = "stream_control"` so the broker
  answers asks on stdin instead. See `docs/cli-permissions.md`.
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
- writes a placeholder `auth.json` into that `GROK_HOME` and sets
  `XAI_API_KEY` to a per-run secret. The daemon admits that secret on a
  `127.0.0.1` reverse proxy, which injects the bearer it reads from the
  user's `~/.grok/auth.json`. The user file is not linked, copied, refreshed,
  or rewritten. Any other bearer, path, or header is rejected. The secret is
  dropped when the turn ends
  ([Grok CLI login live check](cred-hardlink-check.md));
- sets every `GROK_CLAUDE_*_ENABLED` and `GROK_CURSOR_*_ENABLED` to `false`;
- drops `GROK_CONFIG`/`GROK_CONFIG_PATH`.

`/etc/grok/requirements.toml`, `/etc/grok/managed_config.toml`, and the synced
managed config still apply.

## Sandbox and tools

The daemon jail is off for CLI backends, so each CLI's own sandbox is the
boundary. The daemon configures it per turn from the bot's grants (`net` with
its host list, `git`, `ssh`). The settings only add restrictions.

The preferred path for durable low-risk grants (see `docs/cli-permissions.md`)
is to generate or update the CLI's native allow/ask/deny rules from user-accepted
patterns while the daemon continues to host residual asks and record every
decision. This keeps the already-reviewed COI sandbox as the enforcement
boundary and the daemon's audit trail complete.

### Claude

The `--settings` file adds:

- `permissions.deny`: `Skill`, `SlashCommand`; `WebFetch`, `WebSearch` unless
  `net`; `Bash(git push)`/`Bash(git push *)` unless `git`; `ssh`, `scp`,
  `sftp`, `rsync` unless `ssh`; `Read`/`Edit` of credential paths under the real
  HOME (`.ssh`, `.aws`, `.gnupg`, `.config/gh`, `.netrc`, `.docker/config.json`,
  `.kube`, `.config/gcloud`, `.azure`, both CLIs' login files) and of the
  daemon's `admin-token`, `state.db*`, `policy.toml`, and `DATA_DIR/cli`
  (MCP tokens and per-bot CLI state). The workspace is not on this list.
  Paths are written `//abs/path` because `~` would name the per-bot HOME.
- `permissions.blockReadsOutsideWorkingDirectories: true`.
- With `claude_sandbox = "required"` (default), a `sandbox` block:
  `enabled: true`, `failIfUnavailable: true`, `allowUnsandboxedCommands: false`,
  `autoAllowBashIfSandboxed: false` (Bash still asks through the daemon),
  `network.strictAllowlist: true` with `allowedDomains` = the bot's `net` hosts
  (empty without `net`), and `credentials.files` deny entries for the same
  paths. `sandbox.credentials.files` is a real Claude Code setting. Each entry
  is `{path, mode}` where `mode` is `deny` or `mask`. `deny` blocks reads the
  same way as `filesystem.denyRead` (Claude Code v2.1.187+). Checked against
  the [settings reference](https://code.claude.com/docs/en/settings-reference)
  and `@anthropic-ai/claude-agent-sdk` 0.3.300 `sdk.d.ts`
  (`SandboxCredentialsConfigSchema`). That package is not vendored; the check
  was the published type definitions. The daemon writes `deny` only.
  Tests check that the generated settings file carries these entries; that
  Claude actually enforces them was not verified against a real `claude`
  binary in this repo's tests.

Claude's sandbox needs `bwrap` and `socat` on Linux (Seatbelt is built into
macOS). Before launch the daemon checks for both; if one is missing, or Claude
exits with a sandbox error, the turn fails with a notice naming what is
missing and a `cli_sandbox_unavailable` entry in the bot log and audit. A
managed policy can set `claude_sandbox = "off"`; a local one can't (warning).
`"off"` only stops the daemon from writing its own sandbox block. It does
not turn off a sandbox the user or managed settings already enable: the
user's restrictive keys are still copied (see below).

How this combines with sandbox settings a user already has (from Claude's
settings and sandboxing docs, Claude Code v2.1.285+):

- Managed settings: highest precedence. A managed boolean (`enabled`,
  `failIfUnavailable`, `allowUnsandboxedCommands`) wins over the daemon's
  value, and arrays merge. The daemon's own sandbox block never sets
  `enabled: false`. A user's `enabled: false` is never copied. Managed settings
  still win, so a managed sandbox stays on. If managed sets
  `allowUnsandboxedCommands: true`, managed wins; the daemon can't tighten
  that key. Deny rules from every scope are evaluated first, so the daemon's
  deny rules can't be undone by an allow elsewhere, and managed deny rules
  still apply.
- User `~/.claude/settings.json` is not loaded by Claude (`--setting-sources=`).
  The daemon reads it from the real user home and copies its `sandbox` keys
  into the `--settings` file. `permissions.deny` and `sandbox.credentials.files`
  are unions, so a user deny is kept and the daemon's denies are added. On one
  credential path, `deny` wins over `allow`. Only restrictive user keys are
  kept: booleans take the stricter value (`enabled`, `failIfUnavailable`,
  `network.strictAllowlist` true if either side says true;
  `allowUnsandboxedCommands`, `autoAllowBashIfSandboxed`,
  `network.allowLocalBinding` false if either side says false; a user value
  alone is kept only when it is the restrictive one), and deny lists
  (`deniedDomains`, `filesystem.denyRead`/`denyWrite`) are unions.
  Allowlists (`allowedDomains`, `allowUnixSockets`, `filesystem.allowRead`/
  `allowWrite`) are narrowed to what policy grants: a user list is
  intersected with the daemon's, and is empty when policy grants nothing.
  User lists never replace the daemon's. `excludedCommands` and any other
  key not listed here are dropped. Allow
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
deny = ["/home/u/.ssh", ...]  # existing credential paths, admin-token, state.db*, policy.toml, DATA_DIR/cli
```

and passes `--sandbox lgb` plus `--disallowed-tools web_fetch,web_search`
unless `net`. A custom profile fails closed: Grok refuses to start if it can't
apply it (unknown profile, bad `sandbox.toml`, or no `bwrap` for a deny list on
Linux). Only existing paths are listed, since Grok also refuses a deny path it
can't bind. A `ssh` grant drops `~/.ssh` from the list. The user's
`~/.grok/auth.json` is denied when that path exists. The placeholder in this
turn's `GROK_HOME` is not on the list, because Grok must read it.
`DATA_DIR/cli` is not denied whole, because the bot's own `HOME` or
`GROK_HOME` is under it and Grok must write there (a whole-directory deny
made it exit at start). Instead every existing entry under it is denied
except the path down to the bot's own home: other bots' state, this bot's
`perm/` and settings files. Checked live with grok 1.0.52 in both home
modes: the turn ran, the workspace was readable, and a file beside the
bot's home was refused. A bot directory created after the turn starts is
not in that turn's list.

On macOS, Grok's `restrict_network` is not enforced, so a Grok bot
without a `net` grant still has network access there. Only the web tools are
removed. Once per such turn the daemon writes `cli_network_unrestricted` to
the bot log and the audit sink (`backend`, `os`, `run_id`, `reason`) and
prints the same warning on stderr. A `net` grant, and every Linux turn, stay
quiet. Use Claude, or Linux, where network isolation matters.

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

`list_bots`, `read_bot`, and `send_dm` reach every bot on this daemon.
There is no allow-list. `list_bots` returns id, name, label, and status.
`read_bot` takes a name or id and returns that bot's description, model, and
memory keys and values. `send_dm` queues a turn on the named bot.
`create_bot` and `update_bot` stay behind `lgb_manage_bots`.

A repeating timer the bot creates (`lgb timer every`, or `set_timer` with
`every`) is limited on Claude and Grok: at least 5 minutes, and at most 12
scheduled turns an hour for that bot. Policy sets both, as
`cli.lgb.min_timer_interval` and `cli.lgb.max_scheduled_per_hour`. `0` turns
that check off. Ollama is unchanged unless those keys are set. One-shot
timers have no minimum interval. Timers created from the page are not
limited here.

The same hourly cap also counts turns another bot starts. Each `send_dm`
(tool or `lgb dm`) that would start a turn on the recipient, and each
timer-fired turn, is counted per recipient over a rolling hour, in memory
(a daemon restart resets it). When the recipient is at the cap, the DM is
not delivered, the sender's tool call fails with a message naming
`cli.lgb.max_scheduled_per_hour`, and `bot_turn_cap` is written to the
recipient's bot log and the audit log. Timer turns are only counted, not
refused, since timers are already checked when created. DMs and turns the
user starts from the page are not counted.

The command is a thin client. It writes a request to a workspace spool the
daemon watches, then reads the reply. The spool directory is mode 0700 and
is removed when the turn ends. The token is mode 0600 and is the same
`LGB_TOKEN` the environment carries. A bad token, a missing spool, or a
malformed request is a deny. The daemon does not re-jail the CLI process;
the CLI's own sandbox is the boundary.
