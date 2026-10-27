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
# Egress ports for a bot net grant. Default 443 and 80.
# Local policy can only narrow the list. An empty list allows no port.
# Managed policy can set a different list. Local policy still only narrows that.
# net_ports = [443]
# Added to the scrubbed environment. Only managed policy can set this.
# A GROK_* name that selects permission, config, mode, sandbox, hooks,
# plugins, skills, agents, or home is refused, and the managed file
# fail-closes. GROK_CONFIG, GROK_CONFIG_*, and
# GROK_DEFAULT_SELECTED_PERMISSION are in that set.
# env = { ANTHROPIC_BASE_URL = "https://gateway.corp.example" }
# Host files the CLI can still read refuse the turn unless managed policy
# sets this. Local policy cannot set it. Default false.
# trust_system_config = false
```

`[cli].server_tools` is the allow list of non-function model tool types
(`web_search`, `x_search`, and the same kind of provider tool) a
net-granted bot may keep. Function tools are not part of that list.
Omitted, the list is empty and the loopback proxy strips every such
type. An explicit empty list is set: it narrows a managed ceiling to
nothing. Managed policy sets the ceiling. Local policy and each bot's
`server_tools` field can only narrow it. Leaving the bot field out, or
setting it to null, inherits this list. An explicit empty bot list
allows none of those types. A bot without a net grant loses every
non-function tool. The proxy applies this to every non-empty body on
the loopback credential proxy, using the same normalized path as its
allow decision. Permission mode still uses the snapshot from daemon start.

## Timeouts

Every limit on a run is a policy key. Precedence is the same as other keys:
managed settings, then `policy.toml`, then the default. Managed policy can
also set a ceiling (`max_*`); the effective value is the smaller of the
setting (or default) and the ceiling. A `max_*` key in `policy.toml` is
ignored with a warning. A timeout or `stall_retries` set in `policy.toml`
above its managed ceiling is lowered to that ceiling and warned, for example
`ollama.stall_timeout 5m lowered to managed max_stall_timeout 1m`. A value
already within the ceiling is not warned, and a clamped default is not
warned. Values are seconds or a Go duration, positive, at most 24h. A bad
value fail-closes like any other parse error. The error names that key.

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
# Whole Ollama run, all tool rounds. Default 10m. This is the backstop.
run_timeout = "10m"
# Optional hard cap on one model call. Unset means the effective run
# timeout, so only run_timeout bounds the call. An explicit value stays a
# hard per-call cap (and is not retried). Configs that set the old 3m
# default should drop the key unless that cap is still wanted.
# model_timeout = "10m"
# Max wait from sending the request until the first output chunk
# (content, thinking, a tool call, or the final done line). Covers a cold
# model load. Default 5m. When model_timeout is set and this key is not,
# the default is that model_timeout (before max_* ceilings).
first_output_timeout = "5m"
# Max gap between those output chunks after the first. A slow steady
# trickle is not a stall. Default 2m. When model_timeout is set and this
# key is not, the default is that model_timeout (before max_* ceilings).
stall_timeout = "2m"
# How many times one run retries a first-output wait or a stall. Default 1.
# 0 disables. The ceiling is 5. A model_timeout, a run_timeout, Stop, and
# shutdown are not retried.
stall_retries = 1
# Ollama keep_alive on every /api/chat. A Go duration, an integer number of
# seconds (0 unloads), or -1 (keep loaded). Default "30m".
keep_alive = "30m"
# max_run_timeout = "1h"           # managed only
# max_model_timeout = "10m"        # managed only
# max_first_output_timeout = "15m" # managed only
# max_stall_timeout = "5m"         # managed only
# max_stall_retries = 1            # managed only
```

`run_timeout` bounds the whole run. `first_output_timeout` and
`stall_timeout` bound one call by silence, not by wall clock: output is any
streamed chunk with non-empty `message.content`, non-empty `message.thinking`
(thinking counts as activity and is not copied into the reply), a tool call,
or the final `done` chunk. A call that keeps producing those faster than
`stall_timeout` runs until `run_timeout`, or until an explicit `model_timeout`.
`model_timeout` no longer defaults to 3m. When it is unset, the effective
model timeout equals the effective run timeout, still capped by managed
`max_model_timeout`, and the silence defaults stay 5m and 2m. When
`model_timeout` is set in `policy.toml` or in managed policy and
`first_output_timeout` or `stall_timeout` is not set by either source, each
unset one defaults to that explicit `model_timeout` before managed `max_*`
ceilings. The ceilings still apply afterwards. An explicit
`first_output_timeout` or `stall_timeout` is used as written. A file that
already set `model_timeout` and not the new keys therefore stays no stricter
than that cap: a first token at 5m30s still succeeds when `model_timeout` is
10m.

A silence limit that is >= the per-call cap is not armed separately; the call ends as `model_timeout` and is not retried.

A `first_output_timeout` or `stall_timeout` while the run is still alive and
`stall_retries` remain is tried again, once by default, on the same messages.
Tools run only after a complete response, so a failed call has not executed
any tool. The retry publishes `status` `retrying` and a `stream_reset` event
so the page drops the live partial. The attempt is logged with `retry: true`.

A timeout that is not retried (retries used up, `model_timeout`, or
`run_timeout`) keeps the longest partial text seen across that call's
attempts as the bot's reply, marked `timed_out`, and finishes the run as
`timeout`. The thread notice names the limit and its value, and says when a
partial is kept. The same sentence without the `Notice: ` prefix is
`last_run_error`. The page offers Retry (the same user turn, without the
partial or the notice: `POST /api/bots/{id}/runs/{run_id}/retry`) while that
run is the latest timeout and the bot is idle. Continue (the transcript
including the partial, the existing continue endpoint) is offered only when
that timeout kept partial text, so `continue_run_id` is set. With no partial,
`continue_run_id` stays unset and the page shows Retry only. Continue needs
the in-memory offer; a restart drops it and Retry still works. Stop,
shutdown, and a CLI `turn_timeout` are unchanged: a CLI turn still ends
`error` / `turn_timeout`.

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
`GROK_SANDBOX`. Managed `cli.isolation.env` is applied after that scrub.
It cannot set `GROK_CONFIG`, `GROK_CONFIG_PATH`,
`GROK_DEFAULT_SELECTED_PERMISSION`, or any other `GROK_*` name that
selects permission, config, mode, sandbox, hooks, plugins, skills, agents,
or home. One of those keys makes the managed file unparseable and CLI
backends stay off.

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
- drops `GROK_CONFIG`/`GROK_CONFIG_PATH`, and refuses a managed env entry
  that would put them back;
- before the process starts, checks `GROK_HOME` for `config.toml`,
  `requirements.toml`, `trusted_folders.toml`, `managed_config.toml`,
  `hooks-paths`, and the `hooks`, `plugins`, `skills`, and `agents`
  directories. A missing name is created with the daemon's known bytes
  (the permission file, the requirements file, a one-line marker, or a
  directory that holds only that marker). A name whose bytes differ, a
  symlink, or an extra link refuses the turn and is left in place. An
  exact previous requirements marker is replaced with the current
  requirements body. `requirements.toml` sets
  `[ui] remember_tool_approvals = false`. Any
  `sessions/**/permission*.toml` that already exists must be empty or the
  daemon placeholder. A different body is left in place and the turn is
  refused. The scope's `sessions/<encoded workspace>/permission.toml` is
  created when it is missing: the directory name is the URL path-encoding
  of the absolute workspace path, the file is empty, and the jail
  bind-mounts it read-only over the writable `sessions/` mount. Other
  missing permission files are not created. An exact previous
  `config.toml` body is replaced with the current body, which includes
  `disable_web_search = true` (defense in depth; it has no effect on
  Grok server-side search);
- mounts `GROK_HOME` read-only, then mounts `sessions/` and `logs/`
  writable, then mounts the sealed names and matching permission files
  read-only on top. The same startup files are checked in `HOME` and
  mounted read-only: `.bashrc`, `.bash_profile`, `.bash_login`,
  `.profile`, and `.zshrc`. A missing startup file is created as the
  daemon placeholder. A different file refuses the turn and is left in
  place. The same check covers `.agents/skills`, `.claude`,
  `.cursor/mcp.json`, and `.gitconfig`. A missing path is an empty
  placeholder (a directory holds only an empty `placeholder` file) and
  is mounted read-only. A different body or a symlink is left in place
  and the turn is refused.

Writable inside the jail: the workspace, the fresh `/tmp`, the bot `HOME`
except those startup files, the empty home placeholders, and the read-only `GROK_HOME` tree,
`GROK_HOME/sessions` except matching `permission*.toml` files, and
`GROK_HOME/logs`. Not writable: `lsp.json`,
`installed-plugins/registry.json`, `trusted-plugins`,
`trusted-hook-projects`, `disabled-hooks`, `mcp_preferences.json`,
`commands/`, `rules/`, `personas/`, `roles/`, `workflows/`, `bundled/`,
`AGENTS.md`, `CLAUDE.md`, `sandbox.toml`, `auth.json`, and the sealed
names. Top-level names in `GROK_HOME` must be the sealed names,
`sessions`, `logs`, `auth.json`, `sandbox.toml`, `version.json`,
`cache`, or the lock files `managed_config.lock` and `auth.json.lock`.
Any other top-level name, including `lsp.json`, `commands/`, or
`AGENTS.md`, or a top-level symlink, refuses the turn as untrusted
config. A permission file created during a turn, other than the
pre-created scope file, is caught on the next turn's check.

`/etc/grok/requirements.toml`, `/etc/grok/managed_config.toml`, and
`/etc/claude-code/managed-settings.json` refuse the turn when they are
present, for both backends, unless managed policy sets
`trust_system_config`. The default is untrusted. The read-only `/etc`
bind does not hide them. A refusal is audited as `cli_untrusted_config`
and as a host permission denial.

Before a Grok turn the daemon hashes the `grok` binary. When managed
policy sets a `tools.cli` pin for grok, that SHA-256 is compared before
anything is executed. A mismatch refuses the turn and does not run
`--version`. Hardened setups should set `sha256` on the grok entry.
The version gate trusts the text `--version` prints, so the pin is what
stops a replaced binary that still prints an allowed version. When the
hash matches, or no pin is set, the daemon reads `grok --version` and
allows only 1.0.52 and 1.0.62. The version result is cached for that
binary's path, size, and modification time. Any other release, or a
check that does not return a version, refuses the turn and is audited as
`cli_version_refused`.

## Sandbox and tools

Ollama's workspace jail is off for CLI backends. On Linux, Grok is started in
the daemon's pid jail (private `/proc`) so other same-user processes are hidden;
Grok's own `--sandbox` is omitted there because a nested namespace cannot be
created on this host. Claude still uses its own sandbox. The daemon configures
each turn from the bot's grants (`net` with its host list, `git`, `ssh`). The
settings only add restrictions. Remaining limits are in [Sandbox model](sandbox.md).

Durable low-risk grants are decided by the broker (see `docs/cli-permissions.md`).
The bot turn does not load `user-permissions.json` or `grok-permission-rules`
as allow rules. On Linux the Grok jail does not mount those files. When they
exist at turn start, the Grok sandbox deny list names them and Claude settings
deny Read and Edit of those paths. The process boundary is still the daemon
jail (Grok on Linux) or the CLI sandbox (Claude). It is not what applies a
user allow. Grok's tool calls reach that broker through the ACP permission
host: the jail does not decide the allow.

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

and passes `--sandbox lgb` plus `--tools`, a global flag before `agent`.
The list is the tools an ask rule can force to prompt:
`run_terminal_command`, `read_file`, `search_replace`, `grep`, and `write`.
`web_fetch` and `web_search` are added to `--tools` only with a net grant.
That flag does not stop server-side search. `grok agent stdio` ignores
`--tools` and `--disallowed-tools` for tools the model runs at the
provider. The loopback credential proxy reads every non-empty body, on
any method and any path it has already allowed. The path is the same
normalized path as that allow decision, so a trailing slash, another
case, or an encoding that still normalizes to an allowed path does not
skip the check. A path the allow decision rejects is not forwarded.
A `function` tool stays. A JSON value with no top-level `tools` key is
re-encoded and forwarded. A bot without a net grant loses every
non-function tool, including `web_search` and `x_search`. Server-side
search is network access, so policy cannot keep one. A net grant keeps
only the types on the effective `[cli].server_tools` list. The default
list is empty. Managed policy sets the ceiling. Local policy and the
bot's `server_tools` field can only narrow it. Leaving the bot field
out, or setting it to null, inherits policy. An explicit empty bot list
allows none of those types. Omitting the policy key is the empty
default, not an inherit. An explicit empty policy list is a set layer
and narrows a managed ceiling to nothing. A tool entry that is not an
object, has no string type, or names a type outside the list is
stripped. Each strip is audited as `cli_proxy_stripped` with `bot_id`,
`run_id`, `path`, the removed types, and the policy source (`managed`,
`local`, `bot`, `default`, or `no_net`). The row records types only.
After a body parses, the proxy forwards a freshly re-encoded JSON value,
including when nothing was stripped. It does not forward the original
bytes. Number literals stay as written, and `&`, `<`, and `>` are not
escaped. A repeated object key at any depth is refused with 403 and
audited as `cli_proxy_refused` with reason `duplicate_key`. Invalid
JSON, a non-JSON body, `tools` that is not an array, an unsupported
content encoding, or a body nested too deeply is refused with 403 and
reason `unparsed`. An empty body is left alone. The proxy reads this
list when a body has a `tools` array to filter. Permission mode still
uses the snapshot from daemon start. `list_dir`, `x_keyword_search`, and `x_semantic_search`
are not on `--tools`. Everything else stays off that list
(`todo_write`, subagent and scheduler tools, `monitor`, `workflow`,
plan mode, `ask_user_question`, `send_feedback`, image tools,
`search_tool`, `use_tool`). The broker still denies Task, Workflow,
Scheduler, and image or video generation tools if a permission request
arrives, and it denies a write, an edit, or a shell target under
`GROK_HOME`. The same directory gets `config.toml`:
`disable_web_search = true` (defense in depth; it has no effect on Grok
server-side search; the proxy strips those tools),
`permission_mode = "default"`, and a catch-all ask list, so read-only
tools send `session/request_permission` instead of running on their own.

A custom profile fails closed: Grok refuses to start if it can't
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
  spool (tested). Names must be hex. A request over 64 KiB is refused with
  `lgb: request too large (max 64 KiB)`.
- The CLI gets `PATH=<workspace>/.lgb/bin:…`. The daemon sets `LGB_SPOOL`
  and `LGB_TOKEN` for this run. Other `LGB_*` variables are not passed through.

Token. One token per run: `lgbr_` plus 32 random bytes. It is not single-use.
The same token authorizes every lgb call in that run, up to 200 calls, and
call 201 returns `lgb: call limit for this turn reached`. It is never the
admin token, and only the spool accepts it. The HTTP API returns 401 for it.
The permission decision route is the exception: a live `lgbr_` token, or the
turn's MCP permission token, is 403 there. The token is revoked when the run
ends: it is forgotten, the poller stops, and `req` is removed. A later call
fails with "not available in this run", and that route returns 401 again.
Every call, including a bad token, is written as `lgb_call` to the bot log
and the audit sink with `run_id`, the command, the tool, redacted arguments,
and the result.

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
`AUTH_TOKEN` and any variable whose value contains the token are dropped from
the CLI environment, and both CLIs are denied the file. On Linux the daemon
re-execs once at startup so `/proc/self/environ` does not keep the token
either. On macOS the names are unset; original startup memory is unchanged.
Without the token a CLI's shell can't call the API, including
`POST .../permissions/{id}`. `GET /api/health` stays open, as does the
per-run MCP permission route, which only asks the broker. Ollama-only
setups need no token unless `AUTH_TOKEN` is set or `DATA_DIR/admin-token`
already exists. An existing admin-token file is read on every start.

## Voice, TLS, and the permission callback

`POST /api/stt` is local speech recognition. The request shape, status
codes, and audit fields are in `docs/voice.md`. The transcript is not
logged. Policy controls it, and policy beats the environment the same way
`[ollama] host` beats `OLLAMA_URL`.

```toml
[voice]
# Off unless set. A disabled POST /api/stt is 403 and still audited.
enabled = false
# Absolute paths. Both or neither. A missing file is 503.
# The file and its parent must be a regular file or directory, not a symlink,
# owned by root or the daemon user, and not group- or other-writable.
# The same checks run again before each execution, including lib*.so* files
# next to the binary. A failed check is 403. Output larger than 1 MiB is 502.
# A failed check turns voice off (403). The response does not name the path.
# bin = "/usr/local/bin/whisper-cli"
# model = "/var/lib/local-grok-bots/models/ggml-base.en.bin"
# Defaults: 240 seconds, 8 MiB, 60 requests per user per rolling hour.
# Hard range: 1..86400, 1..67108864, 1..100000.
# max_audio_seconds = 240
# max_body_bytes = 8388608
# max_requests_per_hour = 60

[daemon]
# Any one tls_* key replaces TLS_CERT, TLS_KEY, and TLS_SELF_SIGNED together.
# tls_cert and tls_key are absolute and must be set as a pair.
# tls_self_signed cannot be combined with that pair.
# tls_self_signed = false
# perm_callback_addr is 127.0.0.1 or ::1 and a numeric port.
# localhost, other 127/8 addresses, and wildcards fail.
# perm_callback_addr = "127.0.0.1:0"
# allowed_hosts adds names for POST /api/stt. Host names or IPs only.
# Those names are also written into the self-signed certificate.
# allowed_hosts = ["voice.example"]

[managed]
# Only the managed file can set these. The same keys in policy.toml are
# ignored after the range check. A [voice] value above the ceiling is lowered
# and warned, for example:
# voice.max_audio_seconds 600 lowered to managed max_voice_audio_seconds 30
# max_voice_audio_seconds = 240
# max_voice_body_bytes = 8388608
# max_voice_requests_per_hour = 60
```

Unknown keys, a wrong type, zero, a negative number, or a number above the
hard range make that file unparseable. The daemon fail-closes (CLI backends
off) and does not apply the file. A managed TLS, whisper, or
`perm_callback_addr` value that differs from a non-empty environment
variable refuses startup under `conflict_policy = "refuse"`.

HTTPS, when configured, is `ServeTLS` on the listener `bind` already chose.
There is no second public listener. `TLS_SELF_SIGNED=1`, or
`tls_self_signed = true`, writes `DATA_DIR/tls/cert.pem` and `key.pem` mode
0600, owned by the daemon user. The bytes are written to a new file in that
directory and renamed into place. An existing pair is kept when both paths
are regular files, the certificate parses, at least 30 days remain, and
the names are the same set. The names on that certificate are `localhost`,
`127.0.0.1`, `::1`, the bind IP when the bind address is one specific IP,
and each `allowed_hosts` entry. A supplied key that is a
symlink or group- or other-readable refuses startup. `listening on` is
printed after TLS setup succeeds. `POST /api/stt` status codes, the rolling
hour (counted only for an accepted request), and the binary and model file
checks are in `docs/voice.md`.

The permission callback is a separate plain-HTTP socket. It listens only
when the effective backend is Claude, `claude_transport` is `mcp` (including
an empty value, which is `mcp`), and at least one bot exists. Ollama, Grok,
`stream_control`, and `none` do not open it. The bind is `127.0.0.1` or
`::1` with a numeric port (`::ffff:127.0.0.1` counts as `127.0.0.1`), never
`0.0.0.0` or another `127.0.0.0/8` address. A later read of the policy file
starts or stops that socket when `claude_transport` changes. The backend
stays the one chosen at startup. Nothing else uses it.
On a plain-HTTP daemon, MCP keeps the main listener's origin. On HTTPS, the
MCP host base is the callback, and it is empty until that listener is up.

## Policy file reads after startup

A running daemon keeps the policy it loaded at startup. A later read of the
policy file copies only these settings onto that startup policy:

- `[voice]` `enabled`, `bin`, `model`, `max_audio_seconds`, `max_body_bytes`, and `max_requests_per_hour`
- managed voice ceilings (`max_voice_audio_seconds`, `max_voice_body_bytes`, `max_voice_requests_per_hour`)
- `[cli.permission]` `claude_transport`

These take effect only after a restart: `backend` (and the CLI permission and token requirement that follow from it), `bind`, `tls_cert`, `tls_key`, `tls_self_signed`, `allow_insecure_lan`, `perm_callback_addr`, `audit_log`, and `allowed_hosts`. Other settings, including the Ollama host and model, permission mode, tool rules, and jail settings, also stay as they were at startup. When a read differs in one of the restart settings, the daemon logs and audits `policy_restart_required` with the setting names, once per distinct set of names. It does not log the values. A read that cannot use the file turns voice off and leaves the restart settings as they were at startup. The next successful read applies `[voice]` and `claude_transport` again.

`POST /api/stt` and `GET /api/stt/status` allowlist `Host` and, when present, `Origin`. Built-in names are `localhost`, `127.0.0.1`, `::1`, and the listener's bind address when that address is one specific IP. `[daemon] allowed_hosts` adds names. Entries are host names or IP addresses: no scheme, port, or wildcard. Unspecified, multicast, broadcast, IPv4-mapped, and all-digit last labels are rejected. An invalid entry makes the file unusable. The `Origin` port must be the listener port, and the scheme must match the request (`https` under TLS). A `Host` header without a port is refused, including a proxy that listens on 443 and omits the port. When the bind is not loopback, the same host allowlist applies to every `/api` route and to `/login`. A non-loopback bind also needs a token and TLS unless `[daemon] allow_insecure_lan` is set. That key is fixed at startup. File checks for the whisper binary, model, parents, and `lib*.so*` files next to the binary run again before each execution. Output from that binary is read up to 1 MiB. Details are in `docs/voice.md`.

## Ollama run_shell on macOS

On macOS, Ollama `run_shell` now runs under `/usr/bin/sandbox-exec` with a
generated Seatbelt profile. Before this branch it failed closed on macOS, so
the tool never ran a command there. There is no `/work` mount: the shell
starts in the real workspace path. The profile denies by default, reads
system paths and the workspace, and writes only the workspace and a private
temp directory. `net` and `ssh` grants are denied because the connect proxy
needs `LD_PRELOAD`, so the network stays closed. A missing `sandbox-exec`
fails closed. Apple marks `sandbox-exec` deprecated; it still ships. This
path has been compile-checked, not run on a Mac.

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
Skip posts `{"decision":"deny"}`. The decision stays a UI deny; Claude's message uses the reason word `skipped`. Text is set with `textContent`.

Answer keys Claude receives are the original question text. The page may send
the redacted text it was shown; the broker maps that back to the original and
maps a redacted option label back to the original label. A single choice is
the option label, or the typed string when the user picks Other. Free text
longer than 4 KiB is rejected with HTTP 400 and the question stays pending.
A multi-select value is the chosen labels joined by `", "` (a label that
itself contains `", "` is kept whole). Optional `annotations` (`preview`, `notes`), keyed by
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

Grok asks through the ACP host in `docs/cli-permissions.md`. The card is the
same allow-once / deny / allow-session card. The host answers `allow-once` or
`reject-once`. A headless TUI prompt is not the Grok path anymore.
`ErrPermissionPrompt` still fails a Claude turn that asks with no host.

### Grok permission host (CISO)

The Linux bubblewrap jail keeps the same unshare flags
(`user`, `pid`, `uts`, `ipc`, `net`), `--die-with-parent`, `--new-session`,
`--clearenv`, private `/proc`, fresh `/tmp`, workspace bind, read-only binary,
writable `HOME`, read-only `GROK_HOME`, environment scrub, and proxy socket
binds. Nested `--sandbox` is still stripped inside the jail. The credential
forwarder still passes the child's stdin through, which is how ACP is written.
`sessions/` and `logs/` are writable mounts inside the read-only
`GROK_HOME`. Sealed names and matching permission files are `--ro-bind`ed
after those mounts.

What changed around that jail:

- Each turn checks the sealed names under `GROK_HOME` and writes a missing
  one with the no-follow helpers. `config.toml` is `permission_mode = "default"`
  and a catch-all ask list (Bash, Read, Grep, Glob, Edit, Write, WebFetch,
  WebSearch, MCPTool). `requirements.toml` sets
  `[ui] remember_tool_approvals = false`. The other sealed files and
  directory markers are a one-line comment. A different body refuses the
  turn and is not overwritten. The user's `~/.grok` is not written.
  `sandbox.toml` and `auth.json` are still written on the host before the
  turn and are read-only inside the jail, because the whole `GROK_HOME`
  tree is read-only except `sessions/` and `logs/`.
- Argv is `grok` with global flags, then `agent --no-leader stdio`. The
  global flags include `--cwd`, `--sandbox lgb` (omitted inside the jail, as
  before), `--no-auto-update`, and `--tools`. There is no `--always-approve`,
  no `--permission-mode`, no `-p`, no `--disallowed-tools`, and no user rule
  on `--allow` or `--deny`.
- Managed deny rules remain `--deny`. The `lgb` and `coi` spool allows remain
  `--allow`. Other managed allows are broker decisions after Grok asks. They
  are not argv allows.
- `session/new` carries only `cwd` and an empty `mcpServers`. A later turn
  uses `session/load`. Neither sets `yoloMode` or `autoMode`. The result's
  `modes.currentModeId` must be `default` before the prompt is sent. A later
  `current_mode_update`, `config_option_update`, or `_x.ai/sessions/changed`
  that selects another mode, or a bypass flag, fails the turn. A top-level
  notification method `_x.ai/sessions/changed` or `x.ai/sessions/changed`
  is checked the same way, including entries under `params.upserted`.
- A user message that is a slash command, after leading space and format
  characters, is refused before the process starts. A solidus counts as a
  slash.
- `grok --version` must be 1.0.52 or 1.0.62. Any other release refuses the
  turn and is audited as `cli_version_refused`. That check trusts the
  text the binary prints. Hardened setups set `sha256` on the grok
  `tools.cli` pin so a replaced binary is refused before `--version`.
- `HOME` startup files listed above are the daemon placeholder and are
  mounted read-only. A different file refuses the turn.
- Allow is answered `allow-once`. Deny is `reject-once`. An option whose id,
  name, or kind contains `always` is never selected. The permission request's
  session id must be the current session. A session grant stays in the
  broker, keyed by the session id Grok returned, which the next turn loads.
- Host failure (exit before a result, malformed request, broker error, missing
  allow-once or reject-once option, a mode that is not default, a slash
  command, a session id that does not match, protocol timeout) fails the
  turn and writes an audit row with source `host`.
- An unknown tool is audited as tool `unknown` and classification `unknown`.
  A failed tool update whose text says the call was denied, and which never
  asked the host, is audited with source `cli_deny`. Empty failure text is
  not. The turn still records the tool result.

Residuals:

- A profile pinned in `requirements.toml` still outranks `--sandbox` when
  managed policy has trusted that file. `/etc/grok/managed_config.toml` is
  part of the host-file check.
- `cli_deny` matches the words denied, not allowed, disallowed, and not
  permitted. A shell error that uses the same words can be recorded. The
  call is still not allowed by that record.
- `sandbox.toml` and `auth.json` are read-only inside the jail. A new
  `permission*.toml` created during a turn, under a session directory that
  did not have one at the start, is caught on the next turn's check.
  `remember_tool_approvals` is off in the sealed requirements file.
- With `home = "user"`, a missing shell startup file is created as the
  daemon placeholder in that home. A missing `.agents/skills`, `.claude`,
  `.cursor/mcp.json`, or `.gitconfig` is created as an empty placeholder.
  A different file is left in place and the turn is refused. The user's
  `~/.grok` is still not written.
- `hooks-paths` is sealed as a file. A directory of that name is refused.
- A path or symlink can change between `ClassifyCall` and the tool. The jail
  and the sandbox deny list remain the backstop.
- `list_dir` is not on `--tools`. If a permission request for it still
  arrives, it is classified as Glob. Server-side `web_search` and
  `x_search` tools do not reach the host. The loopback proxy strips
  non-function tools from every non-empty body, not only one model path.
  A bot without a net grant loses every one of them (`cli_proxy_stripped`,
  source `no_net`). A net grant keeps only the effective `server_tools`
  list. A duplicate object key is `cli_proxy_refused` with reason
  `duplicate_key`. Any other body that cannot be filtered, including a
  non-JSON body, is `cli_proxy_refused` with reason `unparsed`.
  `x_keyword_search` and `x_semantic_search` stay off the `--tools`
  list either way; that list does not stop a server-side tool.
  `disable_web_search` in the sealed config has no effect on Grok.
- Isolated `GROK_HOME` and no `--trust` still mean a project `.grok/config.toml`
  is not loaded. The ask rules in the per-bot `GROK_HOME` are what make Grok
  request permission. A managed allow does not skip that ask.

## Override files

Before each turn the daemon scans the bot workspace (three levels, skipping
`.git` and `node_modules`) for `.claude/settings.json`,
`.claude/settings.local.json`, `.claude/CLAUDE*.md`, `.mcp.json`, `CLAUDE.md`,
`CLAUDE.local.md`, `AGENTS.md`, anything under `.grok/` (including
`.grok/hooks`, `.grok/skills`, and `.grok/lsp.json`), `.envrc`, and
`.cursor/mcp.json` or `.cursor/hooks.json`. A hit is written to the bot log
and the audit sink as `cli_override` with the files, the mode, and the action.

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
  signed in"; a hard link authenticated. That hard link is no longer how a
  turn authenticates
  ([Grok CLI login live check](cred-hardlink-check.md)). Through `PrepareIsolation` and
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
