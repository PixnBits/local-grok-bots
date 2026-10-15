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
  SDK passes for `setting_sources=[]`.
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
- sets `GROK_HOME=<home>/.grok`, so `~/.grok/config.toml`, `~/.grok/rules`,
  user hooks and plugins do not load;
- runs `--sandbox lgb`, a custom profile it writes to `<home>/.grok/sandbox.toml`
  (see [Sandbox and tools](#sandbox-and-tools));
- hard links `~/.grok/auth.json` into the isolated home (Grok 1.0.52 says
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
  value, and arrays merge. The daemon never writes `enabled: false`, so a
  managed sandbox stays on. If managed sets `allowUnsandboxedCommands: true`,
  managed wins; the daemon can't tighten that key. Deny rules from every scope
  are evaluated first, so the daemon's deny rules can't be undone by an allow
  elsewhere, and managed deny rules still apply.
- User `~/.claude/settings.json`: not loaded (`--setting-sources=`), except
  that Claude still applies its `sandbox.credentials` deny entries. A user's own
  `allowedDomains`, `excludedCommands`, or `allowWrite` therefore don't carry
  over. That narrows, never widens, and can break a workflow that relied on
  them: ask the admin for a policy host grant instead.
- `--settings` with `allowUnsandboxedCommands: false` makes the sandbox
  "admin-required", so a repository's settings can't loosen it either.
- Orgs that already run the sandbox through managed settings and want only
  theirs: managed `claude_sandbox = "off"`. Deny rules and the read block stay.

### Grok

With an isolated home (default) the daemon writes:

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

Under managed `home = "user"` the daemon does not write the user's
`~/.grok/sandbox.toml`. It passes built-in `--sandbox strict`, which Grok runs
unenforced, with a warning, if it can't apply.

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
- Claude's sandbox block, deny rules, the bwrap/socat check, and the merge
  with managed settings are tested only against the settings JSON and a fake
  CLI. The merge rules are from Claude's docs. A real run should confirm that
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
