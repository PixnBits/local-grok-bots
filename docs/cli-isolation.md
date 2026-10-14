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
# user: the daemon user's HOME. Only managed policy can set this.
home = "isolated"
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

### Claude

- `--setting-sources=`: no user, project, or local settings, and so no
  `CLAUDE.md`, hooks, or `settings*.json` from them. This is the form the Agent
  SDK passes for `setting_sources=[]`.
- `--settings DATA_DIR/cli/<bot>/claude-settings.json`: daemon-written,
  `disableAllHooks` and `enableAllProjectMcpServers: false`.
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
- sets every `GROK_CLAUDE_*_ENABLED` and `GROK_CURSOR_*_ENABLED` to `false`;
- drops `GROK_CONFIG`/`GROK_CONFIG_PATH`.

`/etc/grok/requirements.toml`, `/etc/grok/managed_config.toml`, and the synced
managed config still apply.

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
- Real Grok 1.0.52 on Linux: with an isolated `GROK_HOME` and a linked
  `auth.json`, a headless `-p` turn authenticated, reported the folder
  untrusted, and ignored an `AGENTS.md` instruction. `grok inspect` still lists
  a workspace `.mcp.json` with every compat cell off, which is why it is refused.
- Claude was not installed on the test machine. The flags come from the CLI
  reference and the Agent SDK source; that `--setting-sources=` with an empty
  list also skips project `CLAUDE.md`, and that the credential symlink works
  with `CLAUDE_CONFIG_DIR`, need a live run. On macOS Claude keeps its login in
  the Keychain, keyed in part by the config dir, so an isolated home may need
  `ANTHROPIC_API_KEY`/`CLAUDE_CODE_OAUTH_TOKEN` or managed `home = "user"`.
