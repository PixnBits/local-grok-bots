# local-grok-bots

One Go daemon for a personal bot roster on the Framework Desktop. It keeps bots, threads, DMs, timers, and the log in SQLite, calls a local Ollama, and serves a small web page.

```bash
go build -o local-grok-bots ./cmd/local-grok-bots
./local-grok-bots
```

## Set up with a CLI

Two guides are written so a CLI can install this daemon on your machine. Each one builds the binary, installs a per-user service, and checks `GET /api/health`. That install does not need sudo. Login stays in your `~/.grok` or `~/.claude`. The daemon still refuses to run as root. On Linux, CLI turns need the `bubblewrap` package, which an administrator installs when you cannot.

- [Grok CLI](docs/setup/grok.md). Paste: `Follow docs/setup/grok.md and stop whenever it says to ask me.`
- [Claude Code](docs/setup/claude.md). Paste: `Follow docs/setup/claude.md and stop whenever it says to ask me.`

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `DATA_DIR` | `./data` | Directory for `state.db` and `workspace/` |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Local Ollama HTTP API |
| `OLLAMA_MODEL` | `llama3.2` | Model used when a bot has no override. Set this to a model you have pulled. |
| `CLI_BACKEND` | unset | Default for a new bot: `grok`, `claude`, or empty. Empty and `ollama` call Ollama. |
| `BIND_ADDR` | `127.0.0.1:8080` | Address the daemon listens on. A non-loopback address requires `AUTH_TOKEN` |
| `AUTH_TOKEN` | unset | If set, every route except `GET /api/health` requires `Authorization: Bearer <token>`. Required when `BIND_ADDR` is not loopback |
| `SANDBOX_BUILD_BINDS` | unset | Colon-separated absolute paths. With the `build` grant, each path is a read-only bind in the shell jail. A `build_binds` list in the policy file replaces this. |
| `POLICY_FILE` | `DATA_DIR/policy.yaml` when that file exists | Policy file. A named file that cannot be read fails startup. A missing default file is fine. |
| `POLICY_CLI_BACKENDS` | `grok,claude` | Comma-separated CLI backends. `*` allows grok and claude. An empty value allows none. |
| `POLICY_CLI_NETWORK` | `open` | `open`, `proxy`, `explicit-proxy`, or `none`. `proxy` sends CLI TCP through the shell allowlist proxy. `explicit-proxy` does that and dials an upstream corporate proxy. `none` gives the CLI no network. |
| `POLICY_CLI_NET_ALLOW` | empty | Comma-separated hosts for `proxy` and `explicit-proxy`. Empty denies every host. These are the destination hosts, not the corporate proxy. |
| `POLICY_HTTP_PROXY` | `HTTP_PROXY` or `http_proxy` | Upstream proxy URL used when `POLICY_CLI_NETWORK` is `proxy` or `explicit-proxy`. A password stays in the daemon. |
| `POLICY_HTTPS_PROXY` | `HTTPS_PROXY` or `https_proxy` | Upstream proxy for port 443. Falls back to `POLICY_HTTP_PROXY` when unset. |
| `POLICY_NO_PROXY` | `NO_PROXY` or `no_proxy` | Comma-separated hosts the upstream proxy does not handle. The allowlist still applies. |
| `POLICY_ENV_ALLOWLIST` | empty | Extra environment variables copied into a CLI child when they are set. API keys, `SSH_AUTH_SOCK`, and the jail's own variables are rejected. |
| `POLICY_DEFAULT_NET_ALLOW` | empty | Hosts used when a bot has the `net` grant and no `net_allow` of its own. |
| `POLICY_FORCE_LOCAL_ONLY` | false | Refuse a non-loopback Ollama URL and refuse CLI backends. |
| `POLICY_CLI_PINS` | empty | Optional checks, separated by `;`. Each item is `grok` or `claude` plus `path=/absolute`, `sha256=<64 hex>`, or `version=<token>`. Unset checks nothing. A miss fails that turn. |
| `POLICY_AUDIT_LOG` | empty | `stderr`, `syslog`, or an absolute file. Empty writes no audit lines. The schema is `docs/audit.md`. |
| `POLICY_DLP_PATTERNS` | empty | Go regular expressions, separated by `;`. A match fails the CLI turn before the process starts. Empty leaves the check off. |
| `POLICY_DLP_FILE` | empty | Absolute blocklist. A line is a case-insensitive literal unless it starts with `re:`. |
| `POLICY_DLP_COMMAND` | empty | Absolute executable. It reads the prompt on stdin and exits non-zero to reject. Its environment is only `PATH`. |
| `POLICY_DLP_SCAN_TOOLS` | false | Also check tool-result text before the next CLI round. |

Paths inside `DATA_DIR`:

```
data/state.db      bots, messages, memory, timers, runs, log
data/workspace/    the only tree bots may read, write, or shell in
```

`state.db` is SQLite in WAL mode. Names are unique case-insensitively; threads stay attached to the bot id across renames.

## CLI sessions

A bot with `cli_backend` `grok` or `claude` does not call Ollama. The daemon spawns that CLI in `workspace/bots/<bot id>/`, mode `0700`, one headless process per turn, and stores the CLI session id on the bot. The next message, DM, or timer resumes the same session. Auth is the CLI's (`grok login` or `claude` login) under the daemon user's `~/.grok` or `~/.claude`. This daemon does not store API keys, and it does not pass `XAI_API_KEY` or `ANTHROPIC_API_KEY` through the environment.

On Linux the CLI process is wrapped in bubblewrap. That bot directory is bind-mounted at its host path. Ollama file and shell tools still use the shared `workspace/`. The only home paths mounted are `~/.grok`, `~/.claude`, and `~/.claude.json` when that file exists, and they appear under `/lgb-home`. The child environment is cleared, then the jail sets `PATH`, `HOME`, and the locale names. An allowlisted variable is added only when it is set. An SSH agent socket and API keys are not copied. `bwrap` is required; the turn fails closed when it is missing. The default policy leaves the CLI network open so the CLI can reach its model API. `POLICY_CLI_NETWORK=proxy` adds `--unshare-net` and the same Unix-socket proxy the shell uses. `explicit-proxy` uses that same proxy and, when `HTTP_PROXY` or `HTTPS_PROXY` is set, dials the destination through that corporate proxy. `none` unshares the network and does not start a proxy. The CLI child does not receive `HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY`. `open` and `none` ignore those variables. A connect the interposer does not see fails closed. On kernels that block nested user namespaces, `grok --sandbox workspace` may be unable to start a second sandbox inside this jail. `--always-approve` and Claude's permission bypass stay on because a headless turn cannot prompt. The daemon refuses to start as root.

On macOS the same turn runs under `sandbox-exec`. There is no bind mount. `HOME` stays the user home, and the profile allows writes only in `~/.grok`, `~/.claude`, `~/.claude.json`, the bot directory, and a private temp directory. Other home paths, including `~/.ssh`, are not readable. The default policy leaves the network open. `proxy` allows only the proxy socket. `none` allows no network. `sandbox-exec` is required; the turn fails closed when it is missing. Apple marks `sandbox-exec` as deprecated. It is still the Seatbelt entry point this daemon uses, and its deprecation warning is not treated as a failed turn. A CLI that starts its own Seatbelt sandbox inside this one can fail the same way a nested `bwrap` can fail on Linux.

A bot whose backend is not in the policy fails that turn. It does not fall through to Ollama. `GET /api/policy` returns the loaded policy and uses the same authentication as the other routes.

For a machine that should not call a hosted model API:

```yaml
force_local_only: true
cli_network: none
allow_cli_backends: []
cli_net_allow: []
default_net_allow: []
env_allowlist: []
```

`force_local_only` refuses a non-loopback `OLLAMA_URL` at startup and disables CLI backends. `cli_network: none` is the setting when those backends stay enabled and must not reach the network. The file is `DATA_DIR/policy.yaml`, or the path in `POLICY_FILE`. The file wins over the environment. See `docs/plans/2026-10-13-policy-cli-network-plan.md`.

```bash
# new bots use Grok unless they set cli_backend
CLI_BACKEND=grok ./local-grok-bots
```

Per bot, `POST /api/bots` and `PATCH /api/bots/{id}` accept `cli_backend`: `grok`, `claude`, `ollama`, or `""`. Changing it clears the session id.

Grok:

```bash
grok --session-id ID -p PROMPT --sandbox workspace --cwd workspace/bots/<bot id> \
  --output-format streaming-json --always-approve --no-auto-update
```

Later turns pass `--resume ID` instead of `--session-id`. Session files stay in `~/.grok/sessions/`.

Claude Code:

```bash
claude --session-id UUID -p PROMPT --output-format stream-json --verbose \
  --include-partial-messages --permission-mode bypassPermissions
```

The process working directory is that bot's directory. Claude sessions are JSONL files under `~/.claude/projects/`. A rules file there is not visible to another CLI bot. There is no worktree.

The CLI process is killed after 30 minutes without a user message or a new turn, unless a timer created from the page is due within 2 minutes. A timer recorded as bot-created does not keep the process alive. The session file remains. Timers are still scheduled here; the prompt is prefixed `[scheduled]`.

DMs, create/update bot, memory, and timers are not MCP tools. The model puts a fenced block in its reply and the daemon runs it, then strips the fence:

```action
{"tool":"write_memory","key":"note","value":"hello"}
```

Creating a bot, updating a bot, sending a DM, and setting a timer are done from the page. A bot cannot do those.

File and shell work stays on the CLI. When a turn finishes, or the CLI asks for input, the daemon tries `notify-send` on Linux and `osascript` on macOS. If that tool is missing, the turn still completes.

Bots left on Ollama keep the HTTP client and the workspace jail below.

## Workspace

File tools resolve against `workspace/` and reject `..`, absolute host paths, and symlink escapes.

On Linux, `run_shell` uses bubblewrap when `bwrap` is installed, and otherwise `unshare` with a chroot. The workspace is bind-mounted at `/work`. The host filesystem outside it is not visible, and the shell starts with no network. If it reports its workspace as `/work`, that is the jail path, not the host path. If neither `bwrap` nor `unshare` can build the jail, the shell fails closed and the daemon still serves. The unshare jail exposes the entropy devices and not the rest of `/dev`.

On macOS, `run_shell` uses `sandbox-exec`. The shell's working directory is the workspace directory on the host, not `/work`, because Seatbelt cannot bind-mount a path. The profile still hides the rest of the host: reads of `/etc/passwd` and of files outside the workspace fail, and writes outside the workspace fail. The shell starts with no network. libc connects are sent to the same allowlist proxy as on Linux, and Seatbelt allows only that proxy socket, so a connect the proxy does not see is denied. Mach lookup stays available so ordinary binaries can start. It is not a file or network grant. `sandbox-exec` is required; the shell fails closed when it is missing. The daemon still serves.

Grants on the bot (`net`, `git`, `ssh`, `build`) are set from the profile. A missing grant fails closed. `git push` returns a diff and does not push. The model is `docs/sandbox.md`.

To give a bot material, copy or mount it into `workspace/`. The shell PATH includes `/usr/bin`, `/bin`, and toolchain directories already on the read-only system prefix, such as `/usr/local/go/bin`, `/usr/local/bin`, and `/opt/homebrew/bin` when they exist. Home directories and `/snap` are not added.

## systemd

`deploy/local-grok-bots.service` is a system unit. It is not installed by this repo.

```bash
sudo useradd --system --create-home --home-dir /var/lib/local-grok-bots --shell /usr/sbin/nologin local-grok-bots
sudo chown -R local-grok-bots:local-grok-bots /var/lib/local-grok-bots
sudo install -m 755 local-grok-bots /usr/local/bin/local-grok-bots
sudo cp deploy/local-grok-bots.service /etc/systemd/system/local-grok-bots.service
sudo systemctl daemon-reload
sudo systemctl enable --now local-grok-bots
```

The unit sets `User=local-grok-bots` and `ProtectHome=true`. The service home is `/var/lib/local-grok-bots`, so `ProtectHome` does not hide it. Log the CLIs in once as that user (`sudo -u local-grok-bots -- grok login`, and the same for `claude`) so session files and credentials stay in that home. `bwrap` must be installed on the host.

Set `OLLAMA_MODEL` in the installed unit to a model `ollama list` actually shows. Add `After=ollama.service` and `Wants=ollama.service` if that unit exists, so the first boot does not race Ollama.

For a user unit, change `WantedBy` to `default.target`, put the unit in `~/.config/systemd/user/`, and run `systemctl --user enable --now local-grok-bots`.

## launchd

`deploy/com.local-grok-bots.plist` is a per-user LaunchAgent. It is not installed by this repo. Replace `__HOME__` with the absolute home of the user who has run `grok login` or `claude` login. On Apple Silicon, Homebrew's prefix is `/opt/homebrew`; point `ProgramArguments` at the binary you installed if it is not `/usr/local/bin/local-grok-bots`.

```bash
mkdir -p "$HOME/Library/Application Support/local-grok-bots" "$HOME/Library/Logs" "$HOME/Library/LaunchAgents"
sed "s|__HOME__|$HOME|g" deploy/com.local-grok-bots.plist > "$HOME/Library/LaunchAgents/com.local-grok-bots.plist"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.local-grok-bots.plist"
```

The agent runs as that user, so the daemon's refusal to run as root still holds. Do not install this plist as a LaunchDaemon. `sandbox-exec` must be present, which it is on current macOS. Log the CLIs in once in that user's session so credentials stay in `~/.grok` or `~/.claude`.

The page listens on `127.0.0.1` and is plain HTTP. To listen on another address, set `BIND_ADDR` and `AUTH_TOKEN` together. The daemon refuses to start when a non-loopback bind has no token. Do not port-forward it.

## What the page does today

The page is a roster (mark, name, label, status), a conversation with a composer that stays enabled during a run, a profile opened from the bot menu, and a separate log. The conversation does not edit the bot. A working animation sits at the bottom of the message list while a run is alive. Pin and hide are roster flags; hide does not pause the bot or its routines.

Streaming tokens and tool lines come from `GET /api/bots/{id}/thread/stream?run_id=`. Tokens that arrive with a tool call show while that run is streaming and are not kept on the thread. The kept reply is the one with no tool call. If Ollama is down, the run fails and the log records `model_call` with the error. A restart marks an in-flight run `error` / `daemon_restart` and does not resume the model call. A timer whose `next_fire_at` is already past at boot is logged as `timer_missed` and rescheduled, not run. A run stops after 8 model rounds with `tool round limit`. The page can continue that transcript for another 8 rounds. A new message, another turn, or a restart drops the offer.

Target shape is in `docs/PRD.md`. Contracts are in `docs/specs.md`.
