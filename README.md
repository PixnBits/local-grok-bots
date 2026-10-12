# local-grok-bots

One Go daemon for a personal bot roster on the Framework Desktop. It keeps bots, threads, DMs, timers, and the log in SQLite, calls a local Ollama, and serves a small web page.

```bash
go build -o local-grok-bots ./cmd/local-grok-bots
./local-grok-bots
```

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `DATA_DIR` | `./data` | Directory for `state.db` and `workspace/` |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Local Ollama HTTP API |
| `OLLAMA_MODEL` | `llama3.2` | Model used when a bot has no override. Set this to a model you have pulled. |
| `CLI_BACKEND` | unset | Default for a new bot: `grok`, `claude`, or empty. Empty and `ollama` call Ollama. |
| `BIND_ADDR` | `0.0.0.0:8080` | Address the daemon listens on |
| `AUTH_TOKEN` | unset | If set, every route except `GET /api/health` requires `Authorization: Bearer <token>` |
| `SANDBOX_BUILD_BINDS` | unset | Colon-separated absolute paths. With the `build` grant, each path is a read-only bind in the shell jail. |

Paths inside `DATA_DIR`:

```
data/state.db      bots, messages, memory, timers, runs, log
data/workspace/    the only tree bots may read, write, or shell in
```

`state.db` is SQLite in WAL mode. Names are unique case-insensitively; threads stay attached to the bot id across renames.

## CLI sessions

A bot with `cli_backend` `grok` or `claude` does not call Ollama. The daemon spawns that CLI in `workspace/`, one headless process per turn, and stores the CLI session id on the bot. The next message, DM, or timer resumes the same session. Auth is the CLI's (`grok login` or `claude` login) under the daemon user's `~/.grok` or `~/.claude`. This daemon does not store API keys, and it does not pass `XAI_API_KEY` or `ANTHROPIC_API_KEY` through the environment.

The CLI process is wrapped in bubblewrap. The workspace is bind-mounted at its host path. The only home paths mounted are `~/.grok`, `~/.claude`, and `~/.claude.json` when that file exists, and they appear under `/lgb-home`. The child environment is cleared, so an SSH agent socket is not inherited. `bwrap` is required; the turn fails closed when it is missing. Network stays open so the CLI can reach its model API. On kernels that block nested user namespaces, `grok --sandbox workspace` may be unable to start a second sandbox inside this jail. `--always-approve` and Claude's permission bypass stay on because a headless turn cannot prompt. The daemon refuses to start as root.

```bash
# new bots use Grok unless they set cli_backend
CLI_BACKEND=grok ./local-grok-bots
```

Per bot, `POST /api/bots` and `PATCH /api/bots/{id}` accept `cli_backend`: `grok`, `claude`, `ollama`, or `""`. Changing it clears the session id.

Grok:

```bash
grok --session-id ID -p PROMPT --sandbox workspace --cwd workspace \
  --output-format streaming-json --always-approve --no-auto-update
```

Later turns pass `--resume ID` instead of `--session-id`. Session files stay in `~/.grok/sessions/`.

Claude Code:

```bash
claude --session-id UUID -p PROMPT --output-format stream-json --verbose \
  --include-partial-messages --permission-mode bypassPermissions
```

The process working directory is the shared workspace. Claude sessions are JSONL files under `~/.claude/projects/`. There is no per-bot directory and no worktree. A rules file in the workspace is visible to every bot.

The CLI process is killed after 30 minutes without a user message or a new turn, unless a timer is due within 2 minutes. The session file remains. Timers are still scheduled here; the prompt is prefixed `[scheduled]`.

DMs, create/update bot, memory, and timers are not MCP tools. The model puts a fenced block in its reply and the daemon runs it, then strips the fence:

```action
{"tool":"send_dm","to":"Ada","content":"hello"}
```

File and shell work stays on the CLI. When a turn finishes, or the CLI asks for input, the daemon tries `notify-send` on Linux and `osascript` on macOS. If that tool is missing, the turn still completes.

Bots left on Ollama keep the HTTP client and the workspace jail below.

## Workspace

File tools resolve against `workspace/` and reject `..`, absolute host paths, and symlink escapes.

`run_shell` uses bubblewrap when `bwrap` is installed, and otherwise `unshare` with a chroot. The workspace is bind-mounted at `/work`. The host filesystem outside it is not visible, and the shell starts with no network. If it reports its workspace as `/work`, that is the jail path, not the host path. If neither `bwrap` nor `unshare` can build the jail, the shell fails closed and the daemon still serves. The unshare jail exposes the entropy devices and not the rest of `/dev`.

Grants on the bot (`net`, `git`, `ssh`, `build`) are set from the profile. A missing grant fails closed. `git push` returns a diff and does not push. The model is `docs/sandbox.md`.

To give a bot material, copy or mount it into `workspace/`. The shell PATH includes `/usr/bin`, `/bin`, and toolchain directories already on the read-only `/usr` mount, such as `/usr/local/go/bin` and `/usr/local/bin` when they exist. Home directories and `/snap` are not added.

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

The page is plain HTTP on the LAN. The browser warning is expected. Do not port-forward it.

## What the page does today

The page is a roster (mark, name, label, status), a conversation with a composer that stays enabled during a run, a profile opened from the bot menu, and a separate log. The conversation does not edit the bot. A working animation sits at the bottom of the message list while a run is alive. Pin and hide are roster flags; hide does not pause the bot or its routines.

Streaming tokens and tool lines come from `GET /api/bots/{id}/thread/stream?run_id=`. Tokens that arrive with a tool call show while that run is streaming and are not kept on the thread. The kept reply is the one with no tool call. If Ollama is down, the run fails and the log records `model_call` with the error. A restart marks an in-flight run `error` / `daemon_restart` and does not resume the model call. A timer whose `next_fire_at` is already past at boot is logged as `timer_missed` and rescheduled, not run. A run stops after 8 model rounds with `tool round limit`. The page can continue that transcript for another 8 rounds. A new message, another turn, or a restart drops the offer.

Target shape is in `docs/PRD.md`. Contracts are in `docs/specs.md`.
