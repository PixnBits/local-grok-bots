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
| `BIND_ADDR` | `0.0.0.0:8080` | Address the daemon listens on |
| `AUTH_TOKEN` | unset | If set, every route except `GET /api/health` requires `Authorization: Bearer <token>` |
| `SANDBOX_BUILD_BINDS` | unset | Colon-separated absolute paths. With the `build` grant, each path is a read-only bind in the shell jail. |

Paths inside `DATA_DIR`:

```
data/state.db      bots, messages, memory, timers, runs, log
data/workspace/    the only tree bots may read, write, or shell in
```

`state.db` is SQLite in WAL mode. Names are unique case-insensitively; threads stay attached to the bot id across renames.

## Workspace

File tools resolve against `workspace/` and reject `..`, absolute host paths, and symlink escapes.

`run_shell` uses bubblewrap when `bwrap` is installed, and otherwise `unshare` with a chroot. The workspace is bind-mounted at `/work`. The host filesystem outside it is not visible, and the shell starts with no network. If it reports its workspace as `/work`, that is the jail path, not the host path. If neither `bwrap` nor `unshare` can build the jail, the shell fails closed and the daemon still serves.

Grants on the bot (`net`, `git`, `ssh`, `build`) are set from the profile. A missing grant fails closed. `git push` returns a diff and does not push. The model is `docs/sandbox.md`.

To give a bot material, copy or mount it into `workspace/`. The shell PATH includes `/usr/bin`, `/bin`, and toolchain directories already on the read-only `/usr` mount, such as `/usr/local/go/bin` and `/usr/local/bin` when they exist. Home directories and `/snap` are not added.

## systemd

`deploy/local-grok-bots.service` is a system unit. It is not installed by this repo.

```bash
sudo install -m 755 local-grok-bots /usr/local/bin/local-grok-bots
sudo install -d /var/lib/local-grok-bots
sudo cp deploy/local-grok-bots.service /etc/systemd/system/local-grok-bots.service
sudo systemctl daemon-reload
sudo systemctl enable --now local-grok-bots
```

Set `OLLAMA_MODEL` in the installed unit to a model `ollama list` actually shows. Add `After=ollama.service` and `Wants=ollama.service` if that unit exists, so the first boot does not race Ollama.

For a user unit, change `WantedBy` to `default.target`, put the unit in `~/.config/systemd/user/`, and run `systemctl --user enable --now local-grok-bots`.

The page is plain HTTP on the LAN. The browser warning is expected. Do not port-forward it.

## What the page does today

The page is a roster (mark, name, label, status), a conversation with a composer that stays enabled during a run, a profile opened from the bot menu, and a separate log. The conversation does not edit the bot. A working animation sits at the bottom of the message list while a run is alive. Pin and hide are roster flags; hide does not pause the bot or its routines.

Streaming tokens and tool lines come from `GET /api/bots/{id}/thread/stream?run_id=`. Tokens that arrive with a tool call show while that run is streaming and are not kept on the thread. The kept reply is the one with no tool call. If Ollama is down, the run fails and the log records `model_call` with the error. A tool call Ollama cannot parse is diagnosed and tried once more in that run, when a round remains. A second parse failure, or a parse failure on the last round, ends the run. Unreachable Ollama, an HTTP error, a stream failure, and a timeout are not retried. A restart marks an in-flight run `error` / `daemon_restart` and does not resume the model call. A timer whose `next_fire_at` is already past at boot is logged as `timer_missed` and rescheduled, not run. A run stops after 8 model rounds with `tool round limit`. The page can continue that transcript for another 8 rounds. A new message, another turn, or a restart drops the offer.

Target shape is in `docs/PRD.md`. Contracts are in `docs/specs.md`.
