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

Paths inside `DATA_DIR`:

```
data/state.db      bots, messages, memory, timers, runs, log
data/workspace/    the only tree bots may read, write, or shell in
```

`state.db` is SQLite in WAL mode. Names are unique case-insensitively; threads stay attached to the bot id across renames.

## Workspace

File tools resolve against `workspace/` and reject `..`, absolute host paths, and symlink escapes.

`run_shell` needs `unshare` and user namespaces. It re-execs into a mount namespace, chroots, and bind-mounts the workspace at `/work`. Inside the jail the bot cannot see your home, `~/projects`, or host `/tmp`. If it reports its workspace as `/work`, that is the jail path, not the host path. If `unshare` is missing, shell calls fail closed and the daemon still serves.

To give a bot a real checkout, copy or mount it into `workspace/`. Do not expect the Grok Build CLI, `go`, or anything else on the host `PATH` to be callable unless it is visible inside that jail.

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

## What the page does

Three views: the bot list, a conversation whose composer stays enabled during a run, and a log filtered by bot and kind. Streaming tokens and tool lines come from `GET /api/bots/{id}/thread/stream?run_id=`. A failed run shows a banner; the reason is also in the log.

If Ollama is down, the run fails and the log records `model_call` with the error. A restart marks an in-flight run `error` / `daemon_restart` and does not resume the model call. A timer whose `next_fire_at` is already past at boot is logged as `timer_missed` and rescheduled, not run. A run stops after 8 model rounds with `tool round limit`.

Product shape is in `docs/PRD.md`. Contracts are in `docs/specs.md`.
