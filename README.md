# local-grok-bots

One Go daemon for a personal bot roster on the Framework Desktop. It keeps bots, threads, DMs, timers, and the log in SQLite, calls a local Ollama by default, and serves a small web page. It can also use a CLI backend (Claude Code or Grok CLI); backend selection and jail behavior come from `policy.toml` (see `policy.toml.sample`).

```bash
go build -o local-grok-bots ./cmd/local-grok-bots
./local-grok-bots
```

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `DATA_DIR` | `./data` | Directory for `state.db` and `workspace/`. It must be owned by the daemon user and not group or other writable. That is checked at every start |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Local Ollama HTTP API |
| `OLLAMA_MODEL` | `llama3.2` | Model used when a bot has no override. Set this to a model you have pulled. |
| `BIND_ADDR` | `127.0.0.1:8080` | Address the daemon listens on |
| `AUTH_TOKEN` | unset | If set, every route except `GET /api/health` requires `Authorization: Bearer <token>` (or the cookie from `/login?token=`). It is accepted under the name `default`. With a CLI backend and no `AUTH_TOKEN`, a token is generated at `DATA_DIR/admin-token` (0600) and used the same way; see [docs/cli-isolation.md](docs/cli-isolation.md#daemon-api) |
| `AUTH_TOKENS_FILE` | unset | Path of a file of named access tokens, one `name:token` per line. Read at startup. SIGHUP reloads it when set, and is otherwise ignored (logged). See below. |
| `SANDBOX_BUILD_BINDS` | unset | Colon-separated absolute paths. With the `build` grant, each path is a read-only bind in the shell jail. |
| `TLS_CERT` | unset | PEM certificate for HTTPS on the existing listener. Set with `TLS_KEY`. `[daemon]` `tls_*` in policy replaces both. See [docs/voice.md](docs/voice.md) |
| `TLS_KEY` | unset | PEM private key paired with `TLS_CERT` |
| `TLS_SELF_SIGNED` | unset | `1` writes `DATA_DIR/tls/cert.pem` and `key.pem` mode 0600. Not combined with `TLS_CERT` |
| `WHISPER_BIN` | unset | Absolute path of a local whisper.cpp CLI. Set with `WHISPER_MODEL`. `POST /api/stt` stays disabled until `[voice] enabled = true` |
| `WHISPER_MODEL` | unset | Absolute path of the local whisper model |
| `PERM_CALLBACK_ADDR` | `127.0.0.1:0` | Loopback address for the Claude MCP permission callback. Opened only when that transport has a bot |

`AUTH_TOKENS_FILE` adds named tokens to the same gate as `AUTH_TOKEN`. Blank lines and lines whose first character after ASCII space, tab, and line-ending trim is `#` are ignored. A name is 1–64 characters from `[A-Za-z0-9._-]`. The token is the remainder of the line after the first `:`, trimmed, at least 32 characters, and each byte must be printable ASCII (`0x21`–`0x7E`: no spaces, control bytes, or non-ASCII). Only ASCII spaces, tabs and line endings are trimmed; any other character is part of the token and must be printable ASCII. Generate one with `openssl rand -hex 32`. The name `default` is reserved. `AUTH_TOKEN`, or the generated admin token, joins the set under that name, and a file entry named `default` is refused even when both are unset. Duplicate names or duplicate tokens, including a copy of the default token, refuse startup. A file that is empty, or that contains only blank lines and comments, refuses startup.

The file must live outside the workspace and any bot home (`DATA_DIR/workspace` and `DATA_DIR/cli`). The daemon refuses to start when that path, or the path a symlink resolves to, is inside either tree. It opens the file without following a symlink. The file must be a regular file, owned by the daemon user, mode `0600` or stricter (no group or other permission bits), with no extra hard link, and at most 64 KiB. The daemon refuses a file that fails those checks and leaves the mode unchanged. A line it cannot parse refuses startup; the error names the line number and does not include the token. Send SIGHUP to reload the file when `AUTH_TOKENS_FILE` is set. When it is unset, SIGHUP is ignored and the daemon logs that. Restart also picks up a change. Deleting `AUTH_TOKENS_FILE` and sending SIGHUP keeps the previous tokens. To revoke a token, write a file with the remaining tokens, or restart. A cookie whose token was removed stops working after the reload. Either source counts as a token. A non-loopback bind refuses to start when `AUTH_TOKEN` is unset, no admin token exists, and `AUTH_TOKENS_FILE` is unset. That error names both `AUTH_TOKEN` and `AUTH_TOKENS_FILE`. On a non-loopback bind, `AUTH_TOKEN` follows the same rule as a file token: at least 32 printable ASCII characters, or the daemon refuses to start. Loopback binds are unchanged.

Paths inside `DATA_DIR`:

```
data/state.db      bots, messages, memory, timers, runs, log
data/workspace/    shared tree; each bot's files and shell are under workspace/bots/<id>
```

`state.db` is SQLite in WAL mode. Names are unique case-insensitively; threads stay attached to the bot id across renames.

## Workspace

File tools (`read_file`, `write_file`, `edit_file`, `delete_file`) and `run_shell` use that bot's directory, `workspace/bots/<id>`. They reject `..`, absolute host paths, and symlink escapes. Another bot's directory is outside that root.

`run_shell` uses bubblewrap when `bwrap` is installed, and otherwise `unshare` with a chroot. That bot directory is bind-mounted at `/work`. The host filesystem outside it is not visible, and the shell starts with no network. If it reports its workspace as `/work`, that is the jail path, not the host path. If neither `bwrap` nor `unshare` can build the jail, the shell fails closed and the daemon still serves. With the `build` grant, each `SANDBOX_BUILD_BINDS` path is opened without following symlinks. Bubblewrap mounts that file descriptor (`--ro-bind-fd`) and does not fall back to a path bind. The unshare fallback refuses the bind with a daemon-generated `sandbox_block` (`refused bind <path>: unsupported without bwrap`) and does not mount the path.

On macOS, `run_shell` runs under `/usr/bin/sandbox-exec` with a generated Seatbelt profile. It denies by default, reads system paths and the workspace, writes only the workspace and a private temp dir, never writes `.git/hooks`, and has no network. There is no `/work` mount, so the shell starts in the real workspace path. `net` and `ssh` grants are denied on macOS because the connect proxy needs `LD_PRELOAD`. A missing `sandbox-exec` fails closed. Apple marks `sandbox-exec` deprecated; it still ships, but this path has only been compile-checked, not run on a Mac. Behavior change: before this release `run_shell` always failed closed on macOS; Ollama bots with `run_shell` now run commands there.

Grants on the bot (`net`, `git`, `ssh`, `build`) are set from the profile. A missing grant fails closed. `git push` returns a diff and does not push. The model is `docs/sandbox.md`.

User-configured connectors (COIs) are mediated the same way: credentials stay on the host, the daemon performs the real call, and the sandbox sees only a tool or a narrow call site. See the COI section in `docs/sandbox.md`.

## Permission broker

`broker = "hook"` asks before a Claude tool call (through `lgb-permhook`) and before `run_shell`. The flag is daemon-wide. `broker_bots` only chooses which bots use it. Build and install are in [docs/deploy-permission-broker.md](docs/deploy-permission-broker.md). Risk levels, rules, and the admin API are in [docs/permission-broker.md](docs/permission-broker.md).

To give a bot material, copy or mount it into that bot's directory under `workspace/bots/<id>`. The shell PATH includes `/usr/bin`, `/bin`, and toolchain directories already on the read-only `/usr` mount, such as `/usr/local/go/bin` and `/usr/local/bin` when they exist. Home directories and `/snap` are not added.

## Startup changes

Upgrade: a `credential_home` anywhere in `DATA_DIR` other than `DATA_DIR/coi/<name>` (for example `DATA_DIR/homes/*` or `DATA_DIR/cli/*`) now stops startup. Move it to `DATA_DIR/coi/<name>` or outside `DATA_DIR`.

A `[[tools.cli]]` `credential_home` that contains a protected path, for example the `[github]` `token_file`, refuses startup. Move the token file outside that home. A home inside `DATA_DIR/workspace` (raw or resolved) refuses startup and names both paths. A home inside another tool's home does the same. Inside `DATA_DIR`, the only accepted home is `DATA_DIR/coi/<name>`, where `<name>` is one path component and is not `homes`. A path nested under that name is allowed. `DATA_DIR/cli`, `DATA_DIR/mirrors`, `DATA_DIR/github`, `DATA_DIR/config`, `DATA_DIR` itself, `DATA_DIR/coi`, and `DATA_DIR/coi/homes` are refused. The error says to use `DATA_DIR/coi/<name>` or a path outside `DATA_DIR`. Two distinct `DATA_DIR/coi/<id>` homes are allowed. A home outside `DATA_DIR`, such as a user home, is allowed when it does not overlap a protected path.

A `DATA_DIR` that is a symlink, is not owned by the daemon user, or is group or other writable refuses every start.

A `SANDBOX_BUILD_BINDS` entry that does not exist, or that overlaps a protected path, refuses startup. At startup the daemon records a baseline: the device and inode of each protected path and of each existing ancestor directory up to but not including `/`. That baseline stays for the life of the process. SIGHUP does not replace it. A successful `AUTH_TOKENS_FILE` reload adds paths that were not already recorded. A failed reload leaves the snapshot unchanged. Required paths must exist when they are recorded: `DATA_DIR`, the admin token file when the daemon has created it, `POLICY_PATH` when it is set and the policy loaded, `AUTH_TOKENS_FILE` when it is set, the `[github]` `token_file` when it is set, the sandbox SSH key when that file already exists, and each configured `[[tools.cli]]` `credential_home`. A missing required path, or a missing ancestor of it, trips the snapshot (`protected path missing: <path>`). Optional paths may be absent: `state.db`, `state.db-wal`, `state.db-shm`, the secret directories under `DATA_DIR`, and the audit log. A missing optional path records the nearest existing ancestor directory and does not trip. An unconfigured path is not listed. The first time a recorded directory is missing, is no longer a directory, or has a new device or inode, the trip sticks, one audit row `protect_snapshot_tripped` is written, and one log line is written. While tripped, every build bind is refused (`refused bind <path>: protected path changed (restart required)` or `protected path missing (restart required)`). Nothing clears the trip except a restart. Replacing a protected directory needs a restart. A regular file such as `state.db-wal`, or a token file replaced inside the same directory, does not trip. An empty snapshot refuses every build bind. At run time, a bind that cannot be opened without following symlinks, or that overlaps a protected path, or whose opened inode is in that snapshot, is skipped and logged. The turn continues without that bind. Bubblewrap mounts the opened file descriptor and does not fall back to a path bind. Without bubblewrap, the unshare fallback refuses every build bind with a daemon-generated `sandbox_block` and does not mount the path. `DATA_DIR` itself is on the protected list. An empty protected list refuses every build bind.

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

A loopback bind can use plain HTTP. A LAN bind needs `AUTH_TOKEN` or `AUTH_TOKENS_FILE`, and TLS (`TLS_SELF_SIGNED=1` or a cert pair). `allow_insecure_lan` in policy is an explicit, discouraged opt-out for plain HTTP on that bind. Do not port-forward the page.

Release note: an `AUTH_TOKENS_FILE` that fails its checks now blocks startup even when `AUTH_TOKEN` is set. On a non-loopback bind, an `AUTH_TOKEN` shorter than 32 printable characters also blocks startup.

## launchd (macOS)

`deploy/org.pixnbits.local-grok-bots.plist` is a LaunchAgent. It binds `127.0.0.1:8080` and keeps data in `~/Library/Application Support/local-grok-bots`. Replace `USERNAME` first; launchd does not expand `~`.

```bash
GOOS=darwin GOARCH=arm64 go build -o local-grok-bots ./cmd/local-grok-bots   # amd64 for Intel
sudo install -m 755 local-grok-bots /usr/local/bin/local-grok-bots
mkdir -p ~/Library/"Application Support"/local-grok-bots ~/Library/LaunchAgents
sed "s/USERNAME/$USER/g" deploy/org.pixnbits.local-grok-bots.plist > ~/Library/LaunchAgents/org.pixnbits.local-grok-bots.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.pixnbits.local-grok-bots.plist
```

Stop it with `launchctl bootout gui/$(id -u)/org.pixnbits.local-grok-bots`. Logs go to `~/Library/Logs/local-grok-bots.log`. The SQLite driver is pure Go, so the binary cross-compiles without cgo. A binary copied from another machine may need `xattr -d com.apple.quarantine` or signing before Gatekeeper runs it.

## What the page does today

The page is a roster (mark, name, label, status), a conversation with a composer that stays enabled during a run, a profile opened from the bot menu, and a separate log. The conversation does not edit the bot. Messages render markdown in the page, including fenced code blocks with a language label and GFM pipe tables; stored text is unchanged and HTML in a message shows as text. Code blocks and messages have Copy buttons; a message's button copies its original markdown. While a run is alive, a working animation sits in the message list where the next reply will appear. Pin and hide are roster flags; hide does not pause the bot or its routines. Archive (bot menu) takes a bot off the roster, pauses its routines, and stops new runs while keeping all its data; the Archived list restores it. Delete is API-only.

Streaming tokens and tool lines come from `GET /api/bots/{id}/thread/stream?run_id=`. Tokens that arrive with a tool call show while that run is streaming and are not kept on the thread; they are kept with the run's tool records and show, in order, when the tool-call summary is opened. The kept reply is the one with no tool call. Each tool call is also stored per run, and after the run the reply shows a collapsed tool-call summary that opens on tap. If Ollama is down, the run fails and the log records `model_call` with the error. A tool call Ollama cannot parse is diagnosed and tried once more in that run, when a round remains. A second parse failure, or a parse failure on the last round, ends the run. Unreachable Ollama, an HTTP error, and a stream failure are not retried. A stall or a wait for the first output is retried once; a hard model cap, the run deadline, and Stop are not. A timeout that is not retried keeps the partial reply and ends as `timeout`. The page can retry that user turn or continue from the partial. An Ollama restart marks an in-flight run `error` / `daemon_restart` and does not resume the model call. A CLI restart marks that run `interrupted`, keeps `session_id`, and the next message or timer uses `--resume`. A timer whose `next_fire_at` is already past at boot is logged as `timer_missed` and rescheduled, not run. A message sent while a run is alive joins that run before its next model call; if the run has already made its last call, a new run answers it. Tools reach the model as full JSON Schemas with described, example-bearing arguments; a malformed call gets an error listing the expected arguments. `set_timer` takes `in` (one-shot, e.g. `5m`), `at` (one-shot RFC 3339), or `every` (repeating). A run stops after 8 model rounds with `tool round limit`. The page can continue that transcript for another 8 rounds. A new message, another turn, or a restart drops the offer.

Target shape is in `docs/PRD.md`. Contracts are in `docs/specs.md`.
