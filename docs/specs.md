# Local Grok Bot bootstrap — specifications

Contracts the daemon and the web page share. The PRD is the target; this is what each side implements so the other can be built against it.

Personal use, one machine. The default bind is loopback and needs no token. A non-loopback bind requires `AUTH_TOKEN`. The shared secret does not change the routes.

## 1. Data model

Stable ids for anything that gets referenced. Names are for humans and for bot-to-bot addressing.

### Bot

| Field | Type | Notes |
|---|---|---|
| id | string (uuid) | Primary key. Never changes. |
| name | string | Unique, case-insensitive. Used for addressing. |
| label | string | Short role line, shown under the name. Not the description. |
| description | text | Standing prompt: role, boundaries, durable rules. |
| mark | object | `{shape, color}`. Roster and thread only. No behavior. |
| status | enum | `idle` \| `running` \| `paused`. |
| model | string, nullable | Override. Null means the daemon default (local Ollama). |
| created_at | timestamp | |
| updated_at | timestamp | |

Renaming a bot must not break its thread, its DMs, or its timers. Those reference `id`.

`update_bot` identifies the target by `id` if present, otherwise by `name`. A rename only happens when `id` is set and `name` differs. Passing only `name` selects the bot and does not rename it.

`description` is the field the model is prompted with. `label` is display only.

### Memory

Per bot. Not a blob.

| Field | Type | Notes |
|---|---|---|
| bot_id | string | |
| key | string | Unique per bot. |
| value | text | |
| updated_at | timestamp | |

Memory is notes the bot keeps. It is not a substitute for the log.

### Message

| Field | Type | Notes |
|---|---|---|
| id | string (uuid) | |
| bot_id | string | The bot whose thread this belongs to. |
| thread | string | `user` for the user conversation. `dm:<other_bot_id>` for a direct message. |
| role | enum | `user` \| `bot` \| `system`. |
| content | text | |
| run_id | string, nullable | Set when a bot message or system note was produced by a run. |
| created_at | timestamp | Order is by this, then by id. |

One primary user thread per bot. DMs are stored as messages on both sides. Both bots can list the exchange, and the log has both directions.

An inbound DM is also represented in the receiving bot’s user thread as a system line: “Message from {name}”. Storage of the DM itself does not change.

### Timer

| Field | Type | Notes |
|---|---|---|
| id | string (uuid) | |
| bot_id | string | |
| name | string | Shown on the profile. |
| schedule | string | Interval for now: `30s`, `5m`, `2h`, `1d`. Cron is later. |
| prompt | text | Injected as the turn prompt when the timer fires. |
| enabled | bool | |
| next_fire_at | timestamp | Computed by the daemon. |
| last_fire_at | timestamp, nullable | |

### Run

| Field | Type | Notes |
|---|---|---|
| id | string (uuid) | Returned to the client as `run_id`. |
| bot_id | string | |
| status | enum | `running` \| `done` \| `error` \| `cancelled`. |
| started_at | timestamp | |
| finished_at | timestamp, nullable | |
| error | text, nullable | Includes `tool round limit`, `daemon_restart`, `timed out`, `shutdown`. |

A run is capped at 8 model rounds. Hitting the cap finishes the run as `error` / `tool round limit` and writes `run_finished`. The daemon keeps that run's model transcript in memory, including tool results, and `GET /api/bots` and `GET /api/bots/{id}` include `continue_run_id` while the offer is held. `POST /api/bots/{id}/runs/{run_id}/continue` starts a new run on that transcript for another 8 rounds and returns `{run_id}`. The capped run stays `error`. The client does not send a transcript. A second continue while the bot is running is 409 and does not take the transcript. A missing offer is 404. A new user message, a timer or DM turn, or a daemon restart drops the offer. Hitting the cap again offers the new run.

### Log event

| Field | Type | Notes |
|---|---|---|
| id | string or integer | Monotonic. |
| ts | timestamp | |
| bot_id | string, nullable | Null for daemon-level events. |
| kind | enum | Closed set. See §5. |
| detail | json | Small. See §5. |

`GET /api/log` returns newest-first.

## 2. Daemon API

JSON over HTTP. One SSE stream for a live turn. All routes under `/api`.

| Method | Path | Body / query | Returns |
|---|---|---|---|
| GET | /api/health | | `{status, version}` |
| GET | /api/bots | | `[{id, name, label, mark, status, model}]` |
| POST | /api/bots | `{name, label?, description, mark?, model?}` | bot |
| GET | /api/bots/{id} | | bot including description |
| PATCH | /api/bots/{id} | `{name?, label?, description?, mark?, model?, status?}` | bot |
| DELETE | /api/bots/{id} | | 204 |
| GET | /api/bots/{id}/thread | `?before=&limit=` | `{messages: [...]}` oldest-first |
| POST | /api/bots/{id}/thread/messages | `{content}` | `{message, run_id}` immediately |
| GET | /api/bots/{id}/thread/stream | `?run_id=` | SSE |
| POST | /api/bots/{id}/runs/{run_id}/cancel | | `{status}` |
| POST | /api/bots/{id}/runs/{run_id}/continue | | `{run_id}` for another 8 rounds on that capped transcript. 409 if the bot is running. 404 if there is no offer. |
| GET | /api/bots/{id}/memory | | `[{key, value, updated_at}]` |
| POST | /api/bots/{id}/memory | `{key, value}` | memory row |
| DELETE | /api/bots/{id}/memory/{key} | | 204 |
| GET | /api/bots/{id}/timers | | `[timer]` |
| POST | /api/bots/{id}/timers | `{name?, schedule, prompt, enabled?}` | timer |
| PATCH | /api/timers/{id} | `{name?, schedule?, prompt?, enabled?}` | timer |
| DELETE | /api/timers/{id} | | 204 |
| GET | /api/bots/{id}/dms | | list of other bots this bot has exchanged with |
| GET | /api/dms/{bot_a}/{bot_b} | `?before=&limit=` | messages between the two |
| GET | /api/log | `?bot_id=&kind=&before=&limit=` | `[event]` newest-first |

SSE events on the stream:

- `status` — `{state, text?}` while the run is alive. `state` is `working` or a short activity such as a tool name. This drives the animation at the bottom of the thread.
- `token` — `{text}`
- `tool_call` — `{name, arguments}`
- `tool_result` — `{name, ok, result_or_error}`
- `done` — `{run_id}`
- `error` — `{run_id, error}`

`POST .../messages` never blocks on the model. It persists the user message and returns. If a run starts, `run_id` is set. If the bot is already running, `run_id` may be null or may be the existing run; the message is still persisted and will be seen.

Optional gate on loopback: if `AUTH_TOKEN` is set in the daemon environment, require `Authorization: Bearer <token>` on every route except `/api/health`. A non-loopback `BIND_ADDR` refuses to start until that token is set. Same routes either way. The HTML page is still served on an unauthenticated `GET /` so the client can collect the token; API calls then 401 until it is set.

## 3. Turn and queue semantics

- `POST .../messages` always persists the user message, ordered, and returns.
- If the bot is `idle`, the post starts a run and returns its `run_id`.
- If the bot is `running`, the message joins that bot's queue. The running turn may observe new user messages before it finishes, or the next run starts the moment the current one ends and consumes the queue. Either is acceptable. Dropping the message or blocking the POST is not.
- A run ends in exactly one of `done`, `error`, `cancelled`.
- On daemon start, any run still marked `running` is marked `error` with reason `daemon_restart`. No resume of a half-finished model call.
- Cancel sets the run to `cancelled` and stops further tool calls. Partial output already persisted stays.
- Bot-to-bot DMs use the same queue on the receiving bot. The sender does not block waiting for a reply.
- Order is preserved. Nothing is dropped.
- A run that exceeds 8 model rounds ends `error` / `tool round limit`. The page can continue that transcript as a new run for another 8 rounds. A new message, another turn, or a restart drops the offer.
- While a run is `running`, the stream emits `status` events so the page can show the working animation. The animation clears on `done` or `error`.
- Text the model sends in the same response as a tool call is streamed as tokens for that run and kept in that run's in-memory transcript. It is not written to the thread. The stored reply is the response that has no tool call.

## 4. Bot tool surface

Tools the model can call. Each is logged on start and on finish.

| Tool | Arguments | Effect |
|---|---|---|
| list_bots | | `[{id, name, label, status}]` |
| read_bot | `{name or id}` | description and memory keys/values |
| write_memory | `{key, value}` | upsert on the calling bot |
| delete_memory | `{key}` | |
| clear_timer | `{id}` | deletes one of the calling bot's timers |
| read_file | `{path}` | inside the workspace directory only |
| write_file | `{path, content}` | inside the workspace directory only |
| run_shell | `{command}` | jailed to the workspace; stdout/stderr captured and truncated |

`create_bot`, `update_bot`, `send_dm`, and `set_timer` are not model tools. The page creates and edits bots and timers through the HTTP API. A bot that calls one of those names gets an error and no mutation. Paths that escape the workspace are rejected, including `..`, absolute host paths, and symlink escapes.

Arguments containing anything that looks like a secret are redacted in the log.

### Workspace and shell jail

```
<data dir>/workspace/     host path; this is the only tree tools may touch
```

`read_file` and `write_file` resolve against that directory and reject anything that leaves it.

On Linux, `run_shell` uses bubblewrap when `bwrap` is on `PATH`. Otherwise it re-execs under `unshare` into a user, mount, and network namespace, chroots, and bind-mounts the workspace at `/work`. Inside that jail the working directory is `/work`, not the host path. On macOS, `run_shell` uses `sandbox-exec`. The working directory is the host workspace path, because Seatbelt cannot bind-mount `/work`. On both platforms the host filesystem outside the workspace is not readable, and there is no network unless the bot has a grant. PATH also includes toolchain directories already on the read-only system prefix, including `/usr/local/go/bin`, `/usr/local/bin`, and `/opt/homebrew/bin` when they exist. Home directories and `/snap` are not added. If the platform jail cannot be built, the tool fails closed.

Writes to `.git/hooks`, shell rc names, and executable git settings are blocked.

A bot that reports its workspace as `/work` is reporting the Linux jail. On macOS it reports the host workspace path. Giving a bot material means mounting or copying it into `workspace/`. It does not mean relaxing the jail.

Named grants (`net`, `git`, `ssh`, `build`) live on the bot. The profile and the bot API set and clear them, along with `net_allow` and `ssh_allow`. The meta tools do not. A missing grant fails closed and is logged. `git push` returns the diff and does not push. The browser grant in `docs/sandbox.md` is not implemented.

## 5. Log schema

Append-only. `kind` is a closed set:

`user_message`, `bot_message`, `dm_sent`, `dm_received`, `tool_start`, `tool_end`, `bot_created`, `bot_updated`, `bot_deleted`, `timer_fired`, `timer_missed`, `model_call`, `run_started`, `run_finished`, `daemon_start`, `daemon_stop`, `grant_use`, `grant_denied`, `net_request`, `sandbox_block`.

`detail` holds the useful bits and stays small:

- messages: `message_id`, and for DMs the other bot id
- tools: `name`, `arguments` (redacted), `ok`, `error`
- bot changes: `fields` changed, `by` (`user` or bot id)
- timers: `timer_id`, `scheduled_for`
- model: `model`, `ok`, `error`, `tokens` if cheap to capture
- runs: `run_id`, `status`, `error`

The chat transcript stays readable. The log is allowed to be denser. If it is not in the log, it did not happen. `GET /api/log` is newest-first.

## 6. Persistence

SQLite, one file, WAL mode, on the desktop next to a workspace directory.

```
<data dir>/
  state.db          bots, messages, memory, timers, runs, log
  workspace/        files bots may read and write
```

On boot the daemon:

1. Opens the database.
2. Marks any `running` run as `error` / `daemon_restart`.
3. For each enabled timer, if `next_fire_at` is in the past, writes a `timer_missed` log line and computes the next future fire. It does not run the missed prompt.
4. Starts accepting HTTP.

No catch-up of missed timers. No replay of in-flight model calls.

## 7. Web UI

The page is a client. Refreshing reloads from the daemon. Four surfaces. The conversation does not contain the editor.

**Roster.** Mark, name, label, status. Click to open the conversation. A create control.

**Conversation.** The thread and the composer. The composer is never disabled during a run. While a run is in progress, a status animation sits at the bottom of the message list, near the latest messages, driven by `status` events on the stream. It clears when the run ends. Inbound DMs appear as a system line in this thread. There is no description editor on this view.

**Bot menu.** Opened from the conversation header, not as a side panel. Items: View profile, Pin, Hide, Duplicate, Delete.

**Profile.** A separate view. Mark, name, label, description, model override, grants, network and SSH allowlists, and the routines list (add, pause, delete, next run). This is the only place the description and the grants are edited.

**Log.** Filterable by bot and by kind. The verification surface.

## 8. Process

- Daemon starts on boot via a systemd user or system unit, or a per-user launchd agent.
- Binds on `127.0.0.1` by default. A LAN or other non-loopback address requires `AUTH_TOKEN`. No public exposure. Plain HTTP is fine on loopback.
- Default model is the local Ollama endpoint, overridable by `OLLAMA_MODEL` and per bot. If Ollama is down, runs fail with a clear log line and do not hang.
- Clean shutdown writes `daemon_stop`. Crash does not; the next start writes `daemon_start` and reconciles runs as above.
- On Linux, `bwrap` or `unshare` must be usable for `run_shell`. On macOS, `sandbox-exec` must be usable for `run_shell` and for a CLI turn. Missing, the tool or the turn fails; the daemon still serves.
- CLI network, CLI backends, the default shell allowlist, and build binds come from the Policy loaded at startup. The default leaves CLI network open and allows `grok` and `claude`. A backend the policy does not allow fails the turn. `explicit-proxy` sends allowlisted CLI destinations through the corporate proxy named by the policy. The proxy URL is not copied into the child. Optional `cli_pins` check the CLI binary before exec. No pin keeps the current launch.

## Out of these specs

Channels, computer-use, virtual displays, approval cards, multi-user accounts, per-bot microVMs, catch-up of missed timers, templates, documents, links, notifications, voice. The PRD's later list still applies.
