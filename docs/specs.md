# Local Grok Bot bootstrap — specifications

Contracts the daemon and the web page share. The PRD is the target; this is what each side implements so the other can be built against it.

Personal use, one machine, no auth required if the daemon binds on the LAN. A shared-secret header is the only optional gate, and it must not change the routes.

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
| model | string, nullable | Override. Null means the daemon default. |
| backend | string, nullable | Override of daemon backend: `ollama` \| `claude` \| `grok`. Null means daemon default. v1 is daemon-global; per-bot is later. |
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
| timed_out | bool | Present and true when this bot reply is the partial kept after a timeout. Omitted otherwise. |

One primary user thread per bot. DMs are stored as messages on both sides. Both bots can list the exchange, and the log has both directions.

An inbound DM is also represented in the receiving bot’s user thread as a system line: “Message from {name}”. Storage of the DM itself does not change.

### Timer

| Field | Type | Notes |
|---|---|---|
| id | string (uuid) | |
| bot_id | string | |
| name | string | Shown on the profile. |
| schedule | string | A repeating interval (`30s`, `5m`, `2h`, `1d`), or `once` for a one-shot timer: it fires at `next_fire_at`, then sets `enabled` false and keeps the row. Restoring an archived bot keeps a one-shot's time, or fires it at once if that time passed. A one-shot missed while the daemon was down is logged `timer_missed` and disabled. Cron is later. |
| prompt | text | Injected as the turn prompt when the timer fires. |
| enabled | bool | |
| next_fire_at | timestamp | Computed by the daemon. |
| last_fire_at | timestamp, nullable | |

### Run

| Field | Type | Notes |
|---|---|---|
| id | string (uuid) | Returned to the client as `run_id`. |
| bot_id | string | |
| status | enum | `running` \| `waiting` \| `done` \| `error` \| `cancelled` \| `timeout`. `waiting` is a native run suspended for a permission decision on the same run id; it is not terminal. `timeout` is an Ollama stall, first-output wait, model cap, or run cap that was not retried. |
| started_at | timestamp | |
| finished_at | timestamp, nullable | |
| error | text, nullable | Includes `tool round limit`, `daemon_restart`, `timed out`, `shutdown`. For status `timeout` it is the human sentence without the `Notice: ` prefix, naming the limit and its value. |

A run is capped at 8 model rounds. Hitting the cap finishes the run as `error` / `tool round limit` and writes `run_finished`. The daemon keeps that run's model transcript in memory, including tool results, and `GET /api/bots` and `GET /api/bots/{id}` include `continue_run_id` while the offer is held. `POST /api/bots/{id}/runs/{run_id}/continue` starts a new run on that transcript for another 8 rounds and returns `{run_id}`. The capped run stays `error`. The client does not send a transcript. A second continue while the bot is running is 409 and does not take the transcript. A missing offer is 404. A new user message, a timer or DM turn, or a daemon restart drops the offer. Hitting the cap again offers the new run. An Ollama run that ends `timeout` holds the same kind of offer: the transcript, the partial reply when there is one, and a short "Continue from where you stopped." nudge. `POST /api/bots/{id}/runs/{run_id}/retry` answers the same user turn again without that partial or its notice. It is allowed only when `run_id` is the bot's latest run, that run's status is `timeout`, and the bot is not running or paused (409 otherwise, 404 for an unknown bot, an unknown run, a run that is not the latest, or a run that is not `timeout`). It returns `{run_id}` and drops the resume offer.

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
| PATCH | /api/bots/{id} | `{name?, label?, description?, mark?, model?, status?, pinned?, hidden?, archived?}` | bot. `archived: true` stamps `archived_at`, pauses the bot's enabled timers (marked `archive_paused`), and stops new runs; the thread, memory, timers, and queued messages are kept. `archived: false` clears it, re-enables only the timers archiving paused (next fire counted from now), and starts a run if messages are waiting. Bots carry `archived` and `archived_at` |
| DELETE | /api/bots/{id} | | 204. Hard delete; API only, the page offers Archive instead |
| GET | /bots/{id} | | the page (HTML), same as `/`; the client opens that bot. When a token is configured, an unauthenticated request is served with 401 like `/` |
| GET | /api/bots/{id}/thread | `?before=&limit=` (limit default 50, max 200; `before` is a message id) | the newest `limit` messages before `before` (or overall), oldest first, plus `has_more` (older messages remain): `{messages: [...], has_more, tools: {run_id: [{name, arguments, ok, result_or_error, created_at}]}}` oldest-first; `tools` lists, per reply run, that run's records in order: `kind: "text"` is what the model wrote in the same response as a tool call (in `result_or_error`, no name or arguments), stored before that round's calls; `kind: "call"` is a tool call (arguments redacted, result clipped to 4000 bytes); `kind: "permission"` is a CLI permission decision (`name` is the tool, `arguments` redacted, `ok` true when allowed, `result_or_error` is JSON `{decision, source, rule?, transport?}`). CLI turns store the same `text` and `call` records as Ollama turns: text streamed before a tool call, then the call with its result |
| POST | /api/bots/{id}/thread/messages | `{content}` | `{message, run_id}` immediately |
| GET | /api/bots/{id}/thread/stream | `?run_id=` | SSE |
| POST | /api/bots/{id}/runs/{run_id}/cancel | | `{status}` |
| POST | /api/bots/{id}/runs/{run_id}/continue | | `{run_id}` for another 8 rounds on that capped transcript, or on a timed-out transcript including the partial. 409 if the bot is running. 404 if there is no offer. |
| POST | /api/bots/{id}/runs/{run_id}/retry | | `{run_id}` for a new run of the latest `timeout` turn, without that run's bot reply or notice. 409 if the bot is running, paused, or shutting down. 404 if the bot or run is unknown, the run is not the latest, or its status is not `timeout`. |
| GET | /api/bots/{id}/memory | | `[{key, value, updated_at}]` |
| POST | /api/bots/{id}/memory | `{key, value}` | memory row |
| DELETE | /api/bots/{id}/memory/{key} | | 204 |
| GET | /api/bots/{id}/timers | | `[timer]` |
| GET | /api/bots/{id}/state | | `{timers, memory, grants, net_allow, ssh_allow, tools: {current, seen, up_to_date, last_notice}, runs (latest 5), warnings?}` read-only summary for the state panel |
| POST | /api/bots/{id}/timers | `{name?, schedule, prompt, enabled?}` | timer |
| PATCH | /api/timers/{id} | `{name?, schedule?, prompt?, enabled?}` | timer |
| DELETE | /api/timers/{id} | | 204 |
| GET | /api/bots/{id}/dms | | list of other bots this bot has exchanged with |
| GET | /api/dms/{bot_a}/{bot_b} | `?before=&limit=` | messages between the two |
| GET | /api/log | `?bot_id=&kind=&before=&limit=` | `[event]` newest-first |
| GET | /api/permbroker/pending | | `{pending: [...]}`. Admin token. Each item has `id`, `bot_id`, `session_id`, `run_id`, `task_id`, `tool`, redacted `argv` and `command`, `cwd`, `level`, `input_hash`, `created_at`, `ruleset` |
| POST | /api/permbroker/pending/deny-all | `{}` denies every current item. `{ids}` denies that set, or nothing if any id is missing. `{ids:[]}` denies none | `{ok}`. Admin token. Same cross-site check as other mutations |
| POST | /api/permbroker/pending/{id} | `{decision, scope?}`. `decision` is `approve` or `deny`. `scope` is `once`, `task`, `bot`, or `global` | `{ok}`. Admin token. 409 when the item is stale |
| POST | /api/permbroker/hook/repin | | `{ok}`. Admin token. Records the current hook file. A missing or unsafe hook is refused and the old pin stays |
| GET | /api/permbroker/rules | | `{rules: [...]}`. Admin token. Each row has `id`, `effect`, `scope`, `bot_id`, redacted `argv` or `pattern`, `kind`, `source`, `active` and `needs_confirm` when an imported allow is waiting, `created_at`, `last_used_at`, `uses` |
| DELETE | /api/permbroker/rules/{id} | | `{ok}`. Admin token. 404 when the id is unknown. Writes an audit row and bumps the ruleset |
| POST | /api/permbroker/rules/{id}/confirm | | `{ok}`. Admin token. Activates one imported allow. Writes an audit row with the id and a hash and bumps the ruleset. 400 when the row is already active. 404 when the id is unknown |
| POST | /api/permbroker/bots/{id}/git-baseline | | `{ok}`. Admin token. Records that bot's git baseline again. Writes an audit row with the bot id. Does not bump the ruleset |

SSE events on the stream:

- `status` — `{state, text?}` while the run is alive. `state` is `working` or a short activity such as a tool name. This drives the animation at the bottom of the thread.
- `token` — `{text}`
- `tool_call` — `{name, arguments}`
- `tool_result` — `{name, ok, result_or_error}`
- `done` — `{run_id}`
- `error` — `{run_id, error}`
- `timeout` — `{run_id, error, limit}` terminal, same as `done` and `error` for stream history. `error` is the sentence stored on the run.
- `stream_reset` — `{run_id, reason}` not terminal. The page drops the live partial for that run. `reason` is `first_output_timeout` or `stall_timeout`.

`POST .../messages` never blocks on the model. It persists the user message and returns. If a run starts, `run_id` is set. If the bot is already running, `run_id` may be null or may be the existing run; the message is still persisted and will be seen.

Optional gate: if `AUTH_TOKEN` is set, a CLI backend generated an admin token, or `AUTH_TOKENS_FILE` supplies at least one token, require `Authorization: Bearer <token>` or the `lgb_auth` cookie on every route except `GET /api/health`, `GET /login`, and the MCP permission routes. Per-run lgb tokens stay on their own routes. Broker admin routes (pending list, decide, deny-all, repin, rules, confirm, and git baseline) require an admin token. When none is configured they return 403 `{"error":"admin token required"}`. When a token is configured, a missing credential is 401 and a live run token is 403. Mutations also use the host allowlist and the cross-site check (`Sec-Fetch-Site` and `Origin`). With no token from either source, routes other than the broker admin routes are open. Same routes either way. The HTML page is still served on an unauthenticated `GET /` so the client can collect a token; API calls then 401 until one is set.

`AUTH_TOKENS_FILE` is a path, read at startup and again on SIGHUP when it is set. When it is unset, SIGHUP is ignored and the daemon logs that. Restart also picks up a change. A cookie for a token the reload removes stops working after that reload. Each line is `name:token`. Blank lines and lines whose first character after ASCII space, tab, and line-ending trim is `#` are ignored. A name is 1–64 characters from `[A-Za-z0-9._-]`. The token is split on the first `:`, trimmed, at least 32 characters, and each byte must be printable ASCII (`0x21`–`0x7E`: no spaces, control bytes, or non-ASCII). Only ASCII spaces, tabs and line endings are trimmed; any other character is part of the token and must be printable ASCII. `openssl rand -hex 32` generates one. The name `default` is reserved. `AUTH_TOKEN`, or the generated admin token, joins the set under that name, and a file entry named `default` is an error even when both are unset. Duplicate names or duplicate tokens, including a copy of the default token, refuse startup. A file that is empty, or that contains only blank lines and comments, refuses startup.

The file must live outside the workspace and any bot home (`DATA_DIR/workspace` and `DATA_DIR/cli`). Startup fails when the path, or the path a symlink resolves to, is inside either tree. The file is opened without following a symlink. It must be a regular file, owned by the daemon's effective user, mode `0600` or stricter (no group or other permission bits), with no extra hard link, and at most 64 KiB. The daemon refuses a file that fails those checks and does not change its mode. A file that cannot be opened or read, or any bad line, refuses startup. The same checks run on SIGHUP when the file is set; a failed reload keeps the previous tokens. Deleting `AUTH_TOKENS_FILE` and sending SIGHUP keeps the previous tokens. To revoke a token, write a file with the remaining tokens, or restart. The error names the line number and does not include the token. `GET /login?token=` accepts any configured token, sets the cookie to that presented token, and writes an audit row `{"action":"auth_login","token_name":<name>}`. A failed login writes `{"action":"auth_login_failed"}` with no name and no token. A successful reload writes `{"action":"auth_tokens_reloaded","count":N}`. A failed reload writes `{"action":"auth_tokens_reload_failed","reason":"<code>"}` with no error text, no path, no token name, and no token value. `reason` is one of `location`, `bind`, `open`, `type`, `mode`, `owner`, `nlink`, `size`, `parse`, `empty`, `symlink`, or `other`. A non-loopback bind warns at startup only when `AUTH_TOKEN` is unset, no admin token was generated, and `AUTH_TOKENS_FILE` is unset. That warning names both `AUTH_TOKEN` and `AUTH_TOKENS_FILE`.

## 3. Turn and queue semantics

- `POST .../messages` always persists the user message, ordered, and returns.
- If the bot is `idle`, the post starts a run and returns its `run_id`.
- If the bot is `running`, the post returns the live `run_id` and the message is folded into that run: before each model call the run appends any turn input (user messages, scheduled prompts, inbound DMs) stored after what it has already read, records how far it has read in `runs.input_through`, and writes `run_input`. A message that lands after the run's last model call is not lost: the next run starts the moment the current one ends and consumes it. The page follows whichever run is active. Dropping the message or blocking the POST is not acceptable.
- A run ends in exactly one of `done`, `error`, `cancelled`, `timeout`.
- On daemon start, any run still marked `running` is marked `error` with reason `daemon_restart`. No resume of a half-finished Ollama model call. A CLI backend instead marks that run `interrupted`, keeps `session_id`, and the next user message or timer resumes with `--resume`.
- Cancel sets the run to `cancelled` and stops further tool calls. Partial output already persisted stays.
- Bot-to-bot DMs use the same queue on the receiving bot. The sender does not block waiting for a reply.
- Order is preserved. Nothing is dropped.
- A run that exceeds 8 model rounds ends `error` / `tool round limit`. The page can continue that transcript as a new run for another 8 rounds. A new message, another turn, or a restart drops the offer.
- While a run is `running`, the stream emits `status` events so the page can show the working animation. The animation clears on `done`, `error`, or `timeout`.
- Text the model sends in the same response as a tool call is streamed as tokens for that run and kept in that run's in-memory transcript. It is not written to the thread. The stored reply is the response that has no tool call.
- A model response that fails because a tool call could not be parsed is diagnosed in that run's transcript and tried once more, when a round remains. The diagnosis is not written to the thread. A second parse failure ends the run as `error`. A parse failure on the last of the 8 rounds is that error and does not become `tool round limit`. Unreachable Ollama, an HTTP error, and a stream failure are not retried. A wait for the first output (`first_output_timeout`, default 5m) or a gap between output chunks (`stall_timeout`, default 2m) is retried once per run (`stall_retries`, 0 disables) while the run is still alive. Output is content, thinking, a tool call, or the final done chunk. Thinking is activity only. A hard `model_timeout` (unset means the effective `run_timeout`; it no longer defaults to 3m), the run deadline, Stop, and shutdown are not retried. A timeout that is not retried keeps the partial reply (`timed_out`) and ends the run as `timeout`.

## 4. Bot tool surface

Tools the model can call. Each is logged on start and on finish. Every model call sends the whole list in Ollama's `tools` field as JSON Schema objects: each argument has a `type` and a `description` with an example. There is no discovery tool or step. A call missing a required argument, or with arguments in the wrong shape, fails with an error that names the problem and lists the tool's expected arguments. The system prompt starts with the current time in RFC 3339 and the daemon's time zone. It also states that the attached tools are the current, authoritative set and override anything said earlier in the conversation or in memory about which tools exist.

Tool-change notices: each bot stores the SHA-256 and a JSON snapshot of the tool list (names, descriptions, schemas) it last saw, in `bots.tool_hash` and `bots.tool_snapshot`. At the start of every run that is not a continuation, if the current list differs, the daemon posts a thread line `Notice: Tools updated: added X; changed Y (now takes a/b/c); removed Z.` and saves the new snapshot. A bot with no snapshot (one that existed before this) that has replied before gets a one-time `Notice: Tools available now: <names>. ...`; a brand-new bot just records its snapshot. Notice lines reach the model as user messages, show in the thread, do not queue a turn, and are logged as `tools_changed`.

Belief lint: `write_memory` rejects notes whose key or value claim tool availability or absence (phrases like "only have", "no access", "cannot", "don't have" near a tool name or the word "tool"), returning an error that tools are attached per call and must not be stored. Description warnings: on create/update and on GET bot, the daemon computes advisory `warnings` for standing prompts that name a `Something CLI` or a backticked command not on PATH in the jail, or a tool-like name not in `toolDefs`. Warnings appear on the profile page; they do not block saves.

| Tool | Arguments | Effect |
|---|---|---|
| list_bots | | `[{id, name, label, status}]` |
| read_bot | `{name or id}` | description and memory keys/values |
| send_dm | `{to, content}` | persists a DM, queues a turn on the recipient |
| create_bot | `{name, label?, description, model?, server_tools?}` | same as `POST /api/bots`. Omit `server_tools`, or send `null`, to inherit policy. `[]` allows none of those types. |
| update_bot | `{id or name, name?, label?, description?, model?, server_tools?}` | same as `PATCH`; rename requires `id`. Omit `server_tools` to leave it unchanged. `null` inherits policy. `[]` allows none. |
| write_memory | `{key, value}` | upsert on the calling bot |
| delete_memory | `{key}` | |
| set_timer | `{prompt, in? \| at? \| every?, name?}`, exactly one of `in` (one-shot duration like `5m`), `at` (one-shot RFC 3339 time with offset, must be in the future), `every` (repeating interval) | creates an enabled timer on the calling bot and returns `{id, schedule, prompt, next_fire_at, fires_at_local}`. Also accepted: `schedule` (as `every`, or as `in` when `repeat` is false), `seconds` / `in_seconds` / `minutes` numbers, and `message` / `text` / `reminder` for `prompt` |
| list_timers | | the calling bot's timers |
| clear_timer | `{id}` | deletes one of the calling bot's timers |
| read_file | `{path}` | inside the workspace directory only (Ollama mode) |
| write_file | `{path, content}` | inside the workspace directory only (Ollama mode) |
| run_shell | `{command}` | jailed to the workspace; stdout/stderr captured and truncated (Ollama mode) |

Paths that escape the workspace are rejected, including `..`, absolute host paths, and symlink escapes. The meta tools (`create_bot`, `update_bot`) are ordinary tools; the profile performs the same mutations through the API. A change made by a bot is logged with the acting bot id.

Arguments containing anything that looks like a secret are redacted in the log.

**Mode note:** In CLI mode (`backend = claude` or `grok`), `read_file`, `write_file`, and `run_shell` are not daemon tools. The CLI's own tools replace them and run inside the CLI's sandbox. The daemon's only filesystem touch is the narrow timer-injection channel. The daemon does not re-implement the CLI's allow/deny rules.

### Workspace and shell jail (Ollama mode)

```
<data dir>/workspace/     host path; this is the only tree tools may touch
```

`read_file` and `write_file` resolve against that directory and reject anything that leaves it.

`run_shell` uses bubblewrap when `bwrap` is on `PATH`. Otherwise it re-execs under `unshare` into a user, mount, and network namespace, chroots, and bind-mounts the workspace at `/work`. Inside the jail the working directory is `/work`, not the host path. The host filesystem outside the workspace is not visible, and there is no network unless the bot has a grant. PATH also includes toolchain directories already on the read-only system mount, including `/usr/local/go/bin` and `/usr/local/bin` when they exist. Home directories and `/snap` are not added. If neither jail can be built, the tool fails closed. With the `build` grant, each `SANDBOX_BUILD_BINDS` entry is opened without following symlinks. Bubblewrap mounts that descriptor with `--ro-bind-fd` and does not fall back to a path bind. The unshare fallback refuses the bind with a daemon-generated `sandbox_block` (detail `refused bind <path>: unsupported without bwrap`) and does not mount the path.

Writes to `.git/hooks`, shell rc names, and executable git settings are blocked.

A bot that reports its workspace as `/work` is reporting the jail. Giving a bot material means mounting or copying it into `workspace/`. It does not mean relaxing the jail.

Named grants (`net`, `git`, `ssh`, `build`) live on the bot. The profile and the bot API set and clear them, along with `net_allow` and `ssh_allow`. The meta tools do not set grants. They do set `server_tools`: `create_bot` inherits when the field is omitted or `null`, and `update_bot` leaves it unchanged when the field is omitted. `null` on update inherits again. `[]` allows none. A missing grant fails closed and is logged. `git push` returns the diff and does not push. The browser grant in `docs/sandbox.md` is not implemented.

## 5. Log schema

Append-only. `kind` is a closed set:

`user_message`, `bot_message`, `dm_sent`, `dm_received`, `tool_start`, `tool_end`, `bot_created`, `bot_updated`, `bot_deleted`, `timer_fired`, `timer_missed`, `model_call`, `run_input`, `run_started`, `run_finished`, `run_timed_out`, `daemon_start`, `daemon_stop`, `grant_use`, `grant_denied`, `net_request`, `sandbox_block`, `jail_report`, `jail_report_truncated`, `cli_override` (CLI turns: workspace config files found, with `files`, `mode`, `action` ignore or refuse, and `blocked`; see `docs/cli-isolation.md`).

A line the jail writes to its event file is `jail_report` with `untrusted: true` and `reported` set to the kind the line claimed. It is not audited as `sandbox_block`, `grant_use`, or `grant_denied`, and it does not start an approval. `jail_report_truncated` is the daemon's own event when that file exceeds 64 KiB or 64 lines (`dropped N`), or when the events directory cannot be read (`events unavailable`). Repeated untrusted notices in one turn are posted once, with a count. A dropped-line count is reported once per turn, on the first notice, or as one summary when that turn has no notice. `sandbox_block` detail is printable ASCII of at most 256 bytes. A trusted `grant_denied` for `net` or `ssh`, and a trusted `net_request`, are also written to the audit log when it is enabled. A `net_request` whose detail is `not allowlisted` is audited as `grant_denied` with grant `net`. Those rows are deduped per turn by action, grant, and host, with a `count` when the same key repeats. At most 64 such rows are written per turn. One further row, `audit_suppressed`, carries the number that was not written. The bot log stays one row per event.

`detail` holds the useful bits and stays small:

- messages: `message_id`, and for DMs the other bot id
- tools: `name`, `arguments` (redacted), `ok`, `error`
- bot changes: `fields` changed, `by` (`user` or bot id)
- timers: `timer_id`, `scheduled_for`
- model: `model`, `ok`, `error`, `tokens` if cheap to capture. An Ollama call also records `attempt`, `retry`, and `first_output_ms`. A timeout also records `limit` and `limit_value`.
- runs: `run_id`, `status`, `error`. `run_timed_out` records `run_id`, `limit`, `limit_value`, `first_output_ms`, `retried`, and `partial_bytes`.

The chat transcript stays readable. The log is allowed to be denser. If it is not in the log, it did not happen. `GET /api/log` is newest-first.

## 6. Persistence

SQLite, one file, WAL mode, on the desktop next to a workspace directory.

```
<data dir>/
  state.db          bots, messages, memory, timers, runs, log
  workspace/        files bots may read and write
```

`DATA_DIR` must be a real directory owned by the daemon user, not a symlink, and not group or other writable. The daemon checks that at every start and refuses to start when the check fails. A missing directory is created with mode 0700.

### Startup changes

Upgrade: a `credential_home` anywhere in `DATA_DIR` other than `DATA_DIR/coi/<name>` (for example `DATA_DIR/homes/*` or `DATA_DIR/cli/*`) now stops startup. Move it to `DATA_DIR/coi/<name>` or outside `DATA_DIR`.

A `[[tools.cli]]` `credential_home` that contains a protected path, for example the `[github]` `token_file`, refuses startup. Move the token file outside that home. A home inside `DATA_DIR/workspace` (raw or resolved) refuses startup and names both paths. A home inside another tool's home does the same. Inside `DATA_DIR`, the only accepted home is `DATA_DIR/coi/<name>`, where `<name>` is one path component and is not `homes`. A path nested under that name is allowed. `DATA_DIR/cli`, `DATA_DIR/mirrors`, `DATA_DIR/github`, `DATA_DIR/config`, `DATA_DIR` itself, `DATA_DIR/coi`, and `DATA_DIR/coi/homes` are refused. The error says to use `DATA_DIR/coi/<name>` or a path outside `DATA_DIR`. Two distinct `DATA_DIR/coi/<id>` homes are allowed. A home outside `DATA_DIR`, such as a user home, is allowed when it does not overlap a protected path.

A `DATA_DIR` that is a symlink, is not owned by the daemon user, or is group or other writable refuses every start.

A `SANDBOX_BUILD_BINDS` entry that does not exist, or that overlaps a protected path, refuses startup. At startup the daemon records a baseline: the device and inode of each protected path and of each existing ancestor directory up to but not including `/`. That baseline stays for the life of the process. SIGHUP does not replace it. A successful `AUTH_TOKENS_FILE` reload adds paths that were not already recorded. A failed reload leaves the snapshot unchanged. Required paths must exist when they are recorded: `DATA_DIR`, the admin token file when the daemon has created it, `POLICY_PATH` when it is set and the policy loaded, `AUTH_TOKENS_FILE` when it is set, the `[github]` `token_file` when it is set, the sandbox SSH key when that file already exists, and each configured `[[tools.cli]]` `credential_home`. A missing required path, or a missing ancestor of it, trips the snapshot (`protected path missing: <path>`). Optional paths may be absent: `state.db`, `state.db-wal`, `state.db-shm`, the secret directories under `DATA_DIR`, and the audit log. A missing optional path records the nearest existing ancestor directory and does not trip. An unconfigured path is not listed. The first time a recorded directory is missing, is no longer a directory, or has a new device or inode, the trip sticks, one audit row `protect_snapshot_tripped` is written, and one log line is written. While tripped, every build bind is refused (`refused bind <path>: protected path changed (restart required)` or `protected path missing (restart required)`). Nothing clears the trip except a restart. Replacing a protected directory needs a restart. A regular file such as `state.db-wal`, or a token file replaced inside the same directory, does not trip. An empty snapshot refuses every build bind. At run time, a bind that cannot be opened without following symlinks, or that overlaps a protected path, or whose opened inode is in that snapshot, is skipped and logged. The turn continues without that bind. When the audit log is enabled, that row is also written there with action `sandbox_block`, the bot id when one is known, and the detail. The detail is the path only, never file contents, and it is printable ASCII of at most 256 bytes. Bubblewrap mounts the opened file descriptor and does not fall back to a path bind. The unshare fallback refuses every build bind with a daemon-generated `sandbox_block` and does not mount the path. `DATA_DIR` itself, raw and resolved, is on the per-turn protected list. An empty protected list refuses every build bind with a daemon-generated `sandbox_block`. A line read from the jail event file is not that row. The events log is read through a directory descriptor taken when the jail was prepared, so a symlink the bot puts at `/lgb/events` is not followed.

On boot the daemon:

1. Opens the database.
2. Marks any `running` run as `error` / `daemon_restart`.
3. For each enabled timer, if `next_fire_at` is in the past, writes a `timer_missed` log line and computes the next future fire. It does not run the missed prompt.
4. Starts accepting HTTP.

No catch-up of missed timers. No replay of in-flight model calls.

## 7. Web UI

The page is a client. Refreshing reloads from the daemon. Four surfaces. The conversation does not contain the editor.

**Roster.** Mark, name, label, status. Click to open the conversation. The create control sits below the list. Archived bots are not listed; an `Archived (n)` control switches the list to archived bots, and opening one shows an Unarchive action. The bot menu has Archive / Unarchive and no Delete. Opening a bot sets the URL to `/bots/{id}` (history entry; back/forward and reload restore the selection) and the title to `Name — Local Grok Bots`.

**Conversation.** The thread and the composer. Opening a bot loads the newest page and lands at the bottom; scrolling near the top loads the previous page above without moving what is on screen, until `has_more` is false. New output (tokens, tool lines, status, replies) scrolls the list only when the reader is within 80px of the bottom, including height changes from markdown and code rendering; scrolled away, the view stays put and a `New messages ↓` pill jumps back down. The composer is never disabled during a run. Enter sends; Shift+Enter inserts a newline, and the box grows with its content up to 40% of the viewport. Newlines in a message are kept when it is shown. While a run is in progress, a status animation sits inside the message list at the position of the next reply, after the latest message and any live output (in an empty thread it is the first item), driven by `status` events on the stream. It clears when the run ends. User and bot messages render markdown (headings, emphasis, inline code, fenced code blocks, GFM pipe tables, lists, quotes, links). A fenced block is a monospace block that keeps whitespace and indentation, scrolls sideways, and shows its info-string language as a label; there is no syntax highlighting. Each block has a Copy button (shown on hover, always shown on touch screens) that copies the block's raw code and says `Copied` briefly; it uses `navigator.clipboard` in a secure context and a hidden textarea with `execCommand("copy")` otherwise, since the LAN page is plain HTTP. A table needs a header row and an alignment row (`---`, `:--`, `--:`, `:-:`) with the same cell count; `\|` is a literal pipe. A header cell that is only an alignment token (a malformed model table) is shown empty, and a header row made only of such tokens is dropped in the page only; the thread, log, and API keep the original text. The renderer builds DOM nodes from text, so HTML in a message shows as text, and links keep only `http`, `https`, and `mailto`. A reply whose run called tools or had permission decisions carries a collapsed summary (`3 tool calls: read_file, run_shell · 1 permission (1 denied)`) that opens to show each call, interleaved in order with the text the model wrote before each round's calls and each permission decision as `✅ allowed Bash(git status) · ui` or `⛔ denied Bash(rm -rf build) · policy`; tool records live in the `run_tools` table and survive reload, and the reply text is unchanged. Every message is its own bubble; while a run streams, each model round's text starts a new bubble rather than appending to the previous one. Each user and bot message has a small Copy button (on hover; always shown on touch screens) that copies the message's stored raw text, with the same clipboard fallback. Inbound DMs appear as a system line in this thread. There is no description editor on this view.

**Bot menu.** Opened from the conversation header, not as a side panel. Items: View profile, Pin, Hide, Duplicate, Delete.

**Profile.** A separate view. Mark, name, label, description, model override, grants, network and SSH allowlists, server tools, and the routines list (add, pause, delete, next run). Server tools is either "Inherit from policy" or an explicit list. An explicit list with nothing checked allows none. Saving sends that choice. Duplicate copies `server_tools` and does not copy grants. This is the only place the description, the grants, and server tools are edited.

**Log.** Filterable by bot and by kind. The verification surface.

- Bot state panel (closed by default): timers with a live countdown and next fire time in America/Phoenix, memory notes, grants and allowlists, tool status and last tool notice, and the latest 5 runs, from `GET /api/bots/{id}/state`. Clear timer and delete memory ask for confirmation. It opens from a chip in the thread header (`⏱ active timers · 🧠 notes`, plus `⚠` when the description has warnings; dimmed when all are 0) or from "Bot state" in the ⋯ menu, as a right slide-over on desktop and a bottom sheet under 980px. Close, a backdrop tap, or Esc closes it.
## 8. Process

- Daemon starts on boot via a systemd user or system unit.
- Binds on the LAN (or localhost behind a reverse proxy already trusted). No public exposure required. Plain HTTP is fine.
- Default model is the local Ollama endpoint, overridable by `OLLAMA_MODEL` and per bot. If Ollama is down, runs fail with a clear log line and do not hang.
- Clean shutdown writes `daemon_stop`. Crash does not; the next start writes `daemon_start` and reconciles runs as above.
- `bwrap` or `unshare` must be usable for `run_shell` in Ollama mode. Missing, the tool fails; the daemon still serves.
- Policy loading: precedence is managed settings > `policy.toml` > built-in defaults. Fail-closed: if the policy file is missing or unparseable, the daemon defaults to the strictest mode (daemon jail ON, CLI backends OFF) and logs loudly. When a user-level setting conflicts with a managed policy, the daemon refuses to start or logs the conflict according to `conflict_policy`. `[cli].server_tools` names the non-function model tool types a net-granted bot may keep. The default is empty, so the loopback proxy strips every such type. Managed policy sets the ceiling. Local policy and a bot's `server_tools` field can only narrow it. Leaving the bot field out inherits policy. A bot without a net grant loses every non-function tool. The proxy applies that list to every non-empty body on the loopback credential proxy. A duplicate object key is refused. A non-JSON body is refused.

## 9. Policy

The declarative policy file (`policy.toml`) controls the backend and jail behavior. One `backend` knob (`ollama` | `claude` | `grok`) automatically sets jail mode: Ollama implies daemon jail ON; CLI backends imply daemon jail OFF because the CLI's own sandbox is the boundary. See `policy.toml.sample` for the annotated schema. Managed settings (server-managed or MDM) always override the local file. For `server_tools`, managed policy is the ceiling and local policy can only narrow it. An omitted policy list is empty. An explicit empty list narrows a managed ceiling to nothing. Leaving a bot's `server_tools` out means inherit that list.

## Out of these specs

Channels, computer-use, virtual displays, approval cards, multi-user accounts, per-bot microVMs, catch-up of missed timers, templates, documents, links, notifications, voice. The PRD's later list still applies.
