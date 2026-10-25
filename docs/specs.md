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
| PATCH | /api/bots/{id} | `{name?, label?, description?, mark?, model?, status?, pinned?, hidden?, archived?}` | bot. `archived: true` stamps `archived_at`, pauses the bot's enabled timers (marked `archive_paused`), and stops new runs; the thread, memory, timers, and queued messages are kept. `archived: false` clears it, re-enables only the timers archiving paused (next fire counted from now), and starts a run if messages are waiting. Bots carry `archived` and `archived_at` |
| DELETE | /api/bots/{id} | | 204. Hard delete; API only, the page offers Archive instead |
| GET | /bots/{id} | | the page (HTML), same as `/`; the client opens that bot. When a token is configured, an unauthenticated request is served with 401 like `/` |
| GET | /api/bots/{id}/thread | `?before=&limit=` (limit default 50, max 200; `before` is a message id) | the newest `limit` messages before `before` (or overall), oldest first, plus `has_more` (older messages remain): `{messages: [...], has_more, tools: {run_id: [{name, arguments, ok, result_or_error, created_at}]}}` oldest-first; `tools` lists, per reply run, that run's records in order: `kind: "text"` is what the model wrote in the same response as a tool call (in `result_or_error`, no name or arguments), stored before that round's calls; `kind: "call"` is a tool call (arguments redacted, result clipped to 4000 bytes); `kind: "permission"` is a CLI permission decision (`name` is the tool, `arguments` redacted, `ok` true when allowed, `result_or_error` is JSON `{decision, source, rule?, transport?}`). CLI turns store the same `text` and `call` records as Ollama turns: text streamed before a tool call, then the call with its result |
| POST | /api/bots/{id}/thread/messages | `{content}` | `{message, run_id}` immediately |
| GET | /api/bots/{id}/thread/stream | `?run_id=` | SSE |
| POST | /api/bots/{id}/runs/{run_id}/cancel | | `{status}` |
| POST | /api/bots/{id}/runs/{run_id}/continue | | `{run_id}` for another 8 rounds on that capped transcript. 409 if the bot is running. 404 if there is no offer. |
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

SSE events on the stream:

- `status` — `{state, text?}` while the run is alive. `state` is `working` or a short activity such as a tool name. This drives the animation at the bottom of the thread.
- `token` — `{text}`
- `tool_call` — `{name, arguments}`
- `tool_result` — `{name, ok, result_or_error}`
- `done` — `{run_id}`
- `error` — `{run_id, error}`

`POST .../messages` never blocks on the model. It persists the user message and returns. If a run starts, `run_id` is set. If the bot is already running, `run_id` may be null or may be the existing run; the message is still persisted and will be seen.

Optional gate: if `AUTH_TOKEN` is set, a CLI backend generated an admin token, or `AUTH_TOKENS_FILE` supplies at least one token, require `Authorization: Bearer <token>` or the `lgb_auth` cookie on every route except `GET /api/health`, `GET /login`, and the MCP permission routes. Per-run lgb tokens stay on their own routes. With no token from either source the API is open. Same routes either way. The HTML page is still served on an unauthenticated `GET /` so the client can collect a token; API calls then 401 until one is set.

`AUTH_TOKENS_FILE` is a path, read once at startup. Restart to pick up a change. Each line is `name:token`. Blank lines and lines whose first non-whitespace character is `#` are ignored. A name is 1–64 characters from `[A-Za-z0-9._-]`. The token is split on the first `:`, trimmed, at least 32 characters, and must not contain whitespace. `AUTH_TOKEN`, or the generated admin token, joins the set as `default`. A file entry named `default` is an error when that token is set. Duplicate names or duplicate tokens, including a copy of the default token, refuse startup. An empty file is valid.

The file is opened without following a symlink. It must be a regular file, owned by the daemon's effective user, mode `0600` or stricter (no group or other permission bits), and at most 64 KiB. The daemon refuses a file that fails those checks and does not change its mode. A file that cannot be opened or read, or any bad line, refuses startup. The error names the line number and does not include the token. `GET /login?token=` accepts any configured token, sets the cookie to that presented token, and writes an audit row `{"action":"auth_login","token_name":<name>}`. A failed login writes `{"action":"auth_login_failed"}` with no name and no token. A non-loopback bind warns at startup only when neither source has a token.

## 3. Turn and queue semantics

- `POST .../messages` always persists the user message, ordered, and returns.
- If the bot is `idle`, the post starts a run and returns its `run_id`.
- If the bot is `running`, the post returns the live `run_id` and the message is folded into that run: before each model call the run appends any turn input (user messages, scheduled prompts, inbound DMs) stored after what it has already read, records how far it has read in `runs.input_through`, and writes `run_input`. A message that lands after the run's last model call is not lost: the next run starts the moment the current one ends and consumes it. The page follows whichever run is active. Dropping the message or blocking the POST is not acceptable.
- A run ends in exactly one of `done`, `error`, `cancelled`.
- On daemon start, any run still marked `running` is marked `error` with reason `daemon_restart`. No resume of a half-finished Ollama model call. A CLI backend instead marks that run `interrupted`, keeps `session_id`, and the next user message or timer resumes with `--resume`.
- Cancel sets the run to `cancelled` and stops further tool calls. Partial output already persisted stays.
- Bot-to-bot DMs use the same queue on the receiving bot. The sender does not block waiting for a reply.
- Order is preserved. Nothing is dropped.
- A run that exceeds 8 model rounds ends `error` / `tool round limit`. The page can continue that transcript as a new run for another 8 rounds. A new message, another turn, or a restart drops the offer.
- While a run is `running`, the stream emits `status` events so the page can show the working animation. The animation clears on `done` or `error`.
- Text the model sends in the same response as a tool call is streamed as tokens for that run and kept in that run's in-memory transcript. It is not written to the thread. The stored reply is the response that has no tool call.
- A model response that fails because a tool call could not be parsed is diagnosed in that run's transcript and tried once more, when a round remains. The diagnosis is not written to the thread. A second parse failure ends the run as `error`. A parse failure on the last of the 8 rounds is that error and does not become `tool round limit`. Unreachable Ollama, an HTTP error, a stream failure, and a timeout are not retried.

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

`run_shell` uses bubblewrap when `bwrap` is on `PATH`. Otherwise it re-execs under `unshare` into a user, mount, and network namespace, chroots, and bind-mounts the workspace at `/work`. Inside the jail the working directory is `/work`, not the host path. The host filesystem outside the workspace is not visible, and there is no network unless the bot has a grant. PATH also includes toolchain directories already on the read-only system mount, including `/usr/local/go/bin` and `/usr/local/bin` when they exist. Home directories and `/snap` are not added. If neither jail can be built, the tool fails closed.

Writes to `.git/hooks`, shell rc names, and executable git settings are blocked.

A bot that reports its workspace as `/work` is reporting the jail. Giving a bot material means mounting or copying it into `workspace/`. It does not mean relaxing the jail.

Named grants (`net`, `git`, `ssh`, `build`) live on the bot. The profile and the bot API set and clear them, along with `net_allow` and `ssh_allow`. The meta tools do not set grants. They do set `server_tools`: `create_bot` inherits when the field is omitted or `null`, and `update_bot` leaves it unchanged when the field is omitted. `null` on update inherits again. `[]` allows none. A missing grant fails closed and is logged. `git push` returns the diff and does not push. The browser grant in `docs/sandbox.md` is not implemented.

## 5. Log schema

Append-only. `kind` is a closed set:

`user_message`, `bot_message`, `dm_sent`, `dm_received`, `tool_start`, `tool_end`, `bot_created`, `bot_updated`, `bot_deleted`, `timer_fired`, `timer_missed`, `model_call`, `run_input`, `run_started`, `run_finished`, `daemon_start`, `daemon_stop`, `grant_use`, `grant_denied`, `net_request`, `sandbox_block`, `cli_override` (CLI turns: workspace config files found, with `files`, `mode`, `action` ignore or refuse, and `blocked`; see `docs/cli-isolation.md`).

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
