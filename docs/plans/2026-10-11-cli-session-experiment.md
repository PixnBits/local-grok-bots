# CLI Session Experiment

**Base:** Commit `846d81bdac7b8217f2d21642a037ab9494fcee43` — "Add the first running daemon slice."
That commit introduces the Go daemon with SQLite persistence (bots, threads, DMs, timers, log), local Ollama client (`internal/model/ollama.go`), workspace-scoped file/shell tools, basic namespace sandbox (`internal/sandbox/sandbox.go`), web UI, and the initial PRD/specs.

**Note on branch:** Tooling limited create_branch to from a branch name, so this branch was created from main and the plan is added on top. The experiment is defined against the 846d81 snapshot (replace the Ollama client + custom sandbox with CLI sessions).

## Goal

Treat each bot as a durable session in the Grok CLI or Claude Code CLI (configurable). The CLI supplies the model loop, tools, and sandbox. The daemon remains the source of truth for the roster, timers, log, web UI, and message queue. Timers and idle handling use session resumption so the CLI process does not need to stay alive forever.

## Decisions (from user)

- **CLIs:** Grok and Claude only. Configurable which backend per bot (or globally). Handle the nuances of each (flag differences, session store paths, sandbox profiles, output formats, permission models).
- **Idle timeout:** 30 minutes of no user message and no imminent timer → kill process. Resume on next event.
- **Filesystem:** Shared user filesystem for all bots. No per-bot private directories or worktrees. CLI sandbox still applies (prefer `--sandbox workspace` or equivalent; document how shared access is constrained).
- **Custom tools:** No MCP. Handle bot-to-bot DM, create/update bot, memory, and timer coordination without an MCP server. Options: daemon-side injection of context into the prompt, post-processing of CLI tool results, or thin shell wrappers the CLI can call that talk back to the daemon over a local socket/HTTP. Prefer the simplest that preserves the existing tool surface from the 846d81 slice.
- **Auth:** Handled entirely by the CLIs (`grok login` / `claude` auth). Daemon does not manage keys or sessions.
- **Concurrency:** No artificial limits. Daemon can spawn multiple CLI processes as needed.
- **Output / UX / reliability:** Support both batch JSON and streaming-json (or equivalent). Streaming for live user experience and SSE token updates; batch or structured events for reliable interrupt handling, recovery, and session continuity. Design the runner to tolerate process kill/restart mid-stream via session resumption.
- **OS notifications:** When a bot finishes a turn or is requesting user input, emit a native desktop notification on Linux and macOS.
  - Linux: `notify-send` (libnotify / D-Bus).
  - macOS: `osascript -e 'display notification "..." with title "..."'`.
  - Daemon detects platform and calls the appropriate command after capturing the CLI reply (or on a "needs input" signal if the CLI exposes one). Fail open if the notifier is missing.

## Recommended Architecture

- **Daemon (source of truth)**
  - Owns bots, threads, timers, log, web UI, message queue (as in the 846d81 slice).
  - Stores per-bot `session_id` and chosen CLI backend (grok | claude).
  - Owns the clock: schedules timer fires and the 30-minute idle kill.
  - Emits OS notifications on turn complete or input requested.

- **Per-bot session**
  - One CLI session ID (Grok or Claude).
  - Shared user filesystem / workspace. CLI sandbox profile still applied.
  - Native CLI sandbox (`--sandbox workspace` for Grok; Claude equivalent).

- **Turn flow**
  1. User message or timer fire arrives.
  2. If no live process, spawn headless (example for Grok):
     ```
     grok --resume <session_id> \
          -p "<prompt>" \
          --sandbox workspace \
          --cwd <shared-workspace> \
          --output-format streaming-json \
          --always-approve \
          --no-auto-update
     ```
     Claude equivalent with its flags. Capture both streaming events (for SSE) and final structured result.
  3. Persist bot reply to SQLite thread, emit via SSE.
  4. If the turn ends or requests input, send OS notification.
  5. After 30 minutes of idle, kill the process. Session state remains on disk.

- **Timers**
  - Daemon scheduler is authoritative.
  - On fire: resume the session with the routine prompt.
  - Optional short pre-wake before fire.

- **Custom tools (no MCP)**
  - Daemon injects relevant context (other bots, memory snippets) into the prompt or system rules.
  - Or: CLI tools that are thin wrappers (e.g. a `local-grok-bots-dm` binary) which the model can call; they hit a local daemon endpoint.
  - Lean on CLI-native file/shell/search tools. Existing daemon workspace tools can be retired or kept as fallback.

## Why both CLIs

- Configurable backend lets the experiment compare Grok vs Claude session behaviour, sandbox strength, and recovery characteristics on the same daemon.
- Both support durable sessions, `--resume` / `-c` / `-r`, headless `-p`, and structured output.
- Nuances (session path, sandbox flags, permission defaults, `/loop` quirks) are handled in the runner, not exposed to the user.

## Open items (narrowed)

- Exact mechanism for custom coordination tools without MCP (injection vs thin wrappers).
- How to detect "requesting user input" reliably from both CLIs (structured event, exit code, or prompt pattern).
- Streaming interruption recovery details (what is replayed on resume).

## Recommendations

- High confidence to proceed with the experiment on this branch.
- Configurable Grok | Claude backend; handle flag and store differences in the runner.
- 30-minute idle kill + resume.
- Shared user filesystem + CLI sandbox profile.
- No MCP; use prompt injection or thin local wrappers for meta tools.
- Auth left to the CLIs.
- Support both streaming-json (UX) and final structured capture (reliability).
- Add platform-native OS notifications on finish or input request.
- Document deviations from the Ollama + custom sandbox design here.

Implementation can land incrementally. The 846d81 daemon provides a solid base to swap the model client and sandbox for CLI sessions while keeping the rest of the shape.

## Runner notes (M0)

A Grok turn is one headless process. A new session is created with `--session-id` because `--resume` only continues a session that already exists. Later turns pass `--resume` and only the new user, DM, or scheduled text. The CLI keeps the transcript.

```
grok [-m MODEL] (--session-id ID | --resume ID) \
  -p PROMPT \
  --sandbox workspace \
  --cwd SHARED_WORKSPACE \
  --output-format streaming-json \
  --always-approve \
  --no-auto-update
```

- Session files live under `~/.grok/sessions/`, keyed by working directory. The daemon stores the id on `bots.session_id` and does not manage that directory.
- Auth stays in the CLI (`grok login`, or `XAI_API_KEY` in the environment the CLI already uses). The daemon does not read or store keys.
- `CLI_BACKEND` (`grok`, `claude`, or empty) is the default for a new bot. The bot column `cli_backend` is `grok`, `claude`, `ollama`, or empty. Empty and `ollama` keep the Ollama loop. Changing backend clears `session_id`.
- Shared cwd is `DATA_DIR/workspace`. No per-bot directory and no `--worktree`.
- Claude uses the flags in the M3 notes below.
- If a fresh start fails before the CLI reports a session id, the stored id is cleared so the next turn can create another session.

## Runner notes (M1)

- `streaming-json` text events are published as SSE `token` frames. Tool calls are published as `tool_call`. When the stream has no text deltas, the final reply is one token so the page still moves.
- The stored reply prefers the final structured `text` when the CLI sends one. Deltas are the live view only.
- A live CLI is killed after 30 minutes from the last user message or turn start, unless a timer fires within 2 minutes. The process group is killed. `session_id` stays. The next message or timer uses `--resume`.
- CLI turns are not under the 10-minute Ollama cap. Shutdown and cancel still stop them.
- A timer fire posts the routine prompt, prefixed `[scheduled]` as before, and resumes that bot's session.

## Runner notes (M2)

Custom tools stay off MCP. The fresh-session prompt tells the model to emit a fenced block:

```action
{"tool":"send_dm","to":"Bot Name","content":"hello"}
```

The daemon parses `action` and `bot-action` fences, runs the existing daemon tools (DM, create/update bot, memory, timers, list/read), strips the fence from the stored reply, and writes the usual log rows. File and shell actions are rejected so the CLI's own tools stay in charge of the workspace. A follow-up resume happens only when an action failed, a reply was empty, or the action was `list_bots` / `read_bot`.

A finished turn, a failed turn, or a result that asks for input sends a desktop notification. Linux uses `notify-send`. macOS uses `osascript` `display notification`. A missing notifier is ignored.

## Runner notes (M3)

Claude Code is the other backend. Same daemon path: one headless process per turn, session id stored on the bot, resume on the next event.

```
claude [--model MODEL] (--session-id UUID | --resume UUID) \
  -p PROMPT \
  --output-format stream-json \
  --verbose \
  --include-partial-messages \
  --permission-mode bypassPermissions
```

The process working directory is the shared workspace. Claude has no `--sandbox workspace` flag in this adapter. `--permission-mode bypassPermissions` is the stand-in for `--always-approve`. Older builds accept `--dangerously-skip-permissions` as the same switch; this adapter passes the permission-mode form. Auth stays in `claude` login files under `~/.claude`. The daemon does not read keys, and it does not pass `ANTHROPIC_API_KEY` into the CLI process.

Session transcripts are JSONL files under `~/.claude/projects/` (keyed by project directory). `--session-id` must be a UUID. The daemon generates one with the same UUID helper it uses for bot ids; it is not the bot id. `stream-json` text deltas (`stream_event` / `text_delta`) are SSE tokens. The stored reply prefers the final `result` string. Assistant tool-use blocks show up as tool lines. A `permission_denied` system event is a tool line, not a failure of the whole turn.

### Measured behaviour and deviations

- Default backend is still Ollama. Set `CLI_BACKEND=grok` or `claude`, or set `cli_backend` on the bot. Empty and `ollama` keep the HTTP client and the workspace jail.
- Changing `cli_backend` clears `session_id`. The next turn starts a new CLI session and sends the preamble again.
- Fresh Grok sessions use `--session-id`, not `--resume`. `--resume` is only for an id the CLI has already created.
- CLI turns are not under the 10-minute Ollama cap. They stop on shutdown, cancel, or 30 minutes after the last user message or turn start. A timer due within 2 minutes keeps a live process.
- The idle kill is a process-group kill. The session files stay. The next user message, DM, or timer resumes.
- Timers are still daemon-owned. The fired prompt is prefixed `[scheduled]`.
- Meta tools are fenced JSON in the reply, not MCP and not shell wrappers. The stored thread message has the fence removed. The live SSE stream can still show the fence for a moment, because tokens are forwarded as they arrive.
- A follow-up resume with the action results happens only when the action failed, the visible reply was empty, or the action was `list_bots` or `read_bot`. Otherwise one CLI process handles the turn.
- File, shell, and search stay on the CLI's own tools. Ollama file and shell tools still use the workspace jail. A CLI turn runs under bubblewrap: the workspace at its host path, `~/.grok` and `~/.claude` at `/lgb-home`, a cleared environment, and network left open. A nested `bwrap` from `grok --sandbox workspace` can fail when the kernel blocks nested user namespaces.
- All CLI bots share `DATA_DIR/workspace`. A `CLAUDE.md` or Grok rules file in that directory is visible to every bot. There is no per-bot worktree.
- Desktop notification is best-effort after the turn is stored. Linux: `notify-send`. macOS: `osascript`. Other platforms and a missing binary do nothing.
- No API keys are written by the daemon. Do not commit `~/.grok` or `~/.claude`.




