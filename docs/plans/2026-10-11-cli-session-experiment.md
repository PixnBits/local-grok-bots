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
- The Claude adapter is not wired yet.
- If a fresh start fails before the CLI reports a session id, the stored id is cleared so the next turn can create another session.

