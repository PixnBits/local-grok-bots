# CLI Session Experiment

**Status:** Proposal for experiment branch. Conceptual origin: the initial commit (a8f7a68) stub describing a personal local Grok Bot bootstrap. This pivots away from a custom Ollama HTTP client + bubblewrap/unshare sandbox toward using production CLI session engines.

## Goal

Treat each bot as a durable session in the Grok CLI (preferred) or Claude Code CLI. The CLI supplies the model loop, tools, and sandbox. The daemon remains the source of truth for the roster, timers, log, web UI, and message queue. Timers and idle handling use session resumption arguments so the CLI process does not need to stay alive forever.

## Recommended Architecture

- **Daemon (source of truth)**
  - Owns bots, threads, timers, log, web UI, message queue.
  - Stores per-bot `session_id` and private working directory.
  - Owns the clock: schedules timer fires and idle kill decisions.

- **Per-bot session**
  - One Grok CLI session ID (or Claude equivalent).
  - Private cwd: `data/workspace/<bot-id>/` (or git worktree).
  - Native CLI sandbox (`--sandbox workspace` or equivalent).

- **Turn flow**
  1. User message or timer fire arrives.
  2. If no live process, spawn:
     ```
     grok --resume <session_id> \
          -p "<prompt>" \
          --sandbox workspace \
          --cwd <bot-dir> \
          --output-format json \
          --always-approve \
          --no-auto-update
     ```
  3. Capture structured output, persist bot reply to SQLite thread, emit via SSE.
  4. After N minutes of idle (no user message, no imminent timer), kill the process. Session state remains on disk.

- **Timers**
  - Daemon scheduler is authoritative.
  - On fire: resume the session with the routine prompt.
  - Optional pre-wake a short time before fire so the process is warm.

- **Custom tools (DM, create/update bot, set_timer, memory)**
  - Preferred: small local MCP or HTTP endpoint that the CLI can call.
  - Alternative: daemon injects context or post-processes tool results.
  - Lean into CLI-native tools for file/shell/search where possible.

## Why Grok CLI

- Sessions persist on disk under `~/.grok/sessions/` and resume cleanly after process exit via `--resume` / `-c`.
- Headless mode (`-p --output-format json`) returns `sessionId` for chaining.
- First-class sandbox profiles (workspace, read-only, strict); profile is fixed for the life of the session.
- Theme alignment with "Grok Bot".
- `/loop` exists but is session-scoped; the daemon should still own durable scheduling.

Claude Code is a viable alternative (`claude -p --resume <id>`, similar persistence). Make the backend configurable.

## Open Questions

1. Idle timeout default (e.g. 15 min)?
2. Strict per-bot filesystem isolation (private dirs/worktrees) or shared workspace?
3. Auth on the always-on box: `XAI_API_KEY` in the daemon environment, or shared `grok login`?
4. How much of the custom tool surface (bot-to-bot DM, meta-bot, memory) must be preserved vs. leaning fully on CLI tools + thin coordination MCP?
5. Concurrent turns and resource limits (CPU/RAM on the Framework Desktop)?
6. Should long-lived processes be kept for high-activity bots, or always prefer spawn/resume?

## Recommendations

- High confidence for a docs-only experiment on this branch.
- Prefer Grok CLI headless + `--resume` + `--sandbox workspace`.
- Keep daemon as orchestrator and clock owner.
- Isolate bots with private cwds + CLI sandbox.
- Implement custom coordination tools via a small MCP server exposed to the CLI.
- Document deviations from the original Ollama + custom sandbox design in this plan and a short README note.

This is an experiment. Implementation can land incrementally once the open questions are answered.
