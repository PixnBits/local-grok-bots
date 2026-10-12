# CLI Session Experiment Plan (based on 846d81)

**Intended base commit:** `846d81bdac7b8217f2d21642a037ab9494fcee43`
**Commit message:** Add the first running daemon slice. One Go binary persists bots, threads, DMs, timers, and the log in SQLite, calls local Ollama, and serves the page. File and shell tools stay in the workspace. A systemd unit is included but not installed.

**Note:** This branch was created from main because the GitHub tooling does not accept a raw SHA as `from_branch`. The experiment is conceptually and intentionally based on the state at 846d81 (the first complete daemon slice with Ollama client, workspace-scoped tools, and basic sandbox). To work strictly from that commit locally:

```bash
git checkout 846d81bdac7b8217f2d21642a037ab9494fcee43
git checkout -b experiment/cli-sessions-from-846d81-local
# then apply or cherry-pick the docs commits
```

## Goal

Pivot the model client and sandbox from the Ollama HTTP API + custom namespace/bubblewrap sandbox (present in 846d81 at `internal/model/ollama.go` and `internal/sandbox/sandbox.go`) to treating each bot as a durable session in the Grok CLI (preferred) or Claude Code CLI. The CLI supplies the model loop, tools, and native sandbox. The daemon remains the source of truth for the roster, timers, log, web UI, and message queue. Timers and idle handling use session resumption so the CLI process need not stay alive forever.

## Recommended Architecture

- **Daemon (source of truth)** — unchanged from the 846d81 design for roster, timers, log, web UI, message queue.
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
  4. After N minutes of idle (no user message, no imminent timer), kill the process. Session state remains on disk under `~/.grok/sessions/`.

- **Timers**
  - Daemon scheduler remains authoritative (as designed in the PRD and implemented in the daemon).
  - On fire: resume the session with the routine prompt.
  - Optional pre-wake a short time before fire so the process is warm.

- **Custom tools (DM, create/update bot, set_timer, memory)**
  - Preferred: small local MCP or HTTP endpoint that the CLI can call (replacing or augmenting the existing tool surface in `internal/daemon/tools.go`).
  - Alternative: daemon injects context or post-processes tool results.
  - Lean into CLI-native tools for file/shell/search where possible; the existing workspace sandbox can be retired in favor of the CLI sandbox.

## Why Grok CLI

- Sessions persist on disk under `~/.grok/sessions/` and resume cleanly after process exit via `--resume` / `-c`.
- Headless mode (`-p --output-format json`) returns `sessionId` for chaining.
- First-class sandbox profiles (workspace, read-only, strict); profile is fixed for the life of the session.
- Theme alignment with "Grok Bot".
- `/loop` exists but is session-scoped; the daemon should still own durable scheduling (consistent with the original PRD).

Claude Code is a viable alternative (`claude -p --resume <id>`, similar persistence). Make the backend configurable.

## Open Questions

1. Idle timeout default (e.g. 5–15 min)?
2. Strict per-bot filesystem isolation (private dirs/worktrees) or shared workspace (as in the original design)?
3. Auth on the always-on box: `XAI_API_KEY` in the daemon environment, or shared `grok login`?
4. How much of the custom tool surface (bot-to-bot DM, meta-bot, memory) must be preserved vs. leaning fully on CLI tools + thin coordination MCP?
5. Concurrent turns and resource limits (CPU/RAM on the Framework Desktop)?
6. Should long-lived processes be kept for high-activity bots, or always prefer spawn/resume?

## Recommendations

- High confidence for a docs-only experiment on this branch.
- Prefer Grok CLI headless + `--resume` + `--sandbox workspace`.
- Keep daemon as orchestrator and clock owner (as already designed and implemented in the 846d81 slice).
- Isolate bots with private cwds + CLI sandbox.
- Implement custom coordination tools via a small MCP server exposed to the CLI.
- Document deviations from the original Ollama + custom sandbox design (present at this commit) in this plan.

This is an experiment. Implementation can land incrementally once the open questions are answered. The main branch continues with the evolving Ollama + custom sandbox implementation.
