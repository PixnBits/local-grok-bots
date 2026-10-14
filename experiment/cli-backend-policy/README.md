# experiment/cli-backend-policy

Sample policy file for the CLI-backend pivot of local-grok-bots.

## What this branch explores

The middle ground between `main` (Ollama + custom daemon jail) and
`experiment/cli-sessions-from-846d81` (CLI backend + outer daemon jail):

- **Daemon becomes a thin orchestrator**: roster, timers, DMs, log, web
  portal. It hands text to the CLI and reads text back. It never
  executes commands or touches the filesystem on the bot's behalf.
- **CLI's own sandbox is the boundary**: no nested jail around Claude
  Code or Grok CLI. InfoSec's existing managed settings (Seatbelt/
  bubblewrap, domain allowlists, credential deny/mask) are inherited
  for free.
- **One policy knob decides backend + jail mode**: `backend = ollama`
  implies daemon jail ON; `backend = claude|grok` implies daemon jail
  OFF. Jail behavior follows from the backend choice, so you can't
  accidentally run Claude inside a nested jail.
- **Fail-closed + strict precedence**: managed settings > this file >
  defaults. Missing or unparseable policy -> strictest mode, loud log.
- **Session lifetime is policy-driven**: 30-minute idle kill (configurable)
  with a 2-minute user-timer exception; process-group kill; resume on
  next event. See `docs/plans/2026-10-13-cli-session-lifetime.md`.
- **Enterprise controls that still apply**: binary pins, DLP prompt scan,
  audit log for CLI start/stop, turn timeout, and backend allow-list.
  See `docs/plans/2026-10-13-cli-enterprise-controls.md`.

## Files

- `policy.toml.sample` (repo root) — annotated sample policy. Copy to
  `policy.toml` (or the managed path) and edit.
- `docs/plans/2026-10-13-cli-session-lifetime.md` — idle/resume decisions
  carried forward and made policy-configurable.
- `docs/plans/2026-10-13-cli-enterprise-controls.md` — pins, DLP, audit,
  turn timeout, and allow-list carried forward.

## Implementation

The first vertical slice is on this branch:

- `internal/policy` loads `policy.toml` (TOML) and an optional managed JSON or TOML file. Precedence is managed settings, then the file, then built-in defaults. A missing or unparseable file fail-closes to daemon jail ON and CLI backends OFF, and the daemon logs that.
- `backend = ollama` keeps the existing model loop and workspace jail. `claude` or `grok` turns that jail off for the turn and spawns the CLI directly. There is no outer jail around the CLI.
- Each bot stores `session_id`. The first turn passes `--session-id`. Later turns, including timers, pass `--resume`. Timer text is the routine prompt prefixed with `[scheduled]`.
- The daemon parses `stream-json` / `streaming-json` into SSE tokens, tool events, and the stored reply. A stream with no final result is `error` / `interrupted`. The web thread is the daemon store. CLI transcript files are not read.
- A live CLI is process-group killed after `idle_timeout_minutes` (default 30) unless a user-created timer is due within `imminent_timer_minutes` (default 2). The session id is kept.
- `permission_mode` is passed through only when policy sets it. Empty means the CLI prompts. It is not defaulted to always-allow.
- Binary pins, DLP prompt scan, CLI start/stop audit, turn timeout, the backend allow-list, and the Ollama model allow-list are enforced when the policy sets them. Unset, they stay off (allow-lists default to ollama, claude, and grok).

## Open questions

The stream format, history source of truth, timer injection channel, and
permission-mode default are locked in
`docs/plans/2026-10-13-cli-open-questions-locked.md`. InfoSec still has to
choose whether unattended timers may set an always-allow `permission_mode`.
The daemon does not assume that choice.
