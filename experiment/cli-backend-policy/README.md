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

## Files

- `policy.toml.sample` (repo root) — annotated sample policy. Copy to
  `policy.toml` (or the managed path) and edit.
- `docs/plans/2026-10-13-cli-session-lifetime.md` — idle/resume decisions
  carried forward and made policy-configurable.

## Open questions

- Does the CLI's headless output format give clean parseable events
  (tokens, tool calls) or do we scrape text? (stream-json / streaming-json
  is the documented path.)
- What does InfoSec say about `bypassPermissions` for unattended
  timer-driven sessions?
- Session history lives in the CLI's store (`~/.claude/projects/`,
  `~/.grok/sessions/`) — live stream capture is preferred for the web
  thread; direct JSONL parsing is version-fragile for Claude.
