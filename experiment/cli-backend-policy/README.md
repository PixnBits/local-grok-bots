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
- **Timer injection via a narrow channel**: append-only file or Unix
  socket that Claude's own tools read. One small door, no shell.

## Files

- `policy.toml.sample` (repo root) — annotated sample policy. Copy to
  `policy.toml` (or the managed path) and edit.

## Open questions

- Does the CLI's headless output format give clean parseable events
  (tokens, tool calls) or do we scrape text?
- What does InfoSec say about `bypassPermissions` for unattended
  timer-driven sessions?
- Session history lives in the CLI's store (`~/.claude/projects/`,
  `~/.grok/sessions/`) — how cleanly can the daemon project it into
  the web thread?
