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
- A live CLI is process-group killed after `idle_timeout_minutes` (default 30) unless a user-created timer is due within `imminent_timer_minutes` (default 2). Linux signals the `setpgid` group. macOS uses the same group signal and, if that is rejected, signals the leader only. The session id is kept.
- A restart mid-turn marks the run `interrupted` and keeps `session_id`. A graceful stop kills the process group first. A crash stores the pid; the next boot kills that group if it is still `claude` or `grok`. The next user message or timer passes `--resume`. An Ollama restart stays `daemon_restart`.
- `permission_mode` is passed through only when policy sets it. Empty means the CLI prompts when a TTY is available. A permission prompt with no TTY fails the turn with `permission prompt requires a TTY or an explicit permission_mode` and does not hang. It is not defaulted to always-allow.
- Binary pins, DLP prompt scan, CLI start/stop audit, turn timeout, the backend allow-list, and the Ollama model allow-list are enforced when the policy sets them. Unset, they stay off (allow-lists default to ollama, claude, and grok).

## Live smoke

The same command runs on the Framework Desktop (Linux) and on macOS, from the repo root. It sends one short prompt through the daemon, reads the CLI stream into the bot thread, and checks that `session_id` was stored. It does not wrap the CLI in the daemon jail.

It skips when `policy.toml` does not select `claude` or `grok`, and it skips when that binary is not on `PATH`. `LGB_LIVE_CLI=1` keeps an ordinary `go test ./...` from calling a live CLI.

```
LGB_LIVE_CLI=1 POLICY_PATH="$PWD/policy.toml" go test -count=1 -timeout 4m -run '^TestLiveCLISmoke$' ./internal/daemon
```

`POLICY_PATH` is optional. When it is unset, the test reads `policy.toml` from the package directory `go test` uses, which is not the repo root. Set it from the repo root as shown.

A headless machine has no controlling terminal. If `permission_mode` is empty and the CLI asks for approval, the turn fails with `permission prompt requires a TTY or an explicit permission_mode` instead of hanging. Set `permission_mode` in the policy when this smoke should run unattended.

Linux and macOS both kill a live CLI by process group (`setpgid`, then `SIGKILL` to the group). macOS falls back to the leader only if the group signal is rejected.

## Open questions

The stream format, history source of truth, timer injection channel, and
permission-mode default are locked in
`docs/plans/2026-10-13-cli-open-questions-locked.md`. InfoSec still has to
choose whether unattended timers may set an always-allow `permission_mode`.
The daemon does not assume that choice.
