# CLI session lifetime decisions

Carried forward from `experiment/cli-sessions-from-846d81` (runner notes M1/M3 and `internal/daemon/idle.go`) and made policy-driven.

## Model

The daemon stores a per-bot `session_id`. Each turn (user message, DM, or timer) is a short-lived headless CLI process:

```
claude|grok -p --resume <session_id> --output-format stream-json|streaming-json "[scheduled] prompt"
```

(or `--session-id` on the first turn). The daemon captures the stream for SSE and the final result for the stored reply. The CLI owns its transcript on disk. The daemon never keeps a long-running CLI process except for the duration of one turn.

## Idle kill (policy-driven)

A live CLI process is killed after `idle_timeout_minutes` of no user message and no turn start, unless a user-created timer is due within `imminent_timer_minutes`.

- Default: 30 minutes idle, 2 minutes imminent window.
- Only user-created timers keep the process alive. Bot-created timers do not.
- Kill is a process-group kill.
- `session_id` remains stored. The next user message, DM, or timer resumes with `--resume`.
- CLI turns are not under the Ollama round cap. They stop on daemon shutdown, cancel, or idle kill.

These values come from the `[cli]` section of `policy.toml` (or managed settings). Missing or unparseable policy falls back to the defaults and logs loudly (fail-closed for the overall backend choice remains unchanged).

## Timer injection

Daemon scheduler remains authoritative. On fire it resumes the session with the routine prompt prefixed `[scheduled]`. No extra filesystem channel is required; the resume invocation is the injection.

## History projection

Prefer capturing the live stream events into the daemon store for the web thread. On-disk JSONL is secondary and version-fragile for Claude; structured resume queries are safer for backfill.

## Policy fields

See `policy.toml.sample` `[cli]`:

- `idle_timeout_minutes` (default 30)
- `imminent_timer_minutes` (default 2)

Precedence: managed settings > policy.toml > built-in defaults.
