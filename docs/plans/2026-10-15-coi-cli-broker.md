# CLI credential broker (first slice)

The sandboxed bot calls a host CLI through the existing `.lgb` spool and per-run `lgbr_` token (`coi <name> ...` or `lgb coi <name> ...`). The daemon runs the real binary. Credentials stay in `credential_home`, outside the workspace.

## Decisions

- Config is `[[tools.cli]]` in policy, re-read on each call. No SQLite table and no UI in this slice.
- Managed entries may set `lock = true` or `tools.cli_ban`. `tools.cli_allow_local = false` drops local-only names. Local policy may add an unlocked name only when that is not forbidden, and may only narrow a managed entry (subset of args, subset of bots, lower limits). Path and credential home stay with the managed entry.
- Unset or zero timeout, max output, or hourly cap denies the call.
- Args are denied unless the subcommand or flag is listed. Config, auth, login, logout, whoami, token, env, debug, and print-config style args are blocked even if listed. Paths must stay in the workspace. Any arg that mentions the credential home is blocked.
- The child gets an allowlisted environment with `HOME` and the `XDG_*` homes set to the credential home. `LGB_TOKEN` and host secrets are not copied.
- Output is passed through `audit.RedactText`, then literal replacement of credential-home paths and secret values read from that directory.
- Each call that is about to run consumes one slot in a one-hour window, same shape as the bot turn cap. Over the cap denies. Earlier denials do not consume a slot.
- The inner CLI runs with stdin closed. A permission prompt is recorded on the permission broker when that does not wait, then the call is denied. An allow cannot be delivered to a generic CLI.
- A missing policy, unknown name, missing grant, missing binary, or unreadable credential home denies the call.

## Tests

Policy merge, arg blocking, env scrub, output redaction, audit and cap, token auth, and fail-closed paths use a fake CLI script.
