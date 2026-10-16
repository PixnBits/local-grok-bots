# COI CISO hardening

Guardrails for the credential-broker follow-up. Path checks stay; the OS sandbox is the boundary.

## Decisions

- Linux inner CLI runs under bubblewrap only (no unshare fallback). macOS uses sandbox-exec. Missing or failed sandbox denies the call and audits `coi_sandbox_unavailable`.
- Workspace is the only writable tree. System dirs and the resolved CLI file (not `~/.grok`, not `credential_home`) are read-only binds. Credential home is unmounted.
- `credential_files` copies listed relative files into a private 0700 HOME, wiped after the call. `GROK_HOME` is that HOME's `.grok`.
- Bot argv cannot pass `--always-approve` or `--sandbox`. Daemon prepends `fixed_args` / `fixed_env`. Grok also gets `--sandbox lgb`, compat `GROK_*_ENABLED=false`, `GROK_DISABLE_AUTOUPDATER=1`, and a daemon-written `sandbox.toml`. Approval, if needed, is daemon `fixed_args` (`--permission-mode acceptEdits`).
- Flags not in `value_flags` are boolean (no swallowing). Blocked-word checks apply to values and `--flag=value`. `update` is blocked as a whole token and as a subcommand.
- Hourly cap persists in SQLite. Store errors fail closed.
- Spool drain runs COI calls on a bounded worker set so other `lgb` calls proceed.
- PATH is system directories only. Redaction and path checks are backstops.

## Units

- U1 Arg parser + tests for `-p login`, `--cwd=update`, `--always-approve`, `--sandbox`
- U2 Policy fields and managed narrowing
- U3 Inner sandbox, credential copies, grok pins, PATH
- U4 Persistent cap
- U5 Concurrent COI drain
- U6 Docs + live check
