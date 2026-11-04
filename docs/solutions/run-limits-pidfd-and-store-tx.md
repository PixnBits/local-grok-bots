# Run-limit ceilings and shell signals

`internal/policy` must not import `internal/sandbox`. The daemon calls `policy.UseShellSignal(sandbox.SafeSignalSupported)` before `policy.Load`. An unset probe allows shell timeouts above 30s so existing policy tests stay valid. When the probe is false, the effective shell ceiling is 30s and the source text is `the 30s limit on this system` only if the configured ceiling was higher.

`Store` uses one SQLite connection. `InsertBot` and `UpdateBot` write the bot row and the `bot_created`, `bot_updated`, and `bot_limits_changed` rows with `addLogTx` on that transaction. A query on `s.db` while the transaction is open deadlocks. The audit file is written only after commit.

`ShellGuard` signals with `pidfd_send_signal` only after a parent walk reaches the jail root and signal 0 succeeds on the root pidfd and the target pidfd. A failed open, a dead root, or a walk that misses the root sends nothing and calls `OnRefused`.
