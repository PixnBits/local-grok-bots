# Policy limits, timeout, and read-only workspace

Four optional Policy controls. Every zero, false, or empty value keeps the current jail, the current timeouts, and the current writable workspace.

## Decisions

- `rlimit_nofile`, `rlimit_nproc`, and `rlimit_cpu_seconds` are non-negative integers. Zero does not change the process limit. The ceilings are 1048576, 1048576, and 100 days of CPU. The file keys match those names. The environment names are `POLICY_RLIMIT_NOFILE`, `POLICY_RLIMIT_NPROC`, and `POLICY_RLIMIT_CPU_SECONDS`.
- The generated bubblewrap argv gains `--rlimit NAME soft hard` with soft equal to hard. Bubblewrap 0.11.1 has no such flag, so Linux applies the same values with `setrlimit` in a short re-exec and then execs bubblewrap without the unknown flag. A missing `bwrap` does not fall through to unshare when a limit is set.
- macOS Seatbelt cannot express these limits. A non-zero value fails startup and fails the jail launch. It is not skipped.
- Memory cgroups are out of scope. There is no memory field.
- `turn_timeout` accepts a Go duration or a number of seconds. Empty or zero keeps the CLI turn uncapped apart from idle and shutdown, the shell command cap at 30s, and the Ollama run cap at 10m. A set value ends the CLI turn at that deadline as well (idle and shutdown still apply) and replaces the shell and Ollama caps. Expiry fails that turn and logs `turn_timeout` only when this field is set.
- `workspace_readonly` defaults to false. True mounts the workspace read-only in the CLI jail and the shell jail, on Linux and on macOS. CLI login directories stay writable. Daemon `write_file` is refused and logged. A shell write stays a kernel `Read-only file system` error and is logged when that text appears.
- `cli_ro_binds` already audits each path as `cli_ro_bind` with detail `<path> read-only`. `build_binds` gains the same per-path detail. The audit schema names both. Path contents are not logged.

## Out

Writable extra binds, memory cgroups, per-bot read-only grants, and changing the shell `build_binds` refusal rules.

## Lesson

`~/.grok/lessons/local-grok-bots/policy-rlimits.md` — bubblewrap 0.11.1 has no `--rlimit` flag, so the generated argv and the exec path differ.
