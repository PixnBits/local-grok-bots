# CLI read-only binds

`cli_ro_binds` adds read-only paths to the CLI jail. An empty or unset list leaves the current mounts unchanged. The shell `build_binds` path stays as it is.

## Decisions

- The policy file key is `cli_ro_binds`. `POLICY_CLI_RO_BINDS` is a colon-separated list. The file wins. An explicit empty list clears the environment value.
- A path must be absolute, must exist at startup, and must not be empty or duplicated. A missing path, a relative path, or a broken symlink fails startup. The check is not deferred to the first turn.
- The same `refusedBind` rules used by the shell apply: `.ssh`, shell rc names, `.netrc`, `.pgpass`, and git config. The path also fails when it overlaps `DATA_DIR/workspace` or the CLI login paths `~/.grok`, `~/.claude`, and `~/.claude.json`, including a parent that contains one of those. The resolved symlink target is checked the same way.
- Linux mounts each path with `--ro-bind` at the same path, after the fixed system mounts and immediately before the writable workspace mount, so the jail tmpfs does not hide it. Parent directories use the existing `--dir` helper.
- macOS Seatbelt cannot bind-mount. The same list is a `file-read*` subpath at the host path and is not added to the write list. A path Seatbelt cannot quote fails closed. The list is not skipped.
- Each applied path is a `grant_use` event, grant `cli_ro_bind`, detail `<path> read-only`. The audit sink records that when `audit_log` is set. `GET /api/policy` returns the paths.

## Out

Writable extra binds and shell-jail changes. A different CLI destination is decided in `docs/plans/2026-10-13-cli-ro-bind-remap-plan.md`.
