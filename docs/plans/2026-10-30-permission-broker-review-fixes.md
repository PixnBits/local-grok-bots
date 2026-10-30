# Permission broker review fixes

## Goal

When the broker is armed, a Claude turn runs only with the daemon's settings, a current CLI, and a hook binary that still matches the pin taken at policy load. A hook failure blocks the tool. A slow or changed answer denies.

## In this run

- Daemon settings keep one PreToolUse command hook (`matcher` `*`, timeout 30, `onFailure` `block`) and no allow list. The fake CLI blocks a non-blocking hook failure only when that entry says `onFailure` `block`. A read tool otherwise runs; Bash keeps the locked-launch fall-through.
- Claude older than 2.1.295, or a version that cannot be read, refuses the turn before the CLI starts. The check is the resolved binary's `--version`, cached by path, size, and mtime.
- At policy load the hook binary is pinned (content hash, device, inode, owner, mode, size, mtime). Each armed launch compares again. A difference refuses the turn and is audited. Policy reload pins the current file.
- The hook file must be owned by the daemon user or root. The file, every parent up to `/`, and the resolved path must not be group or world writable, must not follow a symlink onto a writable directory, and must not sit inside a jail-writable root.
- The hook binary, the daemon settings file and its directory, and `DATA_DIR/permbroker` are on the Claude deny list and are critical broker paths.
- Socket evaluate answers within 2 seconds; the deadline is a deny. Filesystem work and rule-use persistence stay off the engine lock. A once-token stays bound to the tool name. A risk reload drops pending items, once-tokens, and task grants. A critical command is not allowed by an older once-token.
- The launch argv must name this settings file, pass one empty `--setting-sources`, and must not add directories, plugins, or a foreign MCP config.
- A hook-denied tool result is a failed call. While the broker is armed, a residual denial is recorded as source `broker`. The hook command uses POSIX single quotes. The CLI preamble does not say `lgb` commands are approved without asking.

## Out of this run

Socket uid-only auth changes, exact-string cwd match, path text in errors, and per-bot git snapshots.

## Tests

Do not weaken a `TestGolden_*` test. `TestGolden_HookSIGKILLed` and `TestGolden_HookOverCLITimeout` use a Read so they fail if `onFailure` is removed. A Bash-only case still passes without that field. `TestLiveClaudeHookFailureBlocksRead` skips unless `LGB_LIVE_CLAUDE_BIN` is an absolute path. Hook fixtures cannot live under a group-writable directory such as `/tmp`.
