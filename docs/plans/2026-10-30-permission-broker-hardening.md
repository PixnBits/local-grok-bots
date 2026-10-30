# Permission broker hardening

## Goal

Each bot's workspace and git baseline are its own. A path in another bot's tree is outside. A classifier cannot allow a call unless that context and baseline are active. Critical paths are resolved before the match. Approvals expire. A socket peer on Linux must be the pinned hook under the launched CLI. Profile rules are copied into the broker once.

## In this run

- Inside-workspace checks and the git baseline use `<workspace>/bots/<id>`. Risky git config (`core.hooksPath`, `core.fsmonitor`, `filter.*`, `include` / `includeIf`, `core.sshCommand`, `core.pager`, `core.editor`, `diff.external`, `credential.helper`) makes every git command a hard ask, for Claude and `run_shell`. Writes under `.git/info/`, `.gitmodules`, and `~/.config/git/` ask. `ClassifierMayAllow` is false without that bot's workspace and baseline.
- Argv tokens, flag values, and redirect targets are resolved (leading `cd`, symlinks, `~`, `$HOME`, globs) before the critical-path check. The Claude deny list remains a second layer.
- Once-tokens expire at `[cli.permission] approval_ttl` (default 15m, bounds 1m..24h). Task grants end with the task and also at the shorter of 4 hours and that TTL. Pending items do not expire. Once-token cwd is the cleaned path with symlinks resolved.
- On Linux the socket peer must be the pinned hook binary and a descendant of the CLI the daemon launched for that bot. A platform that cannot name the peer still denies.
- Startup copies profile permission rules into the broker file. Exact text becomes an exact rule, a fitting glob becomes a pattern, and anything else stays a legacy record. The source is not deleted. A second start adds nothing.

## Out of this run

No push, no UI, no classifier model call, no real Claude, and no daemon on a port. Command substitution is not executed.

## Tests

Do not weaken a `TestGolden_*` test. New goldens: `TestGolden_PerBotWorkspaceIsolation`, `TestGolden_RiskyGitConfigHardAsk`, `TestGolden_GitProtectedPaths`, `TestGolden_ClassifierAllowNeedsPerBotContext`, `TestGolden_CriticalPathForms`, `TestGolden_ApprovalTTL`, `TestGolden_SocketPeerMustBeHookUnderBotCLI`, `TestGolden_OnceTokenCwdCanonical`, `TestGolden_LegacyRuleMigration`. `TestGolden_TaskGrantExpires` sets a 24h TTL so the 4h cap stays visible.
