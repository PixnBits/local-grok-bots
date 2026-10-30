# Launch integrity and jail review

## Decisions

- The shell jail's git wrapper does not neutralise every risky git key on every invocation. `run_shell` uses the same `gitConfigRisk` hard ask as Claude Bash, against that bot's workspace, homes, and stored environment. A clean repo stays eligible.
- `run_shell` binds that bot's directory at `/work`, not the shared workspace root. Daemon file tools stay on the shared root. Git push resolution for a shell push uses the bot directory. `deniedPushNames` stays on the shared root.
- Policy publish does not re-pin a hook. No pin yet records one. A matching path and file keeps the pin. A different path or file keeps the old pin, audits `hook changed; re-pin required`, and later launches refuse until `POST /api/permbroker/hook/repin`.
- Each armed Claude launch runs a daemon-owned copy of the pinned hook under `DATA_DIR/permbroker/<bot>/launch/<run>/` (directory 0700, file 0500), hashed to the pin immediately. The copy directory is critical and on the Claude deny list. The original path stays on that list too.
- Every Evaluate and every CLI `tool_use` re-checks the pin and the copy. A mismatch denies the call, ends the run with `hook changed`, and refuses further launches until the admin repin.
- The Claude path returned by `ResolveLaunchPath` and accepted by the version check is `spec.Bin` and the exec path. An absolute argv0 is not looked up again.
- Launch argv refuses `--allowed-tools`, `--allowedTools`, `--allowed_tools`, and the `=` forms, plus the bypass flags already refused.
- If the socket deadline fires after a once-token was taken, the token is put back when the reply is a deadline deny. A result that is already ready is the reply.
- An empty isolation PATH is filled once from the process PATH, or from `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` when that is empty, and one startup warning names it.

## Out of scope

- File tools moving onto the per-bot directory.
- Hiding a hook that lives inside the read-only `/usr`, `/bin`, or `/lib` trees.
- A new daemon CLI flag. The repin procedure is the admin HTTP route.
- `web/` changes, pushes, and live daemons.

## Tests

- `TestGolden_RunShellRiskyGit`
- `TestGolden_JailMountsBwrap`, `TestGolden_JailMountsClaudeDeny`
- `TestGolden_HookRepinOnlyByAdmin`
- `TestGolden_HookSwappedMidTurnRefused` (stream and per-Evaluate)
- `TestGolden_LaunchUsesCheckedClaudePath`
- `TestGolden_BrokerLaunchRefusesAllowedToolsAliases`
- `TestGolden_LateDeadlineOnceToken`

Existing goldens stay strict. The reload subtest expects a refusal. The risky-git run_shell case expects the ask.
