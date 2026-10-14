# CLI runtime follow-ups

Guardrails for the work after the first vertical slice (`d2b4473`). The Ollama path, including `daemon_restart` for an in-flight Ollama run, stays as it is. The CLI is still not wrapped in the daemon jail.

## U1. Process-group kill

Linux sends `SIGKILL` to the process group created with `setpgid`. macOS uses that same POSIX group signal. If the group signal fails on macOS, the fallback is `SIGKILL` of the leader only. Seatbelt is not a kill API. A test spawns a shell and a child sleep. It does not require `claude` or `grok`.

## U2. Empty permission_mode without a TTY

Empty `permission_mode` still means the CLI may prompt. A prompt is a structured permission event (`session/request_permission`, `can_use_tool`, `permission_prompt`) or a permission-prompt line on stderr. If that happens and the process has no controlling terminal, the turn fails with `permission prompt requires a TTY or an explicit permission_mode` and the process group is killed. A text-only turn is left alone. An explicit mode is left alone. A controlling terminal may still answer the prompt.

## U3. Restart mid-CLI-turn

A graceful stop process-group kills the live CLI and marks that run `interrupted`. A later boot under a CLI policy marks any run still `running` as `interrupted`. `session_id` is not cleared. The next user message or timer passes `--resume`. Ollama boot reconciliation stays `daemon_restart`.

## U4. Live smoke

`LGB_LIVE_CLI=1` runs one short prompt through the daemon when policy selects `claude` or `grok` and that binary is on `PATH`. Otherwise the test skips. The exact command lives in `experiment/cli-backend-policy/README.md`.
