# CISO findings to fix

Single-user desktop agent today. Ollama turns stay in the workspace jail. `grok` and `claude` turns do not. Each item below is its own commit, in this order. Do not push. Do not loosen the Ollama jail (fail-closed grants, no host passwd, no extra `/dev` nodes, `git push` held, the daemon SSH key is not a user agent).

## Issues

1. Critical. A CLI bot is the daemon user, with approval bypassed (`--always-approve`, Claude `bypassPermissions`, no Claude filesystem sandbox). The shipped unit has no `User=` and can run as root. Indirect prompt injection is shell and file access as that user.
2. High. Any bot can rewrite any other bot. `create_bot`, `update_bot`, `send_dm`, and `set_timer` have no per-bot auth. `write_memory` and `delete_memory` are already self-only. Reads stay reads. New bots inherit the caller's CLI backend.
3. High. The API defaults to unauthenticated on all interfaces. `BIND_ADDR` is `0.0.0.0:8080`. An empty `AUTH_TOKEN` disables auth. `/api/health` stays open when a token is set.
4. High. CLI tool events are published with empty arguments, and desktop notifications send model text.
5. Medium. The CLI child inherits the daemon environment (`XAI_API_KEY`, `ANTHROPIC_API_KEY`, `SSH_AUTH_SOCK`, cloud variables). Fixed with issue 1, because the jail clears the environment. No separate commit.
6. Medium. Every CLI bot shares `DATA_DIR/workspace`. A rules file written by one bot is the next bot's instruction.
7. Medium. Any timer due within two minutes suppresses the 30-minute idle kill. A bot can `set_timer` and stay resident.
8. Dev. `TestEntropyDevices` starts a privileged Docker container when AppArmor blocks unprivileged user namespaces.

## Decisions

- Issue 1 wraps the CLI with `bwrap`: workspace bind-mounted at its host path, only `~/.grok` and `~/.claude` (and `~/.claude.json` when present) under `/lgb-home`, `--clearenv`, fixed `PATH`, no SSH agent, no API keys in the environment. Fail closed when `bwrap` is missing. Do not `--unshare-net`. Do not `--disable-userns`. Login files remain the auth path; environment API keys stop working.
- The unit runs as system user `local-grok-bots`, home `/var/lib/local-grok-bots`, shell `nologin`, with `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome=true`, and `ReadWritePaths` for that home. The process refuses euid 0. No root override flag.
- Residual, stated in the README: model egress stays open. A nested `bwrap` from `grok --sandbox workspace` can fail when the kernel blocks nested user namespaces. This jail is the boundary the daemon enforces. Ollama file and shell tools stay on the existing workspace jail.
- Issue 2: a bot caller cannot execute `create_bot`, `update_bot`, `send_dm`, or `set_timer`. The HTTP API remains the user path. Hard deny, with the preamble updated. A confirm queue is a later product change.
- Issue 3: default bind `127.0.0.1:8080`. Refuse to start when the bind host is not loopback and `AUTH_TOKEN` is empty. Localhost-only use does not require a token. Update the unit and README.
- Issue 4: parse tool name and arguments, publish and store them redacted, and redact notification bodies.
- Issue 6: CLI cwd is `workspace/bots/<bot id>`, mode `0700`. Ollama file and shell tools keep the shared workspace.
- Issue 7: timers record a source. Only user-created timers (the HTTP API) suppress idle kill.
- Issue 8: privileged Docker re-exec only when `LGB_SANDBOX_DOCKER=1`. Otherwise skip the unshare subtest with a clear message when the kernel blocks user namespaces. Do not weaken `requireBin`. Do not delete the image.

## Tests

- Issue 1: a fake CLI in a temp workspace cannot read a sibling host file, and does not see `SSH_AUTH_SOCK` or an API key. Args include `--clearenv` and exclude `--unshare-net`. `refuseRoot(0)` errors. Existing `ExecRunner` stream and cancel tests still pass.
- Later issues name their checks in the commit that adds them.

## Out of scope

Browser grant, microVMs, MCP, git-push tokens, a network allowlist for the CLI, and rewriting `docs/sandbox.md`.
