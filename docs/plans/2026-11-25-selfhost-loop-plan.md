# Self-host loop: wrap-up, local git, jail node, Ollama options

## Goal

A local bot can go from an issue brief to a committed fix on a local branch without a sidecar proxy.

## Out of scope

Job-card UI (#63), prompt rewrites (#45/#46/#47), new GitHub write features, production deploys, relaxing host `RepoConfigDenied` or the remote-operation checks from #57 and #62.

## Decisions

- Wrap-up is one user message injected once per run, before the model call on the reserved round. Budgets under 4 rounds do not reserve (a note would consume the budget). Budgets of 4–7 reserve the last round. Budgets of 8 or more reserve the last two. The run still ends with `error_code=tool_rounds` and the existing limit sentence. `runs.stop_reason` records `tool_rounds_exhausted`. Held messages stay so Continue resumes the same thread with a fresh round budget.
- Local-only git mode is on when the bot has no GitHub grant or the workspace has no remote. Only a fixed list of local subcommands may skip remote-transport keys (`remote.<name>.pushurl` and `remote.<name>.push`). Dangerous local keys stay refused for every subcommand. Push, fetch, pull, clone, ls-remote, remote update, and submodule update keep today's refusal path. Each skipped key is audited on the wrapper log. The host config denylist is unchanged.
- `[sandbox] node` is an absolute path to a regular executable outside the workspace. The jail bind-mounts the symlink-resolved file read-only at `/opt/lgb-node/bin/node` and puts that directory on `PATH`. An invalid configured path is a hard policy error. When unset, a read-only shim on `PATH` exits 127 with an actionable message.
- Ollama `/api/chat` sends top-level `think` and `options.num_ctx` only when set. `think: false` is sent as false. Precedence is policy per-model, then policy default, then bot, then CLI/env, then unset. `num_ctx` must be greater than 0 and at most 1048576. Policy values are authoritative when set.
- Bots without a `github` grant do not receive GitHub tool definitions. The standing prompt text is unchanged. `toolDefs()` stays complete for schema checks.

## Units

1. Wrap-up and stop reason (`internal/daemon/run.go`, `internal/store`).
2. Local-only git wrapper (`internal/sandbox/wrap.go`) plus pins.
3. Jail node (`internal/policy`, `internal/sandbox`, `internal/daemon` shell request) and an opt-in `go test ./web` jail run.
4. `think` / `num_ctx` through policy, store, API, CLI, and the chat body.
5. Filter GitHub tools when the grant is absent.
