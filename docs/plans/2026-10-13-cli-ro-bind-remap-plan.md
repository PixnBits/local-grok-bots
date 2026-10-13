# CLI read-only bind destinations

An operator can mount a host path at a different path inside the CLI jail. A plain path still mounts onto itself. An empty list still adds nothing. The shell `build_binds` list is unchanged and still mounts each path onto itself.

## Decisions

- The policy file stays a one-line list. It does not gain YAML objects, because a comma inside `{src, dst}` would split the item. A list item with no `:` and no `->` is `src == dst`. A single `:` is `src:dst`. `->` is the same pair. More than one separator is invalid.
- `POLICY_CLI_RO_BINDS` stays a colon-separated list, so `/opt/a:/opt/b` is still two same-path binds. A remap in the environment is `/opt/shared->/reference`. A colon in the environment is not a destination.
- `GET /api/policy` stores each entry as `{"src","dst"}`. A same-path entry has those fields equal. The default is `[]`.
- `src` must be absolute, must exist, and keeps the current refused, credential, login, and workspace checks, including the symlink target. `dst` must be absolute. It does not need to exist on the host. `filepath.Clean` is the stored form. A `dst` that is or lies inside `/usr`, `/bin`, `/lib`, `/lib64`, `/etc`, `/tmp`, `/proc`, `/dev`, `/lgb-home`, or `/lgb-proxy`, or that overlaps the workspace, fails startup. A same-path entry keeps today's exact reserved-root check, so `/usr/local` mounted onto itself still works.
- Linux emits `--ro-bind src dst` and `--dir` for parents of `dst`. The mount stays read-only. The workspace and the CLI login directories stay writable.
- macOS fails startup and jail launch when `dst` differs from `src`. Seatbelt cannot remap, and a read allow on the host path would not make the files appear at `dst`. The error names Seatbelt. A same-path entry stays a `file-read*` allow.
- The `cli_ro_bind` detail stays `<path> read-only` when the paths are equal. When they differ it is `<src> -> <dst> read-only`. The event names the paths and does not include the files inside them.

## Out

Writable binds, shell `build_binds` destinations, and a Seatbelt profile that pretends a path was remapped.

## Lesson

`~/.grok/lessons/local-grok-bots/cli-ro-binds.md` — a colon in `POLICY_CLI_RO_BINDS` still separates two same-path entries. The environment remap is `->`.
