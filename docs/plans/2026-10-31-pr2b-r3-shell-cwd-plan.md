# PR2b r3 shell cwd and never-matches copy

## Goal

A stored per-bot shell directory that has been replaced by a symlink out of the workspace is refused. The broker, the audit row, and task-grant matching see the resolved directory. On Linux the jail starts in that directory with `bwrap --chdir` (and the unshare fallback chdir), not a `cd -- rel &&` prefix. A 4xx `never_matches` from the rule save routes is shown on the rule sheet.

Wrong if a lexical path is still trusted at exec time, the cwd is not reset after a failed re-check, Darwin stops building, the CSRF/JSON middleware changes, or "The daemon didn't respond" is used for an HTTP error.

## Decisions

- Re-resolve in `prepareShellCwd` before `Evaluate`, and again in `shellExecRel` immediately before `sandbox.Run`.
- On Linux, open the workspace directory and `openat2` the stored relative path with `RESOLVE_BENEATH`. `ENOSYS` falls back to `filepath.EvalSymlinks`. Other platforms use `EvalSymlinks` only. The result must be a directory inside `EvalSymlinks(workspace)`.
- Failure resets that bot's stored cwd to the workspace root and returns "working directory is no longer inside the workspace; reset to the workspace root". A stored cwd that is still the workspace root is not a failure when that directory does not exist yet (`gateShell` runs before `shellWorkspace` creates it).
- Pass the resolved path as the broker `Cwd`. The jail receives only the verified relative path.
- `POST /api/permbroker/rules` and the replace route: 4xx `code` `never_matches` uses the existing "This command cannot be allowed by a rule." copy and `aria-invalid` on `#rule-pattern`. The daemon-didn't-respond copy stays on fetch failure only.

## Tests

- Symlink swap through `run_shell`: `cd s1` succeeds, `s1` becomes a symlink to an outside directory, the next command is refused, cwd is the workspace root, and a following command runs there.
- Broker off, seeded cwd swapped: the exec-time check refuses. Reverting that call lets the command through.
- Missing leaf under an escaping symlinked parent: `resolveDir` reports not inside, and `ShellCwdAfter` rejects.
- Seeded outside `shellCwd` / `shellPlan`: `shellSessionDir` returns the workspace, and `commitShellPlan` does not store the outside path.
- Web: `never_matches` is inline; a thrown fetch keeps the network copy.

## Out of scope

Nested git config risk, CSRF, pattern validate returning `never_matches`, and any other review item.
