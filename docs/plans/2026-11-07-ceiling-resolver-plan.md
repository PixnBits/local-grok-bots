# Ceiling path resolver (r5)

## Goal

One fail-closed resolver decides every ceiling path. Any error, or a sensitive match on either the spelled path or the resolved target, is not eligible for ceiling auto-approval.

Wrong if a second lexical or partial-symlink check can still allow a path the resolver would refuse, or if a critical ceiling can still auto-approve a sensitive match.

## Decisions

- Walk components from the real base (resolved cwd, else workspace root). A relative symlink target is applied to the parent already resolved. Do not `filepath.Clean` a symlink target before that walk.
- Cap 40 hops. A seen-set returns a loop error. A dangling link is an error. A missing final component that is not a symlink is a new file.
- Classes on both spelled and resolved: inside workspace, protected, critical list (writes), policy, git-sensitive (case-folded), client-config (case-folded). Any hit refuses, including at critical.
- Hook-path git operations stay on the sole-reason path only when the level is already critical and both sides are `.git/hooks`. Reads of protected paths still ask.
- Glob patterns that contain `..` or `{`, start with `~`, or are absolute are refused before the walk.
- Never auto-approve `git -C`, `--git-dir`, git whose cwd is not the workspace root, or a write of a gitdir signal (`HEAD`, `config`, `packed-refs`, `commondir`, `config.worktree`, `gitdir`, `attributes`, and components `.git`, `objects`, `refs`, `hooks`, `modules`).
- Delete `resolvePathWalk`, `readlinkAbs`, and the ceiling lookalike helper. `resolvePathTarget` is a wrapper over the new walk. Critical-ceiling behaviour stays documented only in `docs/permission-broker.md`.

## Out of scope

New ceiling levels, UI, prod, PR #40, push, rebase, amend.

## Tests

CISO MUST-6, MUST-7, SHOULD-7, SOFT-4. Tester MUST-4 and SHOULD-5..8. Hop cap, loop, dangling. Glob escapes. Shell and non-shell writes. Live git fsmonitor chain (skip if git is missing).
