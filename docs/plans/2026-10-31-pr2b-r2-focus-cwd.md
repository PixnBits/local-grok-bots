# PR2b round-2 residuals

## Goal

Focus stays off `body` for narrow Escape, an emptied queue, and rules Undo. `run_shell` keeps a per-bot cwd across `cd`, inside the workspace, and later commands run there. A nested `.gitattributes` filter hard-ask shows a reason. Designer items 1–5 land as written.

Wrong if focus lands on a hidden Approvals button, the broker is told a cwd the shell did not use, a `cd` can leave the workspace, or the approved CSRF/JSON middleware is weakened.

## Decisions

- Close the queue by dropping `aria-modal` before focus, and focus a button whose ancestors are actually visible. Re-apply if the browser drops focus onto `body`.
- An emptied queue focuses `#approvals-empty-title` while the panel stays open, otherwise the visible Approvals button.
- Rules Undo keeps its focus key until the restored row's actions button exists.
- Session cwd updates only after a successful `cd`. Later commands are prefixed with `cd -- <rel> &&` after the broker gate. Escapes and out-of-workspace symlinks are refused.
- `git_reason` is filled from the git-risk code when drift did not already set one.

## Out of scope

Rule PATCH, /rules filters, task-grant Undo, legacy countdown, macOS peer ancestry, lazy system gitconfig, `cp *` never-match, unknown-baseline rewrite, unknown GET `/api` 200.
