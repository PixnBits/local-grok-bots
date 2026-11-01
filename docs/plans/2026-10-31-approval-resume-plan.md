# Approval resume

A native run that hits a permission ask suspends to disk and continues only after a human decision, including after a daemon restart. The checkpoint is not authority. A wrong change would execute from a tampered file, skip `confirmShellCwd` / `shellExecRel`, accept a reusable once-token for a critical command, or lengthen the hook deadline.

## Decisions

- Same run id continues. Status `waiting` is not terminal. Resume sets that run back to `running`, appends the tool result, and calls the model again. A fresh 8-round budget starts on that same id.
- Checkpoints live in `DATA/permbroker/checkpoints/<pending-id>.json`, mode 0600, temp file plus rename. HMAC-SHA256 uses a 32-byte key at `DATA/permbroker/checkpoint.key` (0600). The MAC covers the pending id and the raw payload bytes. The filename, the payload id, and the restored item id must match.
- Payload: bot, run, task, session, tool name, args, call id (index in the assistant message), resolved cwd, message history through the assistant message that contains the call, state (`open`, `consumed`, `cancelled`, `refused`), and a pending snapshot so restart can restore the card.
- On ask, the model does not see `pending approval … retry`. The run status becomes `waiting`. The bot stays `running` until the wait ends so an in-flight deny still finishes the same turn. Restart reconciliation leaves `waiting` runs alone and sets the bot idle.
- Approve and approve-all re-evaluate through the broker after `confirmShellCwd`. The shell path still calls `shellExecRel` immediately before the jail. The saved command runs only when that re-eval allows. Consumed is written before exec. A second decision or a consumed checkpoint does not run it again.
- Critical native approve does not create a once-token. It records a one-shot bind keyed by the pending id. Only `ResumeEval` for that id can consume it, and a deny rule still wins. A later ordinary `Evaluate` does not accept it.
- Hook-originated critical items cannot be bound to a saved call. The card offers Deny and an explanation, not Approve once. `Decide` / `ApproveAll` reject scope once for those items.
- Deny and deny-all append `denied by user` and continue the same run.
- A new user message, stop, bot deletion, or task change marks the checkpoint `cancelled`. A later decision is recorded and does not execute.
- A hook decision with no native checkpoint posts one system note and starts or queues a run, only when the item's task is still the bot's current task. The sent flag is an exclusive file under `DATA/permbroker/hook-sent/`. The hook deadline stays 2.5s.
- Fail closed: bad MAC, invalid payload, missing checkpoint for a native item, policy or ruleset denial, or cwd re-check failure audits `resume_refused` and does not run. Audit decisions: `suspend`, `resume`, `cancel`, `cli_notify`, `resume_refused`.

## Out of scope

PR #28 follow-ups, async chat, lost tools, hook deadline changes, MCP, CSRF middleware, and weakening the shell cwd checks.

## Tests

Each name fails if its guard is removed.

- `TestGolden_AskSuspendsApproveResumesOnce` — no retry text; one shell execution; a second approve does not run it again.
- `TestGolden_ResumeApprovedExecutesOnce` — `resumeApproved` twice on the same snapshot, including concurrently, runs the saved call once and leaves the checkpoint consumed. A second HTTP approve never reaches `markConsumed`.
- `TestGolden_DenyResumesWithDeniedByUser` — continuation sees `denied by user`.
- `TestGolden_RestartThenApproveResumes` — new `App` on the same data directory, then approve runs the call.
- `TestGolden_PolicyChangeBeforeApproveRefuses` — ruleset change; `resumeApproved` writes `resume_refused`/`policy`, checkpoint `refused`, shell-once not armed, sandbox not entered. HTTP Decide's stale path is a later gate and is not this assertion.
- `TestGolden_StopCancelsWaitingRun` — POST cancel on a waiting run marks the checkpoint `cancelled`, stores the run as `cancelled`, and a later approve does not run.
- `TestGolden_DeleteBotCancelsCheckpoint` — bot deletion marks the checkpoint `cancelled` and a later approve does not run.
- `TestGolden_TamperedCheckpointRefuses` — bad MAC; audited; command not run.
- `TestGolden_NewUserMessageCancelsCheckpoint` — state `cancelled`; approve does not run the call.
- `TestGolden_HookDecisionPostsNoteOnce` — mismatched task posts nothing; a matching decision posts once.
- `TestGolden_CriticalApprovalIsBoundNotAToken` — the critical command runs once; a later `Evaluate` does not allow it.
- Web `hook-critical-no-once` — hook critical `approvalActions` has no Approve once; native critical still confirms.
