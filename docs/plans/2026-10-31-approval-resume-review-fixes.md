# Approval resume review fixes

Head `13f1faa`. A wrong change would let a losing decision refuse a live checkpoint, put hook command text in `role=user`, leave a bot stuck on an unreadable checkpoint, or run a restored open checkpoint a second time. Do not change `protectMutatingAPI`, `confirmShellCwd`, or `shellExecRel`.

## Decisions

- The first HTTP decision on a pending id claims it under `ckMu` before `Decide` / `ApproveAll` / `DenyAll`. The loser is HTTP 409. It does not write the checkpoint and does not call `refuseOpen`. `ErrNotFound` only audits. `ErrStale` while holding the claim still refuses (ruleset change).
- Hook notes store a daemon-only marker plus `Notice:` framing. The command is one JSON-quoted line, truncated to 300 runes with `…`. `mapHist` keeps that marker as `role=system`. The `Your request ` promotion is removed. A user message with that prefix is an ordinary user message.
- An unreadable or missing checkpoint fails the waiting run, audits, and sets the bot idle. Stop calls `CancelWaiting` even when the file cannot be read. Startup does the same for waiting runs no open checkpoint covers. The next user message can start a run.
- `DATA/permbroker/tombstones.json` (dir 0700, file 0600, atomic) stores only pending id and time. Terminal transitions write it before the new checkpoint bytes. Startup refuses an open file whose id is tombstoned or whose run is not `waiting`, and audits that.
- `ResumeEval` still deletes the critical bind before the rest of the checks. `ApproveAll` on a native critical item stores a bind, not a once-token. `ApproveAll` on a hook critical item returns `ErrScope`.
- The shell-once slot stores the pending id. `execSavedCall` puts that id in ctx and clears the slot in a defer. `cancelCheckpoint` clears it too.
- Terminal checkpoints and `hook-sent` markers older than 7 days are removed at startup and about hourly. Tombstones stay.
- A canceled shell context is `shell interrupted`. A deadline is still `shell timed out`. The 30s timer is a deadline-shaped cancel; parent cancel (shutdown) is not.
- The header word is `waiting` while `last_run_status` is `waiting` or the approval wait is on.
- A new ask audits decision `ask`, actor `policy`. The hook verdict stays deny. `checkpoint.key` stays in `DATA/permbroker` and is documented as a same-uid limit. Asks exist only when `broker` is `hook`.

## Tests

Each name fails if its guard is removed.

- `TestConcurrentDecideOnePending` — approve/approve, approve/deny, approve/ApproveAll: one 200, loser 409, the call runs once or not at all, the run finishes.
- `TestHookNoteIsDataNotUserRole` — newlines and fake instructions stay one quoted system line; a user `Your request ` message is not the note.
- `TestUnreadableCheckpointUnwedges` — tamper, truncate, 0644, deleted; a later message starts a run; deleted is audited; restart does not stay waiting.
- `TestTombstoneRefusesRestoredCheckpoint` — open copy after consume, and an open file whose run is not waiting, refused after restart.
- `TestGolden_ResumeEvalBindIsOneShot` — second `ResumeEval` with the same id is not allow.
- `TestGolden_ApproveAllCriticalIsBindNotToken` — no once-token; bind allows one `ResumeEval`.
- `TestGolden_ApproveAllHookCriticalRejectsOnce` — `ErrScope`.
- `TestShellOnceClearedAfterFailAndCancel` — slot gone after a failed exec and after cancel.
- `TestApprovalRetentionSweep` — old terminal checkpoint and hook-sent file go away; an open checkpoint and the tombstone stay.
- `TestShellCancelIsInterrupted` — cancel is not `shell timed out`.
- Web `header-wait` — the pill word is `waiting`.
- `TestAskAuditsAskNotDeny` — the pre-suspend row is `ask`.
