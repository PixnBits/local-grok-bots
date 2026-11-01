# Approval resume: first decision, unreadable files, replay

## The first decision claims the id before Decide

Two decisions on one pending id both used to reach the engine. The loser got `ErrStale` (a buried id lives in `e.dead`, so the second call is stale, not missing) and `refuseOpen` killed the run the winner was about to execute. `claimDecision` holds the id under `ckMu` until `afterBrokerDecision` returns. The claim is memory only: a durable "deciding" state would fail the MAC check as tamper. The loser is HTTP 409 and does not call `refuseOpen`. `ErrNotFound` on the winner only audits. `ErrStale` while that claim is still held (a ruleset change buried the item) still refuses. `TestClaimedDecideDoesNotTouchCheckpoint` fails if the claim gate is removed even when the race does not line up.

## The hook note is a marker, and the command is data

`mapHist` turns `Notice:` and `Message from` into `role=user` before any other system text. The approval note therefore starts with the U+2063 marker `hookNoteMarker`, which is stripped and kept as `role=system`. The command is one JSON string, at most 300 runes, inside `shown below as data:`. A person can type `Your request `; that message stays `role=user`. A command that contains `rm -rf /` is `LevelCritical` via `pathTouches`, so the hook-note fixture must not use a slash path.

## An unreadable checkpoint fails the waiting run

`eachOpen` skips a tampered, truncated, wrong-mode, or missing file, so cancel-by-walk does nothing and `kickLocked` then refuses every new run. `failUncoveredWaiting` runs after the startup walk and after a new user message. Startup audits a tampered file once in the walk and again from that helper, so those tests count `>= 1`. The decide golden stays at one tamper row because it never calls the helper. Stop uses `CancelWaiting` when the file cannot be read.

## Tombstone and "run not waiting" are different refusals

Startup refuses an open checkpoint when its id is in `DATA/permbroker/tombstones.json` or its run is not `waiting`. After a successful approve the run is already done, so deleting the tombstone check still refuses that restored copy. The replay test has to `markConsumed` while the run is still waiting, write the open bytes back, and restart. The stale test finishes the run with the file still open and no tombstone.

## A canceled shell is not a timeout

`ctx.Done` reports `shell interrupted` unless the context's own deadline fired. The 30s shell limit is a cancel timer, and `adjustShellStop` maps that timer back to `shell timed out` only when the parent context is still active. Parent cancel wins. Changing `captureReady` to always say `shell timed out` still passes the `adjustShellStop` unit test; `TestCancelReportsInterrupted` is the one that fails.

## A sweep no-op has to stay vet-clean

`go test` vets the package. A `return` that leaves the rest of `sweepApprovalFiles` unreachable fails the build before the assertion. A cutoff in the future deletes fresh files. A zero `cut` keeps every file, and `TestApprovalRetentionSweep` then fails because the consumed checkpoint is still there.
