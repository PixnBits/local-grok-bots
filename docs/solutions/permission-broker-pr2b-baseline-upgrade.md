# Old git baselines upgrade only when homes match

A data directory written before the system git config piece and the
nested `.gitattributes` pieces reads as drift on the current engine.
Exact git allows then ask on every call.

## Detect the piece set, not a missing version

The file version stays 1. New writes add `format` 2. An old blob is the
one that starts with `v1\n` and has no `system-gitconfig ` line. A blob
that already has that line is current, even when `format` is missing.
An empty file is not an old baseline.

Recompute the old piece set from the current files. When those bytes
equal the stored blob, rewrite the record in the new format and audit
actor `upgrade`. When they differ, keep the old blob and ask. The
pending item carries `git_reason` from the piece that differs.

## Do not upgrade before homes are set

Seed order is workspace, then homes, then the snapshot. The old blob
names each home. If the upgrade runs while homes are still empty, the
recomputed digest drops those lines, the compare fails, and a matching
baseline is treated as drift. Skip the upgrade unless the home list in
the blob is the home list on the bot. A later turn must not record the
baseline again: once the snapshot is set, `SnapshotBot` returns.

A system git config that only the new format covers matches the old
digest and is upgraded. A nested `.gitattributes` added after the old
record does the same. A driver in that file still asks through the git
config scan.
