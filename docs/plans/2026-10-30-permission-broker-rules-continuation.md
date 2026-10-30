# Permission broker rules, continuation, deploy

## Goal

A denied tool call does not end a run. Saved rules can be listed and revoked by an admin. Pattern rules match one token at a time and migration only narrows. Native file tools stay inside the bot directory. The hook can be built and installed from this tree.

## In this run

- A denial on every backend returns a result and the run finishes `done`. Only an explicit stop stores `cancelled`. Old rows may still display "Stopped after denial."
- `GET /api/permbroker/rules` and `DELETE /api/permbroker/rules/{id}` are admin routes. Revoke audits ids and hashes, bumps the ruleset, and applies on the next evaluation. The hook socket still only evaluates.
- A pattern is token-for-token. `*` is one whole token, never a flag, never a path separator, never first, and never last. A stored pattern that fails that check is legacy. A glob becomes a pattern only when every argv the pattern matches also matched the original glob. A legacy allow does not grow past that glob, and it does not cover a wrapper, a critical command, or a compound. Deny and ask legacy rows still use the glob.
- A task grant covers a compound only when every part is granted and none is a hard ask. Saved rules do not.
- `read_file`, `write_file`, `edit_file`, and `delete_file` use `<workspace>/bots/<id>`, the same directory `run_shell` binds.
- `deploy/build.sh` builds both binaries. The install steps live in `docs/permission-broker.md`. `ls`, `pwd`, and `echo` stay unclassified.

## Out

The approvals page, a rules-creation HTTP route, and installing the hook into a live system.

## Tests

New `TestGolden_*` cases cover deny continuation (Ollama, Grok, Claude), revoke, pattern syntax and migration, compound task grants, and the per-bot file root. Existing goldens stay as strict as they are.
