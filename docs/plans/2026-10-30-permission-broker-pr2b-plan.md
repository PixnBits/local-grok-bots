# Permission broker PR 2b (backend)

Goal: one auto-allow choke, a loopback raise-only classifier, approvals APIs, route-attached admin auth, and a jail that uses the declared unshare plan. Do not edit `web/index.html`. Do not commit.

Wrong if a saved rule, task grant, or confirmed legacy allow permits a non-literal command, a command off Linux, or a critical, compound, or git-risk command, or if a deny ends a run.

## Units

- Auto-allow: `autoAllowOK` before every non-human allow. Literal flag comes from a surface argv only when the parser already said "not a literal", so a matching rule or grant would allow if the literal check is removed.
- Classifier guard: command checks and the per-bot Linux/workspace/baseline/git-risk checks are separate conditions. Classifier output only raises a level or sets an advisory.
- Git: walk every `.gitattributes` in the worktree (skip `.git` contents, cap depth and count, cap means ask) and read the system git config path (package var, read-only).
- Local classifier under `[cli.permission.classifier]`, wired only when enabled.
- Approvals JSON under `/api/permbroker/`, admin-gated by the registered handler, not by decoding the URL path.
- Non-broker permission routes fail closed with no admin token.
- `enterJail` applies `unshareFallbackMounts`. A real unshare run checks `/proc` is absent.
- Remove the "Stopped after denial." notice mapping. Document the new behaviour in `docs/permission-broker.md`.

## Tests

Each auto-allow and git check has a golden that allows the command when that check is removed. Classifier guard is a table, one failing condition per row. Each new HTTP route has an auth, run-token, and happy-path daemon test.
