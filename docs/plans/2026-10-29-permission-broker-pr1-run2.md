# Permission broker PR 1 run 2

## Goal

A shell call is allowed only by an exact argv rule, a task grant that covers every part, or a one-time approval. Risk tables set levels. They do not allow.

## In this run

- Shell parse: literal simple commands, bash and POSIX parity, compounds of simple commands, pipe stages on a pure-filter allowlist, state-changing parts void the compound.
- Shipped versioned tables for git, gh, path classes, and non-Bash tool kinds. Policy may only raise. The table version is on every audit row.
- Pinned root-owned PATH, argv0 resolved to an allowlisted binary, no assignment prefix.
- Daemon-run git keeps the jail wrapper's forced config. Claude git asks when `.git/config` or `.gitattributes` differs from the startup snapshot. The broker does not rewrite the Claude command.
- Exact argv rules shared by Claude Bash and `run_shell`. Critical, compounds, and high or unclassified global rules are refused. A ruleset change cancels pending and is audited.
- Task grants use the user message id, end on the next user message, session end, or 4 hours, and are re-checked at request time.

## Out of this run

Approvals UI, pattern rules, classifier model calls, and installing managed settings.

## Tests

Golden bypass corpus must not allow. Positive controls: literal `git status` and `gh pr view` with an exact bot rule; a pipe compound only when every part is granted. Do not weaken run 1 golden tests. Broker stays default off.
