# Per-bot auto-approval ceiling

The ceiling compares the level after `inspectSnap` and `raiseToCurrent`.
That is the shipped table, the policy raise, the classifier, and the
critical path. `inspected.Shipped` is the builtin level only. Using it
for the compare lets a raise or a critical path through.

The rank is strict: low 1, medium 2, high 3, critical 4. Unclassified,
empty, and unknown names have no rank. Critical matches only an exact
critical ceiling, and that check is separate from the rank compare.

`hot.go` does not copy the ceiling into `hotView`. `WithHot` keeps the
startup policy and overlays voice settings and `claude_transport`.
`RestartKeys` names `dangerouslyAllowAllPermissionRequestsUpThrough`
when the map differs. `broker` and `broker_bots` are still not restart
keys. Do not add the ceiling to `hotView`.

Only managed policy may set the key. A local file that contains it is
a load error. The spelling check and the local-file check use decoded
key names, so an escaped folded key is the same error and a string
value that merely contains the name is not. The local policy path and
the managed policy path are critical, and a ceiling match also refuses
a call that resolves to either file. Resolution follows the path and
its parent directories the same way a critical path does.

Evaluate order is deny, then a one-time human approval, then an ask
rule, then the ceiling. The one-time approval is consumed first, so the
next try asks again. Pattern and legacy ask rules are included.

A critical request is auto-approved only when the ceiling is exactly
`critical` and the critical level or a critical path is the only reason.
An unresolved program, a wrapper, a leading `cd`, a void command, a
protected-path read, a git form that runs a command, a non-shell path
outside the workspace, and any other ineligible reason still ask. The
git refusal is on the ceiling side. The classifier is unchanged. A
compound part with no known level, a git-risk, and baseline drift do
not auto-approve at any ceiling. Unclassified commands, parse errors,
and a broker other than `hook` do not auto-approve.

Non-shell auto-approval is a fixed table: in-workspace `Read`, `Glob`,
and `Grep` are low; in-workspace `Write`, `Edit`, `MultiEdit`, and
`NotebookEdit` are medium. Other tools, including `WebFetch`,
`WebSearch`, `Task`, and `mcp__*`, do not auto-approve. A write of a
critical path or a policy path does not auto-approve at any ceiling.

A ceiling auto-approval whose audit row cannot be written is a deny.
The in-memory mirror records the row only after the append succeeds,
and the write failure is logged. The ceiling does not use the Linux-only
allow choke. A ceiling whose bot is missing from `broker_bots` is a load
error. An empty `broker_bots` list does not mean every bot for this key.
Level names are lowercase only. `ceilingCovers` still refuses an empty
or unclassified level before the rank compare.
