# Per-bot auto-approval ceiling

The ceiling compares the level after `inspectSnap` and `raiseToCurrent`.
That is the shipped table, the policy raise, the classifier, and the
critical path. `inspected.Shipped` is the builtin level only. Using it
for the compare lets a raise or a critical path through.

`hot.go` does not copy `broker` or `broker_bots`. `WithHot` keeps the
startup policy and overlays voice settings and `claude_transport`.
The ceiling is the same kind of field. Do not add it to `hotView`.

A critical request is auto-approved only when the ceiling is exactly
`critical`. Deny rules run first. Unclassified commands, parse errors,
and a broker other than `hook` do not auto-approve. A ceiling whose bot
is missing from `broker_bots` is a load error. An empty `broker_bots`
list does not mean every bot for this key.
