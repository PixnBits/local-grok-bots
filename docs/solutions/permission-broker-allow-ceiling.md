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
a load error. The local policy path and the managed policy path are
critical, and a ceiling match also refuses a call that names either
file when the ceiling is critical.

A critical request is auto-approved only when the ceiling is exactly
`critical`. Deny rules and ask rules run first. A hard ask or an
ineligible request whose final level is not critical does not
auto-approve. A critical level can still match an exact critical
ceiling. A compound part with no known level, a git-risk, and baseline
drift do not auto-approve at any ceiling. Unclassified commands, parse
errors, and a broker other than `hook` do not auto-approve. A ceiling
auto-approval whose audit row cannot be written is a deny. The ceiling
does not use the Linux-only allow choke. A ceiling whose bot is missing
from `broker_bots` is a load error. An empty `broker_bots` list does
not mean every bot for this key. Level names are lowercase only.
