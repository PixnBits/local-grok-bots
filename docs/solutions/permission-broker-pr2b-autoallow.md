# Auto-allow choke and git attribute walk

Two constraints from the permission-broker backend. Both look like test
noise and both change who gets an allow.

## The choke has to see a real argv

`autoAllowOK` runs before every non-human allow: a saved rule, a task
grant, and a confirmed legacy allow. It is false off Linux and when
`inspected.Literal` is false. A human one-time token does not call it.

`ParseCommand` leaves `Eligible` false for a word that is not literal,
and `grantCovers` returns before the choke when the command is not
eligible. Setting `HardAsk` from `!Literal` does the same. The golden
then never reaches `autoAllowOK`, so deleting the literal check still
asks and the test stays green.

Surface argv is filled only when `ParseCommand.Reason` is `not a literal`.
The load-bearing command is `git diff $(name)`. `diff` allows one extra
positional, and `$(name)` does not resolve as a binary. `echo $(id)` is
not load-bearing: `echo` is not an allowlisted binary, so the rule never
matches. A literal compound such as `git log --oneline | head -5` must
stay allowed on Linux.

`grantCovers` must not reject `!Literal`. That return asks before
`autoAllowOK`, so deleting the literal check in the choke still asks
and `TestGolden_AutoAllowNeedsLiteral` stays green. Git risk and
critical on `grantCovers` are separate: the live goldens call
`grantCovers` with those fields set. A non-literal pending item can be
approved only once, so that golden plants the grant Decide used to
store and then evaluates again.

The classifier allow guard is separate. `ClassifierMayAllow(bot)` stays
true after a matching snapshot. Command checks live in
`classifierMayAllowCommandLocked`. Each row of the table test is false
for one condition and true for the others, so deleting that one check
makes that row return true. A guard that always returns false does not
fail when a check is removed. The workspace row's check is the whole
baseline `if`, not only `Workspace == ""`.

## A missing workspace is not a cap

`listGitAttributes` walks the worktree. Hitting the file or depth cap
is risky and asks. `WalkDir` on a path that does not exist is not that
cap. Tests use a cwd of `/work` that is not a directory. Treating that
error as a cap made `gitConfigRisk` return `cap`, every git command
became a hard ask, and once-tokens and task grants stopped matching.

If the workspace is empty, missing, or not a directory, the walk
returns no files and `capped == false`. A walk error under a real
directory still caps.
