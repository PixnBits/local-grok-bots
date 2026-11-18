# Background jobs detach from the tool context

A background shell uses the app context, not the tool context. Returning from `run_shell` must not cancel it. The shell-cap timer detaches into a job only when it fires at push depth 0 and the cap has not already fired during a push. A cap that fires while a push is in flight still trims; when the push ends, the rest of the command is killed rather than adopted.

A mid-job permbroker card is Sticky: it is not staged, and approve does not mint a once-token. The git-push permission card for that job sets Persist, so the prompt timeout is not armed. Foreground cards keep the timeout and the once-token.

The log is a regular file at `.lgb/jobs/<id>.log`. `read_file` needs no special case. Two jobs on one bot still share one shell plan and one GitHub read-socket slot. The last job overwrites the slot, and clear removes it only when the stored socket is still that job's.

Restart does not reattach. `New` marks rows still `running` as `job_lost` and writes the `[job]` wake in that transaction. Shutdown does not rewrite a running row.
