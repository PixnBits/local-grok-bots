# Background jobs detach from the tool context

A background shell uses the app context, not the tool context. Returning from `run_shell` must not cancel it. The shell-cap timer detaches into a job only when it fires at push depth 0 and the cap has not already fired during a push. A cap that fires while a push is in flight still trims; when the push ends, the rest of the command is killed rather than adopted.

A mid-job permbroker card is Sticky: it is not staged, and approve does not mint a once-token. The git-push permission card for that job sets Persist, so the prompt timeout is not armed. Foreground cards keep the timeout and the once-token.

The log is a regular file at `.lgb/jobs/<id>.log`. `read_file` needs no special case. Two jobs on one bot still share one shell plan and one GitHub read-socket slot. The last job overwrites the slot, and clear removes it only when the stored socket is still that job's.

Restart does not reattach. `New` marks rows still `running` as `job_lost` and writes the `[job]` wake in that transaction. Shutdown of a live job does the same: the row becomes `job_lost` and the wake is stored. That wake does not start a turn.

`ollama.jobs` defaults off and is host or managed policy only. A bot cannot turn it on. While it is off, `run_shell` matches the foreground tool: the shell cap kills the process, `background` is refused, `stop_job` is not registered, the prompt has no job sentence, and `.lgb/jobs` is not created.

A foreground shell keeps the 16 KiB in-memory capture. Only an adopted job appends to its log, and that file stops at 64 MiB. The daemon does not hold a 64 MiB buffer. A new `.lgb` or `jobs` directory is mode 0700. An existing directory is only narrowed. The `[job]` wake quotes the last 2 KiB as fenced tool output, with the duration when it is known.

A sticky approval is not a once-token. Scope task, bot, global, and approve-all leave no token behind, and the card stays pending across a later user message and a task change. It ends when it is decided, when the job stops or expires, or when the bot is paused, archived, deleted, or has a grant change.
