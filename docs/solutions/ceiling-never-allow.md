# Ceiling never-allow and non-literal shell words

The hard deny for credential output and for hook-path changes runs only
when the broker is `hook` and the bot has a ceiling. It sits after a
deny rule and before a one-time approval, an ask rule, and the ceiling.
A bot with no ceiling still asks. The audit actor and source are
`ceiling_never_allow`. The severity word is `critical`.

The match is exact argv, not a substring. `gh auth token` denies.
`gh auth status`, `gh secret list`, and `git commit -m "core.hooksPath"`
do not. `git credential fill`, `approve`, and `reject` deny.
`git credential-store` asks. Readers are `cat`, `head`, `tail`, `less`,
and Read, and only for the token-file list in
[Critical ceiling](../permission-broker.md#critical-ceiling). `*.pem`
and `*.key` ask. `core.hooksPath` denies only as a `git config` or
`-c` / `--config` key. A value or a commit message with that text asks
or follows the git allowlist.

An unquoted backslash makes the shell word not literal. The check does
not unescape it. A quoted backslash stays in the word.

A set location, config, or command-helper git variable asks, including
an empty value and a shell assignment prefix. Identity variables such
as `GIT_AUTHOR_NAME` do not.

A created directory from `git clone`, `git init`, `git mv`, `mkdir`,
`install`, `cp`, `mv`, `ln`, or `rsync` uses the client-config class on
the spelled path and the resolved path. `.husky` and `.lgb` are in that
class. `.vscode` and `.idea` count when they are the created directory,
including `.VSCode` and `.IDEA`.

Ceiling git auto-approval is the allowlist `ceilingGitAllow`, not the
shipped classifier table. Content writers such as `apply`, `checkout`,
`merge`, `reset`, `stash`, `read-tree`, and `mv` ask at every ceiling.
On Linux a same-filesystem bind is a different mount id and asks. If
`/proc/self/mountinfo` cannot be read, the write asks. Darwin uses the
device id only.
