# Ceiling r8 plan

Fail closed. A bot with no ceiling keeps the human approval prompt for credential printing and hook changes. The shipped classifier table is unchanged for rules and grants.

1. Ceiling git auto-approval uses one allowlist table. A subcommand or flag shape that is not in that table asks. Work-tree content writers are rows in the same table and always ask: apply, am, checkout, switch, restore, merge, pull, rebase, cherry-pick, revert, reset, stash, mv, read-tree, worktree, clone, submodule, checkout-index, sparse-checkout.
2. Safe rows are status, log (no patch or line-dump flags), diff (name or stat format only, no --no-index), show (name or stat format, no rev:path), branch list, rev-parse, ls-files, remote list, tag list, describe, blame, and add/commit of class-checked paths. Commit is -m/--message only. No --amend, no -F, no --no-verify.
3. Shell mv, cp, install, ln, and rsync destinations use the created-directory class, including .vscode and .idea case variants. git mv destinations do too.
4. Hard deny is exact argv only: `gh auth token` and its flags, `git credential fill/approve/reject`, cat/head/tail/less/Read of the token-file list, `core.hooksPath` as a git config or -c key, and writes into `.git/hooks`. `cat .env.example`, a public `ca.pem`, `gh auth status`, `gh secret list`, and `git commit -m "core.hooksPath"` do not deny. Wrappers ask.
5. Git show rev:path, git cat-file, git grep with no pathspec or a sensitive path, and git diff or git log -p of a sensitive path ask.
6. `--flag=value` for path flags is split and checked like the space form.
7. On Linux, a write asks when the mount id from `/proc/self/mountinfo` differs, or when that file cannot be read. Darwin keeps the device id only.
