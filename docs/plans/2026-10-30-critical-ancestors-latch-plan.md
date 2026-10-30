# Critical ancestors, hook latch, startup paths

## Decisions

- After `~`, `$HOME`, `$VAR` expansion, `cd` tracking, relative join, and symlink resolution, a path that is equal to, inside, or a strict ancestor of a critical path is critical (hard ask, not eligible). `/` is an ancestor of every absolute critical path. It is not added to the critical set.
- `.` and `./` mean the tracked working directory. `ls`, `dir`, `vdir`, `du`, and `find` with no path operand also mean that directory. Other commands do not.
- Bare `cd`, `cd` with only POSIX flags, and `cd ~` set the tracked directory to the home used for `~`. `cd -` does not.
- A non-literal word (command substitution, parameter expansion, arithmetic, unquoted glob, brace expansion, or a backslash escape; quotes are respected) is critical when the literal text before that construct, resolved like a path, is inside, equal to, or an ancestor of a critical path, or is a string prefix of one. An empty prefix is the working directory. A fully literal path is not matched by string prefix. Non-literal input stays non-eligible.
- The bot workspace `DATA_DIR/workspace/bots/<id>` is not an ancestor of a seeded critical path.
- Detecting a changed hook at turn start, mid-turn, or Evaluate sets the repin latch. Restoring the original bytes does not clear it. Only the admin repin route does.
- When the broker is `hook`, startup (and later policy publish) seeds `DATA_DIR/permbroker`, the admin-token file, `AUTH_TOKENS_FILE` when set, the hook binary, the hook copy directory, and `DATA_DIR/cli`, plus `BrokerCriticalPaths`. `run_shell` and Bash see that set with no Claude launch.
- `approval_ttl` outside 1m..24h inclusive fails the policy load closed (jail on, CLI backends off). It is not clamped at load. The engine still clamps a direct `SetApprovalTTL` to 24h.
- A corrupt `rules.json` error includes the file path. Revoke writes an audit row that names the action and the id.
- The unshare fallback has no pid namespace and no `/proc` mount. It bind-mounts `/bin`, `/lib`, `/usr`, `/lib64` when present (read-only), the workspace at `/work`, and `/dev/null` only, plus a tmpfs on `/tmp`. `/etc/ld.so.cache` is a copied file, not a mount of `/etc`.

## Tests

Each `TestGolden_*` for an existing fix must fail when that fix is reverted. Do not weaken an existing golden. Adjust one only when the new rule makes the old expectation wrong, and say so.

## Out of scope

No `web/` changes, no push, no network, no daemon on a port, no real Claude.
