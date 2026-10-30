# Jail mounts

Review of what a bot can see from the shell jail and from a Claude or Grok
launch. Paths outside that bot's workspace are not a place the bot is
meant to read. Placeholder names only.

## Shell jail (Linux bubblewrap, and the unshare fallback)

`run_shell` binds that bot's directory (`<workspace>/bots/<id>`) at `/work`.
The shared workspace root is not the bind. The unshare fallback uses the
same directory. On macOS the seatbelt workspace is that directory too;
there is no `/work` mount.

| Path inside the jail | Mode | Why | Result |
| --- | --- | --- | --- |
| `/usr`, `/bin`, `/lib`, `/lib64` when present | ro | The shell and its libraries | Host files under those trees are visible read-only, including a hook that was installed there |
| `/etc` | empty dir, plus ro `/etc/ld.so.cache`, `/etc/ssl`, `/etc/services` when present | Loader and TLS | The host `/etc` is not mounted |
| `/tmp` | tmpfs | Scratch | Not the host `/tmp` |
| `/proc`, `/dev` | proc, dev | The process needs them | Host home and `DATA_DIR` are not mounted here |
| `/work` | rw | The bot directory | Other bots, `DATA_DIR/permbroker`, the rules file, the audit log, and the token file are not inside this bind |
| `/lgb` | rw prep dir | Proxy sockets, the real `git` at `/lgb/bin/git`, wrappers | A per-launch prep tree, not `DATA_DIR` |
| `/usr/bin/git` and `/usr/bin/ssh` | ro wrapper | Narrow git and ssh config | The real binaries stay at `/lgb/bin/…` |
| Environment | fixed | `HOME=/work`, pinned `PATH`, `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` at `/dev/null`, `GIT_CONFIG_NOSYSTEM=1` | The user home is not `HOME` |

The git wrapper sets several safe keys and a protocol list. It does not
cover every risky key on every invocation: a caller can still pass config,
and a git binary other than the wrapped `/usr/bin/git` is the real binary.
`run_shell` therefore uses the same git-config hard ask as Claude. The
ask reads that bot's repo, homes, and stored environment.

Daemon file tools (`read_file`, `write_file`, `edit_file`, `delete_file`)
resolve against the same bot directory `run_shell` binds at `/work`. A
path into another bot, the shared workspace root, `..`, or a symlink out
of that directory is refused.

A hook path that lives under the read-only `/usr`, `/bin`, or `/lib` bind
stays readable inside the jail. Hiding that one path would remove part of
the library tree. That is deferred. A hook under `DATA_DIR` is not mounted.
Claude's deny list names the hook path as well.

## Claude launch

Claude is not in the bubblewrap jail. The working directory is the bot
directory. Settings set `blockReadsOutsideWorkingDirectories`. The deny
list names the hook path, the per-launch copy directory, the settings file
and its directory, `DATA_DIR/permbroker`, the admin token file, and the
credential paths under the user home (`.ssh`, `.config/gh`,
`.claude/.credentials.json`, and the other credential names) unless a grant
removes `.ssh`. `--add-dir` is refused while the broker is armed. The
process `HOME` is the bot home when isolation is on.

## Grok launch

The working directory is the bot directory. The sandbox profile extends
`strict` (reads stay in the workspace and system paths; writes stay in the
workspace and temp) and kernel-denies protected paths that exist: the token
file, secret directories, and credential homes. `DATA_DIR/permbroker` is
outside the workspace. Grok lists a deny path only when the path exists,
because a missing deny path refuses the launch.

## Fixes in this pass

- `run_shell` binds the bot directory at `/work`.
- Native file tools use that same bot directory.
- A shell `git push` resolves the repo in that directory.
- `run_shell` git config uses the hard ask.
- The Claude deny list includes the per-launch hook copy directory.
- An empty isolation `PATH` is filled once and the startup warning names it.

## Deferred

- A hook installed inside the read-only system library bind is still visible to the shell jail.
