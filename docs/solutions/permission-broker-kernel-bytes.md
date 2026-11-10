# Ceiling path bytes and aliases

The ceiling walk must keep every link-target byte. `strings.TrimSpace`
on a target turns `foo ` into the decoy `foo`. Replacing `\` with `/`
turns `q\r` into `q/r`. Both decoys are ordinary files, so the ceiling
allows a write that the kernel lands on `.git/config`. Compare
`resolvePath` with `filepath.EvalSymlinks` for those names. A NUL is
`errPathUnrepresentable`, which is a different error from an empty path,
so deleting the check is not an equivalent survivor.

`Nlink>1` and `os.SameFile` are different kills. A hardlink to a file
outside the workspace has no sensitive path, so only the link count
asks. A bind mount of `.git/config` keeps `Nlink==1` and the same inode,
so only `SameFile` asks. Skip `SameFile` when the resolved path is the
sensitive file itself. That file is already classified, including a
critical read and `git add` of `.git/hooks/pre-commit`.

Inside a user namespace, host uid 0 directories show up as the overflow
uid. `rootOwnedDir` then rejects `/usr/bin`, `resolvePinned("git")`
fails, and `SaveRule` returns `ErrScope`. `NoteHookFile` returns
`hook owner` for the same reason. Skip those tests when `/usr/bin` and
`/bin` are not uid 0. Do not weaken the owner check.
