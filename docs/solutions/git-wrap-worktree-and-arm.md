# Git wrapper: physical worktree, arming, and config values

`core.worktree` is resolved with `cd -P` from the directory that holds the config file. The check refuses when that physical path is outside `/work`. `../inner` and a `.git` symlink or gitfile whose git directory stays inside still pass.

Removal forms (`--unset`, `--unset-all`, `--remove-section`, `config unset`, `config remove-section`) do not use `git -C` on the work tree. The git directory is found from the filesystem, then git runs with `--git-dir` and `--work-tree` set to that directory. A relative `core.worktree` that does not exist otherwise makes git exit with "cannot chdir" before the key can be removed. Other writes still go through `config_guard`.

The file protocol is armed only from the repository positional (`vet` / `accept_local`). `scan_urls` and skipped option values use `check_local` and do not arm. For `git config`, that file scan runs after `config_guard`, so a refused key is named instead of reported as an outside path. `git submodule` exports `GIT_ALLOW_PROTOCOL=file` for that command only: the nested clone does not keep `protocol.file.allow=user`.

`branch.*.remote` and `branch.*.pushremote` are plain names. `submodule.*.url`, `help.autocorrect`, `commit.gpgsign`, and `pack.threads` share `config_value_allowed` in the scan and in `config_guard`. The scan probes with a single SOH byte; a restricted key then reads every `--null --get-all` value. A newline or tab in a value is refused. With no repository positional, `fetch`, `pull`, `ls-remote`, and `push` resolve the current branch remote (and `pushRemote` / `remote.pushDefault`) through `resolve_remote`. `fetch` and `pull` already walk every remote; `ls-remote` and `push` do not, so that resolve is what vets them.

A `git config` long option is refused unless its name is an exact known form. An abbreviation of `--type` or `--comment` is a write. A value that starts with `-` is still a value once the key is known. `git init` confines the target directory, `--separate-git-dir`, and `--template` with a physical path check.
