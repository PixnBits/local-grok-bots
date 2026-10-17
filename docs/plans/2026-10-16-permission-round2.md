# Permission round 2

## Goal

Auto-allow stays a low-risk read inside the workspace. A command is wrong to auto-allow if the shell can expand it, an option can execute or write, a path can leave the workspace, or a stored prefix can swallow a different command.

## Decisions

- Unquoted `{ } * ? [` in a Bash command refuse auto-allow. A file operand is accepted only after `--` when the tool supports it. Otherwise an operand that starts with `-` is refused.
- Each read-only command has an option allowlist. Unknown options refuse auto-allow. `rg` excludes preprocessor and archive flags. `file -C`, `tail -f`/`-F`, and `grep -f` are not allowed.
- The broker does not run git. It returns allow, and the CLI runs the original command. A safe git wrapper cannot be applied on that path. Auto-allow keeps only `git status` with `-s`, `--short`, `-b`, `--branch`, `--porcelain` (short `s`/`b` may cluster). `diff`, `log`, and `show` are not auto-allowed. `-C`, `--git-dir`, `--work-tree`, `--ext-diff`, `--textconv`, `--no-index`, and any `-c` are refused.
- `gh` is a network command. It is not auto-allowed and is not suggested as low-risk.
- Decision time resolves path arguments with `filepath.EvalSymlinks`. A result outside the workspace, or a missing parent, is refused. Sandbox read limits are the backstop for the check-then-run gap.
- Glob `pattern` and Grep `glob` and `path` are paths. Absolute paths, `..`, and `~` are refused.
- A Bash command with any byte outside `0x20`-`0x7E` is refused before splitting.
- A stored prefix rule does not match when the suffix contains `; | & ` $ ( ) < >` or a newline.

## Tests

Regression tests cover each case with generic names. `gofmt -l .` is empty. `go vet ./...`, `go test -race ./...`, `go test -race -tags lgbtest ./...`, and `GOOS=darwin GOARCH=arm64 go build ./...` pass.
