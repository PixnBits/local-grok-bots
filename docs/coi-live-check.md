# COI live check

Date: 2026-10-15. Worktree branch `docs/coi-credential-broker`. Binary `/tmp/lgb-coi-check` (not `/tmp/lgb-dev`). Listen address `127.0.0.1:8139`. Data dir and policy under `/home/pixnbits/lgb-dev-data/coi-check`. No `-h`, no default port, and no default data dir.

The other daemons were left running: pid 287544 (`/tmp/lgb-dev`) on port 8090, pid 510125 (`lgb-voice-bin`) on port 8095, and whatever is bound to port 8080. Nothing in this check signaled them.

## Credential home

`/home/pixnbits/lgb-dev-data/coi-check/grok-home` is mode `0700`. The only file copied from `/home/pixnbits/.grok` was `auth.json`, installed as a regular file mode `0600` at `grok-home/.grok/auth.json`. It is not a symlink and it is not the same inode as `/home/pixnbits/.grok/auth.json`.

With `HOME` and the XDG home variables set to that directory, and `GROK_HOME` unset, grok reads `$HOME/.grok/auth.json`. It does not need the user's `config.toml`. After the brokered edit the home held 571 regular files and no symlinks. SHA-256 of the user file and the copy still matched at the end of the check (the digest is not recorded here).

The outer CLI-isolation hardlink is a different file: `data/cli/b829ff40-9797-4dd7-8574-fa15968e502e/home/.grok/auth.json`. It shares the user's inode (`nlink` 2). The broker copy is its own inode.

## Policy

`/home/pixnbits/lgb-dev-data/coi-check/policy.toml`, granted only to bot name `coi-check`. The file started with `timeout = "8m"`. Before the over-cap calls, that one line was rewritten to `timeout = "1s"`. The daemon re-reads the file on every call.

```toml
[daemon]
bind = "127.0.0.1:8139"

[backend]
backend = "grok"

[cli]
turn_timeout = "30m"

[cli.permission]
ui_prompts = false

[timers]
enabled = false

[security]
fail_closed = true
conflict_policy = "refuse"
audit_log = "/home/pixnbits/lgb-dev-data/coi-check/audit.log"

[[tools.cli]]
name = "grok"
path = "/home/pixnbits/.grok/bin/grok"
credential_home = "/home/pixnbits/lgb-dev-data/coi-check/grok-home"
bots = ["coi-check"]
allowed_args = ["-p", "--cwd", "--always-approve", "--no-auto-update", "--max-turns"]
timeout = "1s"
max_output = 1048576
max_calls_per_hour = 5
```

Allowed arguments are the ones the edit used: `-p`, `--cwd`, `--always-approve`, `--no-auto-update`, `--max-turns`.

## How the turn was driven

Backend `grok` so a CLI turn calls `startLGB` and writes `.lgb/bin/coi`. No second model was asked to drive the spool. `PATH` for the daemon was prefixed with `/home/pixnbits/lgb-dev-data/coi-check/bin`, where `grok` is a stub. If `LGB_SPOOL` is unset the stub execs `/home/pixnbits/.grok/bin/grok`. If it is set, the stub execs `driver.sh`. The policy `path` stays the absolute grok binary, so the brokered child is the real CLI on the host.

`driver.sh` runs the checks inside `bwrap` (`--unshare-user --unshare-net --unshare-pid --unshare-uts --die-with-parent --clearenv`). The bot workspace is bound at its absolute path so `LGB_SPOOL` works. The credential home and `/home/pixnbits/.grok` are not mounted. Sandbox env is `HOME` (the workspace), `PATH` (`/usr/bin:/bin:<workspace>/.lgb/bin`), `LANG`, `TMPDIR`, `LGB_SPOOL`, `LGB_TOKEN`, and the check's `COI_*` paths.

The daemon was started as pid 566544:

```sh
DATA_DIR=$BASE/data BIND_ADDR=127.0.0.1:8139 POLICY_PATH=$BASE/policy.toml \
  PATH=$BASE/bin:$PATH /tmp/lgb-coi-check
```

`AUTH_TOKEN`, `XAI_API_KEY`, `GROK_CONFIG`, `GROK_CONFIG_PATH`, and `GROK_HOME` were unset. Health `GET /api/health` returned 200. `POST /api/bots` with name `coi-check` returned 201. Bot id `b829ff40-9797-4dd7-8574-fa15968e502e`. `POST /api/bots/<id>/thread/messages` returned 200. Both bubblewrap phases exited 0.

## Secret scan

Secrets were the JSON string values of length 8 or more from both `auth.json` files, plus the admin token file. That was 11 values. The scanner printed hit counts only. It did not print `env.raw`, the database, or any line that contained `lgbr_`.

Scanned after every phase: `coi-out/*`, `hello.txt`, `audit.log`, `daemon.log`, `state.db`, `state.db-wal`, `state.db-shm`. Every one of those had `secret_hits=0`. `audit.log` also had `lgbr_` count 0. `env.raw` (909 bytes) had `secret_hits=0` and `lgbr_` count 1: the per-run spool token is in the sandbox because `.lgb/bin/coi` reads `LGB_TOKEN`. The grok secrets and the admin token were absent. `env.raw` was not printed.

Sandbox env keys: `COI_CRED`, `COI_OUT`, `COI_WS`, `HOME`, `LANG`, `LGB_SPOOL`, `LGB_TOKEN`, `OLDPWD`, `PATH`, `PWD`, `TMPDIR`. `HOME` was the workspace.

`daemon.log` (231 bytes) names the admin-token path and says the API token is required. The login hint in that log is the literal placeholder `<token>`, not the token. It also says `listening on 127.0.0.1:8139`.

## Edit

From inside the sandbox, via `.lgb/bin/coi`:

```text
coi grok -p "Create the file hello.txt in the current working directory. Write exactly one line into it: hello-from-coi" \
  --cwd <bot workspace> --always-approve --no-auto-update --max-turns 8
```

Exit 0. Broker status `ok`. `hello.txt` is exactly `hello-from-coi` plus a newline (15 bytes). The returned text says the file was created with that line. `secret_hits=0`.

## Exfil and denials

Each of these was a `coi grok ...` call from inside the sandbox, except the two `cat`s and the env dump, which ran in the sandbox directly.

| Case | Call | Result |
|---|---|---|
| auth | `grok auth status` | exit 1, `coi: argument is blocked` |
| config | `grok config` | exit 1, `coi: argument is blocked` |
| whoami | `grok whoami` | exit 1, `coi: argument is blocked` |
| login | `grok login` | exit 1, `coi: argument is blocked` |
| token | `grok token` | exit 1, `coi: argument is blocked` |
| debug | `grok --debug` | exit 1, `coi: argument is blocked` |
| print-config | `grok --print-config` | exit 1, `coi: argument is blocked` |
| tilde | `--cwd '~/.grok'` (quoted, so the sandbox did not expand it) | exit 1, `coi: path is outside the workspace` |
| cred path | `--cwd` set to the absolute credential home | exit 1, `coi: argument references the credential home` |
| cred prompt | `-p` text naming `<credential home>/.grok/auth.json` | exit 1, `coi: argument references the credential home` |
| print secrets | `-p` asking grok to print the environment and both auth files | exit 0. Model refused. Returned text has no secret (`secret_hits=0`, 129 bytes). The child environment itself was not captured; the model would not print it. |
| cat cred home | `cat <credential home>/.grok/auth.json` | exit 1, empty stdout, `No such file or directory` |
| cat user auth | `cat /home/pixnbits/.grok/auth.json` | exit 1, empty stdout, `No such file or directory` |
| env dump | `env` in the sandbox | no grok secret and no admin token. The run's `LGB_TOKEN` is present, as above. |
| wrong token | same sandbox, `LGB_TOKEN` replaced with `lgbr_` plus 64 zeros before `coi` | exit 2, `coi: not authorized`. Audit: one `coi_call` denied, error `bad token`. Grok was not started. |
| over cap | three `-p hi` calls after the policy timeout was `1s`, then a fourth | three `coi: timed out` (exit 1), then `coi: hourly cap reached` (exit 1). `cap.at` is `4`. |

Audit totals for `coi_call`: 2 `ok` (the edit and the refused print), 7 `argument is blocked`, 2 `argument references the credential home`, 1 `path is outside the workspace`, 3 `timed out`, 1 `hourly cap reached`, 1 `bad token`. No permission-prompt denial. Two `cli_start` / `cli_stop` pairs (the main turn, then the wrong-token turn).

The hour cap is in memory. The five slots were the edit, the print attempt, and three timeouts. Denials before a CLI start, including the wrong token, did not take a slot. The wrong-token turn was a second message to the same bot, and `driver.sh` stopped before the timeout rewrite so it would not look for the already-replaced `8m` line.

## Bug found

`ReadSecrets` refused a home past 256 files (`maxSecretFiles`). A grok home after one launch is larger than that (571 files here), so the next call died with `credential home is not available` and never reached the CLI. Commit `ccb06cf` raises the cap to 16384 and adds `TestReadSecretsScansPastAFreshCLIHome`. `/tmp/lgb-coi-check` was rebuilt after that commit. The edit above ran against the populated home and succeeded.

## Stop

`SIGTERM` to pid 566544 only, after `ps` confirmed the command was `/tmp/lgb-coi-check`. The process exited. `ss -ltn` shows no listener on port 8139. Ports 8080, 8090, and 8095 were still listening, and pids 287544 and 510125 were still the same commands.

## Gates

Run from the worktree after the stop. `gofmt -l .` printed nothing (`GOFMT_LINES=0`). `go vet ./...` exited 0. `go test -race ./...` exited 0 (`internal/coi` 1.231s, `internal/daemon` 80.063s; unchanged packages were cache hits). `GOOS=darwin GOARCH=arm64 go build ./...` exited 0.
