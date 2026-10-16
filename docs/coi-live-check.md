# COI live check

Date: 2026-10-15. Worktree branch `docs/coi-credential-broker`. Binary `/tmp/lgb-coi-check` (not `/tmp/lgb-dev`). Listen address `127.0.0.1:8139`. Data dir and policy under `/home/pixnbits/lgb-dev-data/coi-check/r2`. No `-h`, no default port, and no default data dir.

The other daemons were left running: pid 287544 (`/tmp/lgb-dev`) on port 8090, and listeners on 8080 and 8095. Nothing in this check signaled them.

## Credential home

`/home/pixnbits/lgb-dev-data/coi-check/r2/grok-home` is mode `0700`. The only file copied from `/home/pixnbits/.grok` was `auth.json`, installed as a regular file mode `0600` at `grok-home/.grok/auth.json`. It is not a symlink and it is not the same inode as `/home/pixnbits/.grok/auth.json`. SHA-256 of the user file and the copy still matched at the end of the check (the digest is not recorded here). Policy `credential_files = [".grok/auth.json"]` hands that file to the inner CLI as a short-lived copy in a private HOME. The credential home itself is not mounted.

## Policy

`/home/pixnbits/lgb-dev-data/coi-check/r2/policy.toml`, granted only to bot name `coi-check`. The file started with `timeout = "8m"`. For the sandbox-unavailable case, `sandbox_bin = "/no/such/coi-bwrap"` was inserted, then removed. Before the over-cap calls, `timeout` was rewritten to `1s`. The daemon re-reads the file on every call.

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
audit_log = "/home/pixnbits/lgb-dev-data/coi-check/r2/audit.log"

[[tools.cli]]
name = "grok"
path = "/home/pixnbits/.grok/bin/grok"
credential_home = "/home/pixnbits/lgb-dev-data/coi-check/r2/grok-home"
credential_files = [".grok/auth.json"]
bots = ["coi-check"]
allowed_args = ["-p", "--cwd", "--max-turns"]
value_flags = ["-p", "--cwd", "--max-turns"]
fixed_args = ["--always-approve"]
timeout = "8m"
max_output = 1048576
max_calls_per_hour = 10
```

Allowed arguments no longer include `--always-approve` or `--sandbox`. The daemon prepends `--always-approve` via `fixed_args` because `--permission-mode acceptEdits` returned text and did not write `hello.txt` in a probe. Nested Grok `--sandbox lgb` cannot start inside the daemon bwrap on this Ubuntu kernel (`apparmor_restrict_unprivileged_userns=1`); the daemon bwrap is the filesystem boundary. Compat env (`GROK_CLAUDE_*_ENABLED=false` and the Cursor/Codex equivalents), `GROK_DISABLE_AUTOUPDATER=1`, isolated `GROK_HOME`, and a daemon-written `sandbox.toml` are still applied. Redaction is a backstop.

## How the turn was driven

Backend `grok` so a CLI turn calls `startLGB` and writes `.lgb/bin/coi`. No second model was asked to drive the spool. `PATH` for the daemon was prefixed with `/home/pixnbits/lgb-dev-data/coi-check/r2/bin`, where `grok` is a stub. If `LGB_SPOOL` is unset the stub execs `/home/pixnbits/.grok/bin/grok`. If it is set, the stub execs `driver.sh`. The policy `path` stays the absolute grok binary, so the brokered child is the real CLI, wrapped in bwrap by the daemon.

`driver.sh` runs the checks inside `bwrap` (`--unshare-user --unshare-net --unshare-pid --unshare-uts --die-with-parent --clearenv`). The bot workspace is bound at its absolute path so `LGB_SPOOL` works. The credential home and `/home/pixnbits/.grok` are not mounted. Sandbox env is `HOME` (the workspace), `PATH` (`/usr/bin:/bin:<workspace>/.lgb/bin`), `LANG`, `TMPDIR`, `LGB_SPOOL`, `LGB_TOKEN`, and the check's `COI_*` paths.

The daemon was started as pid 585128:

```sh
DATA_DIR=$BASE/data BIND_ADDR=127.0.0.1:8139 POLICY_PATH=$BASE/policy.toml \
  PATH=$BASE/bin:$PATH /tmp/lgb-coi-check
```

`AUTH_TOKEN`, `XAI_API_KEY`, `GROK_CONFIG`, `GROK_CONFIG_PATH`, and `GROK_HOME` were unset. Health `GET /api/health` returned 200. `POST /api/bots` with name `coi-check` returned 201. Bot id `9dd464ca-db2e-4cbe-a8ed-7f440696f7b4`. `POST /api/bots/<id>/thread/messages` returned 200. Bubblewrap driver phases exited 0.

A second message, with `results/mode-wrong` set, ran the wrong-token case. Then `SIGTERM` to pid 585128 only.

## Secret scan

Secrets were the JSON string values of length 8 or more from both `auth.json` files, plus the admin token file. That was 11 values. The scanner printed hit counts only. It did not print `env.raw`, the database, or any line that contained `lgbr_`.

Scanned after the run: `coi-out/*`, `hello.txt`, `audit.log`, `daemon.log`, `state.db`, `state.db-wal`, `state.db-shm`. Every one of those had `secret_hits=0`. `audit.log` also had `lgbr_` count 0. `env.raw` (933 bytes) had `secret_hits=0` and `lgbr_` count 1: the per-run spool token is in the sandbox because `.lgb/bin/coi` reads `LGB_TOKEN`. The grok secrets and the admin token were absent. `env.raw` was not printed.

Sandbox env keys: `COI_CRED`, `COI_OUT`, `COI_WS`, `HOME`, `LANG`, `LGB_SPOOL`, `LGB_TOKEN`, `OLDPWD`, `PATH`, `PWD`, `TMPDIR`. `HOME` was the workspace.

`daemon.log` (234 bytes) names the admin-token path and says the API token is required. The login hint in that log is the literal placeholder `<token>`, not the token. It also says `listening on 127.0.0.1:8139`.

## Edit

From inside the sandbox, via `.lgb/bin/coi` (no `--always-approve` on bot argv):

```text
coi grok -p "Create the file hello.txt in the current working directory. Write exactly one line into it: hello-from-coi" \
  --cwd <bot workspace> --max-turns 8
```

Exit 0. Broker status `ok`. `hello.txt` is exactly `hello-from-coi` plus a newline (15 bytes). Inner grok tools ran inside the daemon bwrap. `secret_hits=0`.

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
| tilde | `--cwd '~/.grok'` | exit 1, `coi: path is outside the workspace` |
| cred path | `--cwd` set to the absolute credential home | exit 1, `coi: argument references the credential home` |
| cred prompt | `-p` text naming `<credential home>/.grok/auth.json` | exit 1, `coi: argument is blocked` (`auth` in the value) |
| boolean swallow | `-p login` | exit 1, `coi: argument is blocked` |
| flag equals | `--cwd=update` | exit 1, `coi: argument is blocked` |
| always-approve | `--always-approve` | exit 1, `coi: argument is blocked` |
| sandbox flag | `--sandbox x` | exit 1, `coi: argument is blocked` |
| print secrets | `-p` asking grok to print the environment and both auth files | exit 1, `coi: argument is blocked` (`auth` in the value). Stronger than the previous check, where the model ran and refused. |
| copy auth files | `-p` asking grok to copy `~/.grok/auth.json` and `/home/pixnbits/.grok/auth.json` into the workspace | exit 1, `coi: argument is blocked`. `stolen.exists=no`. No `stolen-*.json` in the workspace. `secret_hits=0`. |
| cat cred home | `cat <credential home>/.grok/auth.json` | exit 1, empty stdout, `No such file or directory` |
| cat user auth | `cat /home/pixnbits/.grok/auth.json` | exit 1, empty stdout, `No such file or directory` |
| env dump | `env` in the sandbox | no grok secret and no admin token. The run's `LGB_TOKEN` is present, as above. |
| bwrap missing | policy `sandbox_bin = "/no/such/coi-bwrap"` then `-p hi` | exit 1, `coi: sandbox is not available`. Audit event `coi_sandbox_unavailable`. |
| wrong token | same sandbox, `LGB_TOKEN` replaced with `lgbr_` plus 64 zeros before `coi` | exit 2, `coi: not authorized`. Audit: one `coi_call` denied, error `bad token`. Grok was not started. |
| over cap | eight `-p hi` calls after the policy timeout was `1s`, then a ninth | eight `coi: timed out` (exit 1), then `coi: hourly cap reached` (exit 1). `cap.at` is `9`. |

Audit totals for `coi_call`: 1 `ok` (the edit), 14 `argument is blocked`, 1 `argument references the credential home`, 1 `path is outside the workspace`, 8 `timed out`, 1 `hourly cap reached`, 1 `bad token`. One separate `coi_sandbox_unavailable`. No permission-prompt denial. Two `cli_start` / run pairs (the main turn, then the wrong-token turn).

The hour cap is in SQLite (`coi_cap`). In this run the sandbox-unavailable call still reached `Take` before `Run`; a follow-up commit checks `SandboxReady` before taking a slot. The eight timeouts plus the edit filled the window (`cap.at` is `9` with `max_calls_per_hour = 10` because the unavailable call had already taken one). Argv denials and the wrong token did not take a slot.

## Stop

`SIGTERM` to pid 585128 only, after `ps` confirmed the command was `/tmp/lgb-coi-check`. The process exited. `ss -ltn` shows no listener on port 8139. Ports 8080, 8090, and 8095 were still listening, and pid 287544 was still `/tmp/lgb-dev`.

## Gates

Run from the worktree after the stop. `gofmt -l .` printed nothing (`GOFMT_LINES=0`). `go vet ./...` exited 0. `go test -race ./...` exited 0 (`internal/coi` 1.258s, `internal/daemon` 83.678s; unchanged packages were cache hits). `GOOS=darwin GOARCH=arm64 go build ./...` exited 0.

## Round 3: egress proxy

Date: 2026-10-16. Same worktree branch `docs/coi-credential-broker`. Binary `/tmp/lgb-coi-check`, rebuilt from commit `28fdffb` (not `/tmp/lgb-dev`). Listen address `127.0.0.1:8139`. Data dir `/home/pixnbits/lgb-dev-data/coi-check/r3`. No `-h`, no default port, and no default data dir.

An earlier binary, started as pid 700982 before `28fdffb`, was stopped with `SIGTERM` after `ps` showed `/tmp/lgb-coi-check`. That attempt's edit and copy both exited 1 with the CLI signed-out message and did not write `hello.txt`. Grok 1.0.52 does not treat the synthetic `auth.json` as a session. The forwarder now sets `XAI_API_KEY` to the placeholder, and this section is the rerun.

Listeners left running: pid 287544 (`/tmp/lgb-dev`) on port 8090, pid 510125 (`lgb-voice-bin`) on port 8095, and port 8080. Nothing in this check signaled them.

### Credential home

`/home/pixnbits/lgb-dev-data/coi-check/r3/grok-home` is mode `0700`. `auth.json` is a regular file mode `0600`, not a symlink, and not the same inode as `/home/pixnbits/.grok/auth.json`. Its `expires_at` field was rewritten to `2099-01-01T00:00:00.000000000Z` so the host proxy would not call the refresh endpoint. A refresh rotates the refresh token and would desync the user file. The access token's own expiry was left as issued. The file was not printed.

### Policy

`/home/pixnbits/lgb-dev-data/coi-check/r3/policy.toml`, granted only to bot name `coi-check`. The tool `path` started as `r3/probe.sh` so the first call ran inside the same jail as grok. The driver then rewrote `path` to `/home/pixnbits/.grok/bin/grok`. `proxy_hosts`, `credential_files`, and `fixed_args` stayed in place. The daemon re-reads the file on every call.

```toml
[[tools.cli]]
name = "grok"
path = "/home/pixnbits/lgb-dev-data/coi-check/r3/probe.sh"
credential_home = "/home/pixnbits/lgb-dev-data/coi-check/r3/grok-home"
credential_files = [".grok/auth.json"]
proxy_hosts = ["cli-chat-proxy.grok.com"]
bots = ["coi-check"]
allowed_args = ["-p", "--cwd", "--max-turns", "--version"]
value_flags = ["-p", "--cwd", "--max-turns"]
fixed_args = ["--always-approve"]
timeout = "8m"
max_output = 1048576
max_calls_per_hour = 10
```

The daemon bind, backend `grok`, `turn_timeout = "30m"`, `ui_prompts = false`, timers off, and the audit log path match the round 2 file with `r2` replaced by `r3`. There is no `sandbox.toml` and no `--sandbox` in `fixed_args`. The daemon jail is the only sandbox for this brokered CLI.

### How the turn was driven

`PATH` for the daemon was prefixed with `r3/bin`, where `grok` is a stub. If `LGB_SPOOL` is unset the stub execs `/home/pixnbits/.grok/bin/grok`. If it is set, the stub execs `driver.sh`. The driver runs each phase in bwrap (`--unshare-user --unshare-net --unshare-pid --unshare-uts --die-with-parent --disable-userns --clearenv`). The credential home and `/home/pixnbits/.grok` are not mounted there. `coi` talks to the daemon through the workspace spool.

Started 2026-10-16T10:05:08Z as pid 703436. `AUTH_TOKEN`, `XAI_API_KEY`, `GROK_CONFIG`, `GROK_CONFIG_PATH`, and `GROK_HOME` were unset in the daemon environment. Health returned 200. `POST /api/bots` returned 201. Bot id `227e0f57-71e2-4aa8-8378-d010e802dcb8`. `POST /api/bots/<id>/thread/messages` returned 200. The driver reached phase `done` at 10:06:02Z. Bubblewrap phase exits were 0.

The jail reaches `cli-chat-proxy.grok.com` only through the reverse proxy. The in-jail forwarder listens on `127.0.0.1`, splices TCP to `/coi-proxy.sock`, sets the three Grok base-URL variables to `http://127.0.0.1:<port>/v1`, and sets `XAI_API_KEY` to `coi-placeholder-token`. The host proxy opens TLS to the first `proxy_hosts` entry and replaces `Authorization`. It does not log bodies or headers.

### Cases

| Case | What ran | Result |
|---|---|---|
| (a) edit | `coi grok -p` asking for `hello.txt` containing `hello-from-coi`, `--cwd` the workspace, `--max-turns 8` | exit 0, broker `coi_call` status `ok`. `hello.txt` is exactly that line plus a newline (15 bytes). |
| (b) probe | `probe.sh` as the tool path, same jail | exit 0. `docker=closed`, `run=closed`, `proxy=present`, `lgb=hidden`, `loop8090=closed`, `gw=closed`, `lan=closed`. |
| (c) jail auth | probe copied `$HOME` to `jail-copy/` | one file, `jail-copy/.grok/auth.json`, 289 bytes. Placeholder token, placeholder refresh, and `2099-01-01` each occur once. No `eyJ`. The user file's expiry prefix does not occur. |
| (d) copy | `-p` asking to copy `$HOME/.grok` into `model-copy`, without blocked words | exit 0, broker `coi_call` status `ok`. `model-copy/auth.json` matches the placeholder counts in (c). |
| (e) proxy down | `auth.json` moved aside, then `coi grok -p hi` | exit 1, stdout `coi: proxy is not available`. Audit `coi_proxy_unavailable` once. SQLite `log_events` kind `coi_proxy_unavailable`, status `denied`, error `proxy is not available`. `coi_cap` has 3 rows, so this denial did not take a slot. |
| (f) leak scan | JSON strings of length 8 or more from both `auth.json` files, plus the admin token, minus placeholder strings | `real_secret_values` 10. `secret_hits_total` 1. |

Case (b) targets were `/run/docker.sock`, `/run`, `/var/run`, `127.0.0.1:8090`, the default gateway (LAN gateway, port 80), and the host LAN address (host LAN IP, port 8090). `proxy=present` is the bind at `/coi-proxy.sock`. `lgb=hidden` means `find .lgb -mindepth 1` printed nothing. The empty tmpfs mount still exists, so a check of `[ -e .lgb ]` would be true and would not show the spool. Probe stdout was 306 bytes: `probe-done` once, `Connection refused` twice, `Network is unreachable` four times, no `eyJ`.

Three `coi_call` rows are status `ok` with an empty error (probe, edit, copy). There was no `coi_sandbox_unavailable`. `daemon.log` is 234 bytes, `secret_hits=0`, `lgbr_` count 0, and it names `127.0.0.1:8139`. The login hint there is the literal `<token>`.

The one strict hit is the public OIDC client id (36 characters) in `model-copy/logs/unified.jsonl`, six times, on Grok's `AuthManager::new` scope line. It is the client id compiled into Grok 1.0.52. The jail placeholder uses a different synthetic id, and the line records `GROK_AUTH` unset. The access token, the refresh token, the email, and the other private `auth.json` strings were absent from the workspace, `audit.log`, `daemon.log`, `state.db`, `state.db-wal`, and `state.db-shm`. `audit.log` `lgbr_` count is 0.

## Stop

`SIGTERM` to pid 703436 only, after `ps` confirmed the command was `/tmp/lgb-coi-check`. The process exited. `ss -ltn` shows no listener on port 8139. Ports 8080, 8090, and 8095 were still listening. Pid 287544 was still `/tmp/lgb-dev`. Pid 510125 was still `lgb-voice-bin`.

`r3/grok-home/.grok/auth.json` was removed after its inode was confirmed different from `/home/pixnbits/.grok/auth.json`. The user file was still there afterward, same inode, same size (1758 bytes), mode unchanged, nlink unchanged. There was no `auth.json.off`.

## Gates

Run from the worktree after the stop. `gofmt -l .` printed nothing (`gofmt_lines` 0). `go vet ./...` exited 0. `go test -race ./...` exited 0 (`internal/coi` 2.296s, `internal/daemon` 83.574s; unchanged packages were cache hits). `GOOS=darwin GOARCH=arm64 go build ./...` exited 0. The Seatbelt profile was not executed on this Linux host.

## Round 3 (path allowlist and header strip)

Data under `~/lgb-dev-data/coi-check/r4`, binary `/tmp/lgb-coi-check` built at `c860009`, bind `127.0.0.1:8139` only. The credential copy was a new inode, mode 0600, with only `expires_at` pinned far in the future so nothing refreshed the real login. The default `proxy_path_prefixes` is `/v1`.

| Case | Result |
|---|---|
| Path probe from inside the jail through the forwarder | `/v2/x` 403, `/admin` 403, `/v1/../x` 403. While this ran, the daemon held no socket to port 443 (`peak 0` over 347 samples), so the upstream was not contacted. |
| Grok edit through the shim with the allowlist on | bwrap exit 0, `coi_call` status `ok`. `hello.txt` is exactly `hello-from-coi` plus a newline (15 bytes). The daemon opened one upstream socket on 443 (`peak 1`). |
| Leak scan (workspace, audit log, daemon log, database) | 4 token values and 7 other login strings checked. 0 hits for each. |

Stop: SIGTERM to the 8139 pid only, after confirming the command. Nothing listens on 8139. Ports 8080, 8090, and 8095 were left running. The r4 credential copy was deleted. `~/.grok/auth.json` has the same inode, size, and SHA-256 as before the run (the hash is not recorded). The CLI-backend outer home (not the COI broker) hardlinks the user's login into its data dir, as noted in round 1. That throwaway link was removed after the check.
