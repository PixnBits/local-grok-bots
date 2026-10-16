# Grok process isolation live check

Date: 2026-10-16. Branch `fix/grok-proc-isolation`. Binary `/tmp/lgb-proc-check`. Listen address `127.0.0.1:8139`. Fresh data dir `/home/pixnbits/lgb-dev-data/proc-check`. No `-h`, no default port, and no default data dir. The daemon was started with `env -i`, a `PATH` that includes the Grok binary directory, a canary `AUTH_TOKEN`, and `LGB_CANARY_*` names. Policy bind and `BIND_ADDR` were `127.0.0.1:8139`. Backend `grok`. Timers off. `ui_prompts` false. Managed policy set `bypassPermissions` so the headless turns could write files. Grok's sandbox requirement was not turned off in managed policy. `socat` was present.

Listeners left running: pid 287544 (`/tmp/lgb-dev`) on port 8090, pid 510125 (`lgb-voice-bin`) on port 8095, and port 8080. Nothing in this check signaled them.

## Daemon environment

The running daemon pid was 989873 (`/tmp/lgb-proc-check`). `/proc/<pid>/environ` had 10 names: `BIND_ADDR`, `DATA_DIR`, `HOME`, `LANG`, `LGB_ENV_READY`, `LOGNAME`, `MANAGED_POLICY`, `PATH`, `POLICY_PATH`, `USER`. Canary names were absent. `AUTH_TOKEN` was absent. Canary and token values were absent. `GET /api/health` returned 200. `GET /api/bots` without a bearer returned 401.

## Two Grok-backend bots

`POST /api/bots` returned 201 twice. Bot A `210a13e0-072d-4698-907d-5ad7569f0f39`. Bot B `3b03b908-be18-4366-a8bf-6c971d6210ca`. Both turns finished `done` with empty errors.

Both wrote `workspace/bots/<id>/hello.txt` as `hello` plus one newline (6 bytes).

From a process in bot A's turn, `/proc` showed three pids: pid 1 `bwrap`, pid 2 `grok-1.0.52-lin`, and a `bash` helper. The daemon pid was not visible. Its environment file and `fd` directory were missing. A host marker pid started for the check was not visible. Bot B's id was recorded; no other `grok` comm was listed. Bot B was still in its turn while A probed.

`cli/<A>/home/.grok/sandbox.toml` was still written (mode `0600`). The turn did not pass a nested sandbox flag; the daemon pid jail was the process boundary.

Audit events: `cli_start` 2, `cli_proxy_request` 17, `cli_stop` 2. The log text does not contain `Authorization`, `Bearer`, or `lgb_`.

## User login file

`~/.grok/auth.json` stayed a regular file, not a symlink. The inode was the same, the SHA-256 was the same, and `nlink` was 1. A poll every 0.2 seconds recorded 869 samples, each 1. `secret_hits` in the data dir was 0 (130 files).

## Stop

`SIGTERM` went only to pid 989873 after `ps` showed `/tmp/lgb-proc-check`. The process exited. Nothing listens on port 8139. Ports 8080, 8090, and 8095 were still listening. Pid 287544 was still `/tmp/lgb-dev`. Pid 510125 was still `lgb-voice-bin`.

`git grep -nE '192\.168\.'` is empty.
