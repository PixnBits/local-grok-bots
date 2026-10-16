# Grok process isolation live check

Date: 2026-10-16. Branch `fix/grok-proc-isolation`. Binary `/tmp/lgb-proc-check` (production build, no test tag). Listen address `127.0.0.1:8139`. Fresh data dir `/home/pixnbits/lgb-dev-data/proc-check2`. No `-h`, no default port, and no default data dir. The daemon was started with a clean environment, a `PATH` that includes the Grok binary directory, a canary `AUTH_TOKEN`, and `LGB_CANARY_*` names. Policy bind and `BIND_ADDR` were `127.0.0.1:8139`. Backend `grok`. Timers off. `ui_prompts` false. Managed policy set `bypassPermissions` so the headless turn could write files. Grok's sandbox requirement was not turned off. `socat` was present.

Listeners left running: pid 287544 (`/tmp/lgb-dev`) on port 8090, pid 510125 (`lgb-voice-bin`) on port 8095, and port 8080. Nothing in this check signaled them.

## Daemon environment

The running daemon pid was 1031434 (`/tmp/lgb-proc-check`). `/proc/<pid>/environ` had 10 names: `BIND_ADDR`, `DATA_DIR`, `HOME`, `LANG`, `LGB_ENV_READY`, `LOGNAME`, `MANAGED_POLICY`, `PATH`, `POLICY_PATH`, `USER`. Canary names were absent. `AUTH_TOKEN` was absent. Canary and token values were absent. The reexec marker was not the literal value `1`. `GET /api/health` returned 200. `GET /api/bots` without a bearer returned 401.

## Grok turn

`POST /api/bots` returned 201. Bot `8aea5d71-e080-42c1-9b72-553fb38306a2` had no net grant. The turn finished `done` with an empty error. It wrote `workspace/bots/<id>/hello.txt` as `hello` plus one newline (6 bytes).

The jail's `/proc` showed five processes: pid 1 `bwrap`, the forwarder, a `grok` process, and the `bash` and `python` helper that ran the probe. The daemon pid was not visible.

From that probe, a host abstract listener the checker could connect to was unreachable, and so was another host abstract socket the checker could connect to. The well-known systemd private bus name and the dbus abstract name were not present on this host. The host's loopback model listener and this daemon's listen port were unreachable. The LAN default gateway was unreachable. `HTTP_PROXY` and `HTTPS_PROXY` were unset.

A credential-proxy socket was present under the data dir during the turn. Audit events: `cli_start` 1, `cli_proxy_request` 11, `cli_stop` 1. The log text does not contain `Authorization`, `Bearer`, or `lgb_`. There was no `cli_bridge_unavailable` event.

## User login file

`~/.grok/auth.json` stayed a regular file, not a symlink. The inode was the same, the SHA-256 was the same, and `nlink` was 1. A poll every 0.2 seconds recorded 121 samples, each 1. `secret_hits` in the data dir was 0 (71 files), counting the login file's key and refresh token only.

## Stop

`SIGTERM` went only to pid 1031434 after `ps` showed `/tmp/lgb-proc-check`. The process exited. Nothing listens on port 8139. Ports 8080, 8090, and 8095 were still listening. Pid 287544 was still `/tmp/lgb-dev`. Pid 510125 was still `lgb-voice-bin`.

`git grep -nE '192\.168\.'` is empty.
