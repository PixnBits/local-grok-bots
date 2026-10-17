# Grok process isolation live check

Date: 2026-10-16. Branch `fix/grok-proc-isolation`. Binary `/tmp/lgb-proc-check` (production build, no test tag). Listen address `127.0.0.1:8139`. Fresh data dir `/home/pixnbits/lgb-dev-data/proc-check3`. No `-h`, no default port, and no default data dir. The daemon was started with a clean environment, a `PATH` that includes the Grok binary directory, a canary `AUTH_TOKEN`, and `LGB_CANARY_*` names. Policy bind and `BIND_ADDR` were `127.0.0.1:8139`. Backend `grok`. Timers off. `ui_prompts` false. Managed policy set `bypassPermissions` so the headless turn could write files. Grok's sandbox requirement was not turned off. `socat` was present.

Listeners left running: pid 287544 (`/tmp/lgb-dev`) on port 8090, pid 510125 (`lgb-voice-bin`) on port 8095, and port 8080. Nothing in this check signaled them.

## Daemon environment

The running daemon was `/tmp/lgb-proc-check`. `/proc/<pid>/environ` had 10 names: `BIND_ADDR`, `DATA_DIR`, `HOME`, `LANG`, `LGB_ENV_READY`, `LOGNAME`, `MANAGED_POLICY`, `PATH`, `POLICY_PATH`, `USER`. Canary names were absent. `AUTH_TOKEN` was absent. Canary and token values were absent. Because `AUTH_TOKEN` was set at startup, it remained the API token and `DATA_DIR/admin-token` was not created. `GET /api/health` returned 200. `GET /api/bots` without a bearer returned 401.

## Egress from the jail

`POST /api/bots` returned 201. Bot `4dec943b-c873-4a8b-8a08-c8e42ee551b0` had the `net` grant. Its allowlist was `example.com`, `api.github.com`, one literal tailnet address, and one literal LAN address. No host file was edited. The turn finished `done` with an empty error. A program inside the jail requested those targets on port 443 through the egress proxy.

`example.com` and `api.github.com` returned HTTP 200. The tailnet address and the LAN address were refused. The proxy answered before dialing. Python's client reports a refused CONNECT as `URLError`. The audit rows, with those addresses replaced, are:

| host | port | decision | reason |
|---|---|---|---|
| example.com | 443 | allow | ok |
| api.github.com | 443 | allow | ok |
| `<tailnet>` | 443 | deny | address |
| `<lan>` | 443 | deny | address |

Each row is `cli_egress_request` and also carries `bot_id`, `run_id`, and `ts`. The audit text does not contain `Authorization`, `Bearer`, or a request header. Other events in the same log: `cli_start` 1, `cli_proxy_request` 8, `cli_stop` 1.

## User login file

`~/.grok` and `~/.grok/auth.json` kept the same inode, link count, and SHA-256. `auth.json` stayed a regular file, not a symlink, with `nlink` 1. A poll every 0.5 seconds recorded 77 samples, each 1.

## Stop

`SIGTERM` went only to the `/tmp/lgb-proc-check` process that was listening on port 8139. The process exited. Nothing listens on port 8139. Ports 8080, 8090, and 8095 were still listening. Pid 287544 was still `/tmp/lgb-dev`. Pid 510125 was still `lgb-voice-bin`.

`git grep -nE '192\.168|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.'` matches only example addresses in `internal/sandbox/http_proxy_test.go`.
