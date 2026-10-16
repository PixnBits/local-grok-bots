# Grok CLI login live check

Date: 2026-10-16. Branch `fix/cred-hardlink-and-deps`. Binary `/tmp/lgb-cred-check` (not `/tmp/lgb-dev`). Listen address `127.0.0.1:8139`. Data dir `/home/pixnbits/lgb-dev-data/cred-check`. No `-h`, no default port, and no default data dir. The daemon was started with `env -i` and did not receive `AUTH_TOKEN`, `XAI_API_KEY`, or `GROK_*`.

Listeners left running: pid 287544 (`/tmp/lgb-dev`) on port 8090, pid 510125 (`lgb-voice-bin`) on port 8095, and port 8080. Nothing in this check signaled them.

## What ran

Policy bind and `BIND_ADDR` were both `127.0.0.1:8139`. Backend `grok`. Timers off. `ui_prompts` false. Managed policy set `bypassPermissions` so the headless turn could write a file. `POST /api/bots` returned 201. Bot id `868d6c20-4449-4237-aaab-cf3ae6763c3a`. `POST /api/bots/<id>/thread/messages` returned 200. The bot asked Grok to create `hello.txt` containing `hello` and one newline.

`last_run_status` was `done`. `last_run_error` length was 0. The bot returned to `idle`. Audit events were one `cli_start` and one `cli_stop`. `workspace/bots/<id>/hello.txt` is 6 bytes and matches that text. The turn's `sandbox.toml` has `restrict_network = true` and still reached the loopback proxy, so no read-only bind of the user login was added.

## User login file

Compared `~/.grok/auth.json` before the daemon started, after the turn, and after bot delete. It was not a symlink. The inode was the same, the SHA-256 was the same, and `nlink` was 1 at each comparison (the digest is not recorded here). A poll every 0.2 seconds during the run recorded 41 samples, and every sample was 1. No file under the data dir shared that inode. No symlink there resolved to that path. The file was not modified, refreshed, copied, or linked.

The bot home held a regular placeholder `auth.json`, mode `0600`, different inode, 336 bytes. Its key was the per-run proxy secret. That secret occurred once in the data dir, in that file only.

## Delete

`DELETE /api/bots/<id>` returned 204. A following `GET` returned 404. Neither `cli/<id>/home/.grok/auth.json` nor `cli/<id>/grok-home/auth.json` remained, and no other `auth.json` remained under that bot's cli home. The per-run secret pattern was absent from the data dir after the delete.

## Secret scan

JSON string values of length 8 or more from the user `auth.json`. `key` and `refresh_token` are the token values. The scan printed counts only.

`secret_hits` was 0 before delete and 0 after delete, including `state.db`, `audit.log`, and `daemon.log`. `daemon.log` is 227 bytes. It names the admin-token path and prints the literal placeholder `<token>`. It says `listening on 127.0.0.1:8139`.

Other strings from that file: the public issuer `https://auth.x.ai` and the `oidc_client_id` (36 characters). Before delete the issuer also occurred twice in the placeholder, which names that issuer. After delete both remain only in `cli/<id>/home/.grok/logs/unified.jsonl`, 7 times each. That is Grok's own log line for its public client id. It is not the access token or the refresh token. Email and the other private strings in the user file had no hits.

## Stop

`SIGTERM` to pid 922082 only, after `ps` confirmed the command was `/tmp/lgb-cred-check`. The process exited. Nothing listens on port 8139. Ports 8080, 8090, and 8095 were still listening. Pid 287544 was still `/tmp/lgb-dev`. Pid 510125 was still `lgb-voice-bin`.

## Round 2

Date: 2026-10-16. Same binary path and port. Fresh data dir `/home/pixnbits/lgb-dev-data/cred-check2`. `env -i` again, with `HOME`, `PATH`, `USER`, `LOGNAME`, and `LANG` only. No `AUTH_TOKEN`, `XAI_API_KEY`, or `GROK_*`. Policy bind and `BIND_ADDR` were `127.0.0.1:8139`. Backend `grok`. Timers off. `ui_prompts` false. Managed policy set `bypassPermissions`.

The turn finished `done` with an empty error. `workspace/bots/<id>/hello.txt` is 6 bytes and is `hello` plus one newline. The audit log has 9 `cli_proxy_request` rows. Each carried bot id, run id, path, and status, except one rejected row whose bot id, run id, and path were empty and whose status was 403. Paths were under `/v1`. The rows have no header and no body. A scan of the data dir for the user login's token strings was 0 hits, including `audit.log`. The strings `Authorization`, `Bearer`, and `lgb_` did not occur in that log.

`~/.grok/auth.json` was not a symlink. Across the turn and the later delete it kept the same inode, the same SHA-256, and `nlink` 1. A poll every 0.2 seconds during the turn recorded 382 samples, and every sample was 1.

The first `DELETE /api/bots/<id>` returned 500 and left `cli/<id>` in place. The tree contained a directory whose mode did not allow listing. Removal now sets that directory's mode and then deletes it, without following a symlink. A second delete, on the same data dir and a rebuilt listener, returned 204 with an empty body. `cli/<id>` was gone. The user login file was unchanged. `SIGTERM` went only to the `/tmp/lgb-cred-check` pid. Port 8139 was free. Ports 8080, 8090, and 8095 were still listening. Pid 287544 was still `/tmp/lgb-dev`. Pid 510125 was still `lgb-voice-bin`.

## Process environment

The COI bubblewrap jail hides an unrelated host pid. The jailed command does not keep the launcher's marker. Pid 1 in that jail is `bwrap`, and that process's environment file still contains the launcher's variable names. The command's own `/proc/self/environ` file was empty.

On the live Grok turn, `/proc/1` was `systemd` and its environment names were empty. The daemon pid was visible. Its environment names were not returned. The turn's own environment names included the proxy variables and ordinary host names. No environment values were recorded.

## Supervisor environment

Date: 2026-10-16. Binary `/tmp/lgb-cred-check`. Listen address `127.0.0.1:8139`. Fresh data dir `/home/pixnbits/lgb-dev-data/cred-check3`. The daemon was started with `env -i`, a `PATH` that includes the Grok binary directory, and canary variables. It did not receive `AUTH_TOKEN`, `XAI_API_KEY`, or `GROK_*`. Listeners on 8080, 8090, and 8095, including pid 287544 (`/tmp/lgb-dev`), were left running.

The COI jail's pid 1 was `bwrap`. Its environment names were only `PATH`. The forwarder and the probe carried the scrubbed child names: `HOME`, `LANG`, `LOGNAME`, `PATH`, `PWD`, `TMPDIR`, `USER`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, and `XDG_STATE_HOME`. The probe also had `COI_FORWARD_URL`. No canary name and no daemon data or policy name was readable from any `/proc/*/environ` in that jail.

A brokered `coi grok` call exited 0. `hello-from-coi.txt` is `hello-from-coi` plus one newline. Both `coi_call` rows were `ok`. The outer turn finished `done` and wrote `hello.txt` as `hello` plus one newline. Its environment names did not include the canaries or `AUTH_TOKEN`. They included `PATH`, `HOME`, `LANG`, `TERM`, `LGB_SPOOL`, `LGB_TOKEN`, `LGB_SESSION_MARKER`, `XAI_API_KEY`, the three proxy base URL names, and the `GROK_*` names this isolation sets. Grok's own sandbox also added pager, git, and cargo names.

`secret_hits` was 0. A poll of the user login file recorded 101 samples, each with `nlink` 1. The credential copy was a new regular file, mode `0600`, a different inode, and it was deleted after the check. The user file kept the same inode and the same SHA-256.

`SIGTERM` went only to the `/tmp/lgb-cred-check` pid. Port 8139 was free afterward. The other listeners were unchanged.

The unix-socket egress used by the jailed forwarder is still outside the loopback per-run gate and is not recorded as `cli_proxy_request`.
