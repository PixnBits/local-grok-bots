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

At the time of this note the listener on `127.0.0.1:8139` was pid 922082, command `/tmp/lgb-cred-check`. It is stopped after this note is committed.
