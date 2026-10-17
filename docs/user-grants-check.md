# Durable grant live check

Date: 2026-10-16. Branch `feature/user-auto-grants-analysis`. Binary `/tmp/lgb-grants-check` (production build, no test tag). Listen address `127.0.0.1:8139`. Fresh data dir `/home/pixnbits/lgb-dev-data/grants-check/data`. Policy `/home/pixnbits/lgb-dev-data/grants-check/policy.toml`. No `-h`, no default port, and no default data dir.

Listeners left running: pid 287544 (`/tmp/lgb-dev`) on port 8090, pid 510125 (`lgb-voice-bin`) on port 8095, and port 8080. Nothing in this check signaled them. `SIGTERM` went only to pid 1102851, the `/tmp/lgb-grants-check` process listening on `127.0.0.1:8139`. That process exited. Nothing listens on 8139. Ports 8080, 8090, and 8095 were still listening.

The daemon log is 234 bytes, contains `listening on 127.0.0.1:8139`, and does not contain the admin token. `GET /api/bots` without a bearer returned 401. `GET /api/health` returned 200. The token file mode was `0600`.

## Policy

`claude_sandbox` was omitted, so the default stayed `required`. `ui_prompts` was set true and `claude_transport` was `stream_control`, so a residual ask stays pending instead of a `no_ui` deny. Timers were off. Backend was `claude`. The generated `claude-settings.json` had sandbox `enabled` true and `failIfUnavailable` true. It did not contain `git status`. Argv used `--input-format stream-json` and did not contain `Bash(git status*)`.

`claude` on `PATH` was a stream-json peer at `/tmp/grants-check-bin/claude`, not the Claude product. The peer does not run a shell. The daemon's login probe (`claude auth status`) closed stdin and the peer exited; the turns still completed.

## User login file

`~/.grok` and `~/.grok/auth.json` kept the same inode, link count, and SHA-256. `auth.json` stayed a regular file with `nlink` 1. A poll every 0.5 seconds recorded 7 samples, each 1. One unreadable name under `~/.grok` stayed unreadable; its inode and link count were unchanged. Digests are not recorded here.

## Accept and auto-allow

`POST /api/bots` returned 201. One seed turn asked `git status -sb`, stayed pending, and was answered `allow_once` (200). The run finished `done` with an empty error. `POST /api/bots/{id}/permission-suggestions/analyze` returned 200 with one pending card, pattern `Bash(git status *)`, risk `low`. Accept posted effect `allow` and pattern `Bash(git status*)` (the card's pattern edited, which is what the profile field does) and returned 201. `user-permissions.json` and `grok-permission-rules` were regular files mode `0600`. The JSON contained `Bash(git status*)`. The text file contained `allow Bash(git status*)`.

A second turn asked `git status`. It did not sit in `GET /api/bots/{id}/permissions`. The run finished `done` with an empty error. The `kind: "permission"` row was `decision` `allow`, `source` `user`, `rule` `Bash(git status*)`, `classification` `read_only`, `ok` true. Its `rule_id` was set and equaled the id from the accept response.

## Composed command

`x` was created in the bot workspace with body `keep`. A third turn asked `git status; rm x`. `GET /api/bots/{id}/permissions` showed one pending `Bash` card whose command was `git status; rm x`. `x` was still `keep` while that card was open. The card was then denied (200) so the turn could finish. The run finished `done` with an empty error. The permission row was `decision` `deny`, `source` `ui`, not a user allow, and `rule_id` was empty. `x` was still present and still `keep`. The peer received `behavior=deny` and did not remove the file.

## Address grep

`git grep -nE '192\.168\.'` is not empty. The matches are existing examples in `internal/sandbox/http_proxy_test.go`. This check does not add one.
