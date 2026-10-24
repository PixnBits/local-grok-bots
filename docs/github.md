# GitHub pull requests from Ollama bots

An Ollama bot with a `github` grant can clone, fetch, commit, push, and open a pull request on an allowlisted repository. The fine-grained PAT stays on the host.

Wrong if any of these happen: the token appears in the jail, an environment, a log, a tool result, or an event; the jail socket can push or call a write API; a push or pull request targets a repo outside the allowlist; a force push, tag, branch delete, or default-branch update is sent; host git reads or runs the bot's `.git`; the model is told a push succeeded when it was not sent.

## What is built

`run_shell` with the `github` grant gets a mode-`0600` unix socket at `/lgb/sock/github.sock`. That socket is a read proxy. It forwards only:

- `GET` `…/info/refs?service=git-upload-pack`
- `POST` `…/git-upload-pack`
- `GET /repos/{owner}/{repo}`
- `GET /repos/{owner}/{repo}/pulls/{n}`

for an allowlisted owner/repo. `git-receive-pack`, `HEAD`, every other non-GET, and any other route return 403. The proxy audits the method. A non-GET is action `github_write`. The token is added only on a forwarded request, after the caller's `Authorization` is dropped.

`git push` in the jail does not run `git push`. The wrapper hands the argv to the daemon and waits. The daemon hard-denies, before the approval card, a missing grant, an allowlist miss, a bad token file, a refused `.git/config`, a mirror it cannot build, a bad ref, a tag, and a destination branch equal to the default branch in any letter case. Force, delete, and tag shapes in the argv are denied the same way. `github_allow` omitted or empty allows no repository.

A push that is still allowed always shows a card (`ForceAsk` on `git_push`). Bypass mode, a managed allow, a durable allow, and a session grant do not skip it. `ui_prompts` off denies with no card. After the card is approved, the daemon opens a second proxy, on `127.0.0.1` only, pushes, and closes it. That listener is not mounted in the jail and does not exist while the card is waiting.

`create_pr` reads the default branch through a read proxy, closes that proxy, then asks (`ForceAsk`). The pull-request `POST` uses the write proxy and only after approval. The head branch is refused when it matches the default branch in any letter case. The base branch may be the default. `pr_status` is a read through the read proxy and does not open a card.

The splice proxy still refuses `github.com` and `api.github.com` even when they are on `net_allow`. A jail denial of that kind, and a missing GitHub socket, is an audit row with action `github_refuse`.

## Threat model

The jail can fetch an allowlisted repo. It cannot push, open a pull request, or call any other write route. The socket it sees is the read proxy.

Host git never uses the bot workspace as `GIT_DIR` or as `git -C`. The workspace `.git` is writable by the bot, so its config, hooks, attributes, and objects are untrusted. The daemon parses `.git/config` as text, without running git, and hard-denies a push when it contains a key in `url.*`, `credential*`, `http.*`, `gpg.*`, `include*`, `includeIf*`, or `core.fsmonitor` / `core.askpass`. A `[remote]` URL is not one of those keys, and the push does not read it. The remote on the card and the push URL come from the allowlist and the argv.

Before the card, the daemon copies refs and objects into a bare mirror under its own data directory. The copy skips config, hooks, attributes, logs, and `objects/info/alternates`, and it does not follow symlinks or a gitfile. The mirror gets a config the daemon writes. Every host git command uses that mirror as both cwd and `GIT_DIR`, with `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` on `/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, and overrides for fsmonitor, hooks, askpass, the credential helper, `gpg.program`, `log.showSignature`, external diff, attributes, and the file and ext protocols. The commit list on the card is `git log --stat` from the mirror with `--no-textconv`, `--no-ext-diff`, and `--no-show-signature`. The push URL is the write proxy's loopback address for the allowlisted owner/repo, not an `insteadOf` rewrite of `https://github.com/`.

`deploy/local-grok-bots.service` has no `User=`. systemd starts that unit as root. A hook, `gpg.program`, fsmonitor, textconv, askpass, or credential helper in the bot's `.git` would run as root if host git pointed at that directory. The mirror and the config deny exist so a bot-writable repository cannot choose the program or the push target.

The token file stays root-owned mode `0600`. The daemon refuses a symlink, any other mode, any other owner, and a file larger than 4096 bytes. The token is not mounted, not put in the jail environment, and not written to logs, tool results, or audit rows.

## Setup

1. Create a fine-grained PAT as the resource owner. Limit it to the selected repositories. Permissions: Contents read-write, Pull requests read-write, Metadata read. Set an expiry.
2. Create a private scratch repository and a non-default branch the bot is allowed to push. Do not push the default branch.
3. Put the token in the `token_file` path. `chown root:root` and `chmod 0600`. The daemon reads that path on the host. It does not mount or copy the file into the jail. The unit runs as root, so it can read a root-owned `0600` file. Do not loosen the mode. A non-root `User=` cannot pass the owner check.
4. Add a `[github]` stanza to `policy.toml`: `token_file`, `repos`, and `author_email` when `{bot-name}@users.noreply` is not the address you want. Turn `ui_prompts` on under `[cli.permission]`, or the card denies immediately.
5. On the bot, enable the `github` grant and set `github_allow` to the scratch repo. An empty `github_allow` allows nothing. Enable `git` as well if the bot will clone and commit. `net` is not required for GitHub, and `github.com` on `net_allow` does not open a bypass.
