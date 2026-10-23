# GitHub pull requests from Ollama bots

Design only. Implementation waits until this is reviewed. No code in this change.

Goal: an Ollama bot with a `github` grant can clone, test, commit, push, and open a pull request on an allowlisted GitHub repo. The fine-grained PAT stays on the host.

Wrong if any of these happen: the token appears in the jail, an environment, a log, a tool result, or an event; a push or pull request targets a repo outside the allowlist intersection; a force push, tag, branch delete, or default-branch update is sent; the model is told a push succeeded when it was not sent; a file tool follows a symlink out of the workspace.

## 1. Current state

Ollama native tools are `read_file`, `write_file`, and `run_shell` (`internal/daemon/tools.go:78-86`). `execTool` logs `tool_start` / `tool_end` and calls `dispatchTool` (`tools.go:200-219`). Nothing on that path calls `permission.Broker.Evaluate`.

`read_file` is `sandbox.Resolve` then `os.ReadFile` (`tools.go:408-416`). `write_file` is `sandbox.Resolve`, `sandbox.CheckWrite`, `os.MkdirAll`, `os.WriteFile` (`tools.go:423-441`). `Resolve` (`internal/sandbox/sandbox.go:27-90`) walks with `Lstat`, and if a component is a symlink whose target stays inside the workspace it continues from that target (`sandbox.go:68-82`). `CheckWrite` (`internal/sandbox/protect.go:13-23`) rejects hook, git-config, and shell-rc paths by string. Neither call is `openat` or `O_NOFOLLOW`. The check and the write are separate, so a swapped symlink is a TOCTOU. `read_file` has the same gap.

`run_shell` reloads the bot and calls `sandbox.Run` with grants, `net_allow`, `ssh_allow`, and read-only `BuildBinds` (`tools.go:443-460`). The shell context is 30 seconds (`tools.go:449`). `sandbox.Request` has no token field (`internal/sandbox/run.go:17-28`). The jail environment is `PATH`, `HOME=/work`, `TMPDIR`, `PWD`, `LANG`, and the three `GIT_CONFIG_*` clears (`run.go:266-275`). No GitHub token is injected. With a proxy it adds only `LD_PRELOAD` and `LGB_PROXY_SOCK` (`run.go:276-280`).

Grants are `net`, `git`, `ssh`, and `build`. Anything else is rejected (`internal/store/store.go:84-105`). The bot row stores `grants`, `net_allow`, and `ssh_allow` (`store.go:228-230`, columns at `store.go:360-362`).

The git binary in the jail is a shell wrapper (`internal/sandbox/wrap.go:11-79`), installed at prepare time (`run.go:175-183`). `status`, `diff`, `log`, `show`, and the other names in `wrap.go:59` run with no grant. Other subcommands need the `git` grant (`wrap.go:63-67`), so `clone` and `commit` run when that grant is on. Every `run()` invocation sets `user.name=local-grok-bots`, `user.email=bot@localhost`, and `core.sshCommand=/bin/false` (`wrap.go:49-52`). `git push` does not call `run()`. It appends `push` to `/lgb/events/log`, prints `git push held for review; not sent`, prints status, diff, and log, and exits 0 (`wrap.go:68-75`). After the process exits, `parseEventFile` maps that line to `grant_use` / `git` / `push held` (`run.go:99-105`, `run.go:416-417`). `recordSandbox` stores the event and posts `Notice: Git push held for review` (`tools.go:478-495`). The tool result is success, because the wrapper exited 0. The events file is created mode `0666` and read only after exit (`run.go:136-137`). Nothing tails it while the command is still running.

The Ollama jail has no network of its own (`internal/sandbox/run_linux.go:24` and `:92`, `--unshare-net`). `LD_PRELOAD` sends non-loopback `connect` to a unix socket (`internal/sandbox/preload.c.txt:18-20`). `startProxy` (`internal/sandbox/proxy.go:34-51`) splices TCP after an allow decision. It does not read HTTP headers and does not set `Authorization`. `net` plus an exact `net_allow` host is enough (`proxy.go:163-169`), so `github.com` on `net_allow` is unauthenticated TLS from the jail. The socket is mode `0666` (`proxy.go:43`).

`internal/sandbox/http_proxy.go` is a different proxy. `HTTPAllow` is the CLI jail egress (`internal/daemon/cli.go:931-942`). On a plain forward it deletes `Proxy-Authorization` and writes the request on (`http_proxy.go:195-204`). It does not delete `Authorization` and it does not add a bearer. A `CONNECT` is spliced after the SNI check (`http_proxy.go:179-192`), so that path cannot inject a header inside TLS.

The COI proxy can inject a header because it is a reverse proxy, not a `CONNECT` tunnel (`internal/coi/proxy.go:27-30`). `StartEgress` (`proxy.go:91-94`) and `StartLoopback` (`proxy.go:148-156`) keep the bearer on the host. The rewrite copies a fixed header allow-list that omits `Authorization` (`proxy.go:954-956`) and then sets `Authorization: Bearer` (`proxy.go:519-530`). `SetAudit` (`proxy.go:235-239`) and `SetRefuseAudit` (`proxy.go:248-251`) record path and status, not headers or the bearer. The daemon registers those hooks at `internal/daemon/cli.go:689-694`.

`permission.Broker.Evaluate` (`internal/permission/broker.go:189-194`) takes durable `UserRules` (`broker.go:65-67`, type at `broker.go:180-187`). Order is hooks, managed deny, user deny (`broker.go:236-237`), asks, then hook allow, bypass mode (`broker.go:266-268`), managed allow (`broker.go:269-270`), a user allow only when the call still classifies as low-risk read-only (`broker.go:272-277`), a session grant (`broker.go:280-282`), then the card. `git push` is classified irreversible, so it is not auto-allowed (`internal/permission/classify.go:35-37`, `classify.go:272-274`). Production callers are CLI stream control (`internal/daemon/cli.go:1337-1352`), Grok ACP (`cli.go:1378-1406`), the MCP `approve` method (`internal/daemon/mcp.go:310-357`), and the COI inner-prompt note (`internal/daemon/coi.go:248-265`, and only when UI prompts are already off). The Ollama tool path is not a caller. With `ui_prompts` off, `Evaluate` denies immediately (`broker.go:435-437`). That is the policy default (`policy.toml.sample` `[cli.permission]`).

Managed policy is the ceiling. Local policy narrows it. `mergeCLITools` keeps a managed CLI entry and applies local only as a narrowing (`internal/policy/clitools.go:567-610`). `finishServerTools` intersects name lists (`internal/policy/policy.go:736-767`). `finishEgressPorts` drops local ports that sit outside the managed or default list (`policy.go:666-693`). A missing or unparseable policy file fail-closes (`policy.go:1-5`).

The `build` grant only bind-mounts extra read-only toolchain paths (`run.go:239-263`). It does not open the network. Network still requires the `net` grant and `net_allow` (`proxy.go:163-169`).

For CLI backends, `clisession/harden.go` adds `Bash(git push)` and `Bash(git push *)` to the Claude deny list only when the bot has no `git` grant (`harden.go:55-57`). That path is out of scope here. The openat walk those file tools should reuse is in `internal/clisession/safedir_unix.go`: `O_NOFOLLOW` directory opens (`safedir_unix.go:19-20`, `:47`, `:121`), exclusive create (`:205`), and replace (`writeReplacingAt`, `:728`, sibling `O_EXCL|O_NOFOLLOW` at `:750`, `Renameat` at `:779`). `removeFileNoFollow` (`:235`) unlinks the leaf and does not follow it, but a symlink leaf is removed (`:255-258`), not refused. `removeTreeNoFollow` (`:267`) walks a tree and is the wrong primitive. The walk is unexported. `WriteFileInDir` (`internal/clisession/safedir.go:12-17`) is the exported wrapper, and it is aimed at credential files.

The profile page hardcodes the four grants (`web/index.html:451-458`) and the status tags (`web/index.html:2184`). Bot tools cannot set grants.

There is no pull-request tool.

## 2. Design

Implementation follows this section after review. Fail closed on a bad parse, a bad token file, a missing grant, or an allowlist miss. Audit every allow and every deny. Audit fields are bot, run, action, `owner/repo`, decision, and reason. They do not contain the token, an `Authorization` value, or a request body.

### Credentials

Use a fine-grained PAT with Contents read-write, Pull requests read-write, and Metadata read, on the chosen repositories only.

`policy.toml` `[github] token_file` is the host path. On each use the daemon `Lstat`s it and refuses it unless all of these hold: not a symlink, regular file, permission bits exactly `0600`, owner uid 0, size at most 4096 bytes, one line. The bytes stay in daemon memory and in the host proxy. They are not mounted, not put in the jail environment, not passed as jail argv, and not written to logs, tool results, or events.

The proxy follows the COI reverse proxy, not `sandbox/proxy.go` and not `HTTPAllow`. It accepts only `github.com` and `api.github.com`. It accepts a path only when the `owner` and `repo` segments are on the effective allowlist (`/owner/repo.git`, `/owner/repo/`, `/repos/owner/repo`, and the pull-request subpaths of those). Encoded `..`, extra slashes, and a path that fails the COI-style unescape checks are refused. It deletes inbound `Authorization` and `Proxy-Authorization`, then sets `Authorization: Bearer` from the host token. Audit matches COI: path and status, no header and no bearer.

The jail network namespace is empty, and the existing preload protocol cannot carry an injected header. The GitHub socket is a separate mode-`0600` unix socket, bind-mounted into the jail, with a small loopback forwarder in the jail the way COI publishes its proxy. Git is pointed at that loopback by wrapper `-c` values. The wrapper does not contain the token.

`startProxy` refuses `github.com` and `api.github.com` even when they are on `net_allow`. A `net` grant does not reach GitHub. SSH remotes stay off (`core.sshCommand=/bin/false` stays). `git@` and `ssh://` URLs are refused.

### Policy and the `github` grant

`[github]` holds `token_file`, an optional `author_email`, and `repos` as `owner/repo` strings.

Merge matches `finishServerTools` (`policy.go:736-768`):

- Neither layer sets `repos`: the list is empty.
- Only managed sets it: that list is the ceiling.
- Only local sets it: that list is used.
- Both set it: intersection. Local names outside the ceiling are ignored and warned.

A bad `[github]` value disables GitHub (empty list) and warns. It does not turn the feature on.

The bot gains `github_allow`, stored like `net_allow`. It can only narrow the policy list. Omitted or empty allows no repository. That is stricter than `server_tools`, where nil inherits the policy list. A credentialed repo does not inherit.

`NormalizeGrants` gains `github` (`store.go:93-101`). The profile checkbox list gains it too (`web/index.html:451-458`, `:2184`). Bot tools still cannot set grants.

A GitHub operation needs the `github` grant and a repository in the intersection of the policy list and `github_allow`. Local `commit` still needs the existing `git` grant. `git push` needs both grants. `create_pr` and `pr_status` need `github` and the allowlist. They do not need a jail push.

### Clone and fetch

`git clone` and `git fetch` of an allowlisted repo use HTTPS through the injecting proxy, including private repos. Any other repo is refused. The refusal happens before git runs.

### `edit_file` and `delete_file`

Both are workspace-only (`a.ws`, the same root `write_file` uses) and keep `CheckWrite`.

`edit_file` replaces an exact string, not a regular expression. Zero matches are refused. More than one match is refused unless `expected_count` is set, in which case the count must equal it and each match is replaced. `expected_count` below 1 is refused. The file must already be a regular file. Content stays within the `write_file` 1 MiB cap (`tools.go:433-434`); a larger file is refused whole.

`delete_file` deletes one regular file. A directory, a symlink, and any non-regular file are refused. It does not recurse and it does not call `removeTreeNoFollow`. It also does not call `removeFileNoFollow` unchanged: that helper unlinks a symlink leaf (`safedir_unix.go:255-258`). Check the leaf with `O_NOFOLLOW` and unlink only a regular file.

The walk uses the `safedir_unix.go` flags: `openat` from a directory fd opened with `O_NOFOLLOW`, and `O_NOFOLLOW` on each component, including the leaf. Parents are created with `mkdirat` and `O_NOFOLLOW`. Replacement uses a sibling created `O_EXCL|O_NOFOLLOW` and `renameat`, as `writeReplacingAt` does. The helpers are unexported and live in `clisession`, so the implementation exports a narrow workspace API or moves the walk. It does not import the credential scrub into the Ollama tool path by calling `WriteFileInDir`.

`write_file` moves to that same walk. `read_file` has the same TOCTOU today; moving it is a follow-up, not part of the first change, unless the shared helper makes it the same patch.

### Build grant

Unchanged mechanism: read-only `BuildBinds` only (`run.go:239-263`). `go test` and `npm test` run in the jail. They get network only when the bot also has `net` and the host is on `net_allow`. The `build` grant does not add a network exception. The system prompt says so.

### Commit author

`user.name` is the bot name. `user.email` is `[github] author_email` when set, otherwise `{bot-name}@users.noreply`. Both must match a safe charset before they are placed in the wrapper. A value that fails the check refuses the git invocation. This replaces `wrap.go:49-50`. It is not read from host git config. `GIT_CONFIG_GLOBAL=/dev/null` stays.

### Push

`git push` in the jail does not exec `git push` and does not exit 0.

The wrapper parses the argv enough to send the remote and the refspecs to the daemon, then blocks on a socket. The socket is served while `sandbox.Run` is still inside `launch`. The events log cannot do this: it is parsed only after exit (`run.go:99-105`). `sandbox.Request` gains a host callback. The callback runs on a goroutine started in `prepare`, the same way `startProxy` already serves concurrently (`proxy.go:50`). The callback has the bot, the run, and the broker. It does not return the token.

The daemon resolves the remote and the destination ref itself, from the workspace on the host. It does not trust the jail's diff text. Then, before `Evaluate`:

- missing `git` or `github` grant
- repository not in the intersection
- token file refused
- remote not HTTPS `github.com` for an allowlisted `owner/repo`
- `--force`, `--force-with-lease`, `--force-if-includes`, or a refspec whose source starts with `+`
- `--delete`, an empty source, or a refspec that deletes
- a tag destination, `--tags`
- `--all`, `--mirror`
- destination branch equal to the repository default branch
- default-branch lookup failed

The default branch is `default_branch` from `GET /repos/{owner}/{repo}` through the proxy. A non-200 or a missing field is a deny.

Any of those is a hard deny: audit, do not call `Evaluate`, wrapper exits non-zero. A durable allow, a managed allow, bypass mode, and a session grant never see the request.

A push that passes is `Evaluate` with tool name `git_push`. The card arguments are the repo, the branch, the commit list, and the diffstat, gathered on the host. The existing `permission_request` card is the UI (`broker.go:452-470`). `git_push` is not classified `AutoAllow`, so a durable user allow does not skip the card (`broker.go:272-277`). A durable deny still denies. Session grants do not satisfy `git_push` or `create_pr` (`broker.go:280-282` must not hit). Managed bypass can still allow a request that reached `Evaluate` (`broker.go:266-268`); see open questions.

On allow, the daemon runs the push on the host through the injecting proxy. The jail git process is not the client that authenticates. The wrapper's exit status is the daemon's result. Deny and transport failure are non-zero. The tool output says whether the push was sent. It does not include the token.

`run_shell`'s 30 second context (`tools.go:449`) is not the card deadline. Once the handoff starts, the wait uses `EffectivePromptTimeout` (`policy.go:456-459`). Until the handoff starts, the 30 second cap still applies. `ui_prompts` must be on, or `Evaluate` denies with `no_ui` (`broker.go:435-437`).

### `create_pr` and `pr_status`

`create_pr` is an Ollama tool in `toolDefs`, executed in `dispatchTool` on the host. No MCP server. Arguments: `repo` (`owner/repo`), `head`, `base`, `title`, `body`, and `draft` (default true when omitted). The same hard denies apply. `head` must not be the default branch. `base` may be. Both are branch names. The call then uses `Evaluate` with tool name `create_pr` and the same card fields. On allow the daemon sends `POST /repos/{owner}/{repo}/pulls` through the proxy and returns the pull request URL. The raw response is not returned.

`pr_status` is optional and read-only. Arguments: `repo` and the pull request number. It requires the `github` grant and the allowlist, it is audited, and it does not open a card. The result is a projection: URL, state, draft, head, base. It is not the raw JSON.

### Prompt text

`internal/daemon/run.go:352` gains `edit_file`, `delete_file`, `create_pr`, and `pr_status`. It says file tools stay in the workspace; GitHub remotes are HTTPS to allowlisted repos; `git push` waits for a card and is sent by the daemon; tests stay offline unless `net` is granted. `run_shell`'s description (`tools.go:85`) stops saying that a grant makes `git push` succeed. It says push is an approval and is not sent from the jail.

## 3. Conflicts and open questions

Native Ollama tools never call `Broker.Evaluate`. `read_file`, `write_file`, `edit_file`, and `delete_file` stay on the sandbox path. `git_push` and `create_pr` are the new callers, through the callback and `dispatchTool`. Wiring `Evaluate` into every `run_shell` is not part of this design.

`write_file` is `Resolve` plus `os.WriteFile` (`tools.go:423-441`, `sandbox.go:52-84`). That is not the `O_NOFOLLOW` walk this design requires. The first implementation moves `write_file` onto that walk. Leaving it on `os.WriteFile` would miss the requirement.

`wrap.go:49-50` hardcodes the author. The wrapper is generated with `fmt.Sprintf` into a shell script. Bot name and `author_email` must be charset-checked before they are embedded. A name that can break out of the script refuses the command.

A held push exits 0 (`wrap.go:75`) and the model sees a successful tool result plus `not sent` in the output. The new flow exits non-zero unless the host push actually succeeded. `TestShellGitAndSSHGrants` requires that success: `err == nil`, stdout contains `not sent` and `PUSH_DONE`, and the thread gets the notice (`internal/daemon/grants_test.go:453-467`). That test changes with the implementation.

`net` plus `net_allow` can already open TLS to `github.com` (`proxy.go:163-169`) with no token. This design refuses those two hosts on the splice proxy. Other hosts are unchanged. A bot that needs public GitHub traffic without the `github` grant will lose it. That is the intended cut.

The git wrapper is a shell script. `parseEventFile` runs after exit, so it cannot block on a card. The handoff is a socket served during `launch`. The model runs as the same uid and can connect to that socket. The daemon rebuilds the repo, ref, commit list, and diffstat on the host before the card. The socket reply is an allow or a deny. It is not a credential.

The `build` grant does not control network (`run.go:239-263`). Offline tests are the prompt plus the existing jail, not a new grant behavior.

`deploy/local-grok-bots.service` sets no `User=`, so the unit as committed runs as root and can read a root-owned `0600` file. `policy.toml.sample` says the unit should run as a non-root system user. A non-root daemon cannot read a root-owned `0600` file. This design keeps the root-owned `0600` check and fail-closes when the open or the owner check fails. Review chooses one: keep "daemon euid must be 0", or change the check to "owner uid is the daemon euid, mode `0600`" and have the operator `chown` the file to that user. Group-readable is not an option. The file is not mounted into the jail in either choice.

`github_allow` omitted means no repos. `server_tools` nil inherits (`store.go:231-233`). Review can flip `github_allow` to inherit. The written choice is empty.

Durable user allows do not auto-approve `git push` today, because it is not low-risk read-only. This design keeps that for `git_push` and `create_pr`. A durable allow therefore does not skip the card. Hard denies never reach `Evaluate`, so they also cannot match a deny rule or an allow rule. If review wants a durable allow to skip the card for a non-default, non-force, allowlisted push, that is a separate exception. It is not the default here.

Managed bypass (`broker.go:266-268`) and a managed allow rule (`broker.go:269-270`) still allow a request that reached `Evaluate`, without a card. Hard denies are outside that path. Confirm at review whether a managed always-allow mode may approve a normal `git_push` or `create_pr`. This design leaves that existing order in place.

`ui_prompts` defaults off, which denies the card (`broker.go:435-437`). The test bot's policy has to turn it on or every push and pull request is denied.

`clisession/harden.go:55-57` denies `git push` for Claude only when the `git` grant is absent. CLI backends are out of scope. This design does not change that file.

Issue #8 is "Egress and credential proxy hardening follow-ups". It is not part of this work.

## 4. Tests planned

- The token is absent from the jail environment, jail mounts, stdout, stderr, the events file, audit rows, and tool output. A caller-supplied `Authorization` is not what GitHub sees.
- A repo outside the intersection is refused. A repo on the bot list but outside the managed ceiling is refused. A local-only list works when managed sets no `repos`. An omitted `github_allow` allows nothing.
- Default branch, `+` refspecs, `--force`, `--force-with-lease`, tags, and branch delete are refused with no `Evaluate` call, including when a durable allow rule would otherwise match.
- `edit_file` refuses zero matches and a non-unique match, and accepts `expected_count` when the count matches.
- `delete_file` refuses a directory, a symlink leaf, and a symlink parent that points outside the workspace.
- Audit rows exist for allow and deny and contain no token.
- `httptest` stands in for GitHub on push and `create_pr`, including the default-branch lookup.
- The old "push held" exit-0 case in `grants_test.go` is updated to the non-zero deny or the host-push result.

Gate, from a clean tree, after the implementation:

```
gofmt -l . && go vet ./... && go test -race ./... && go test -race -tags lgbtest ./... && GOOS=darwin go build ./...
```

## 5. Out of scope

Other forges. Grok and Claude backends, including `clisession/harden.go`. Auto-merge. Issue #8 (egress and credential-proxy hardening follow-ups). The voice branch. Deploys, and the processes already listening on 8080, 8090, and 8095.

## 6. Setup Nick must do

1. Create a fine-grained PAT as the resource owner. Limit it to the selected repositories. Permissions: Contents read-write, Pull requests read-write, Metadata read. Set an expiry.
2. Create a private scratch repository, `PixnBits/lgb-pr-scratch`, and a non-default branch that the test bot is allowed to push. Do not allow the default branch.
3. Put the token in the `token_file` path. `chown root:root` and `chmod 0600`. The daemon reads that path on the host. It does not mount or copy the file into the jail. The unit in `deploy/local-grok-bots.service` has no `User=`, so it runs as root and can read the file. If you set `User=` to a non-root account, the owner check fail-closes until review changes it (section 3). Do not loosen the mode.
4. Add a `[github]` stanza to `policy.toml`: `token_file`, `repos = ["PixnBits/lgb-pr-scratch"]`, and `author_email` if `{bot-name}@users.noreply` is not the address you want. Turn `ui_prompts` on under `[cli.permission]`, or the card denies immediately.
5. On the test bot, enable the `github` grant and set `github_allow` to `PixnBits/lgb-pr-scratch`. Enable `git` as well if the bot will clone and commit. `build` is only needed for toolchain binds. `net` is not required for GitHub, and `github.com` on `net_allow` will not open a bypass.
