# CLI permission approvals

A headless CLI turn used to fail with `permission prompt requires a TTY or an explicit permission_mode` as soon as the CLI asked for a tool. The daemon is the permission host for Claude and for Grok. `cli.permission.claude_transport` selects the Claude host: `mcp` (the default), `stream_control`, or `none`. Grok turns use the ACP host described below. `acp` is not a `claude_transport` value. A raw Claude permission prompt that is not covered by a host or by `--permission-prompts none` still fails the turn.

The stock page subscribes to the run stream with `?prompts=1` and renders `permission_request`. With `ui_prompts` on, a request waits whether or not any page is attached to that run: the bot does not have to be the open tab. It stays pending until it is answered, the run ends (`cancel`), or `prompt_timeout` passes (`timeout`, deny). `GET /api/bots/{id}/permissions` (and `GET /api/permissions` for every bot) lists open requests with the same payload as `permission_request`, so a page that opens later shows and answers them. `GET /api/bots` carries `pending_permissions` per bot, and the bot list shows a "needs approval" badge. A live run token (lgb or the MCP permission token) cannot read these lists or decide a card.

## Policy

`[cli.permission]` (and the older `[cli].permission_mode`) sets:

| Field | Meaning |
|---|---|
| `mode` | Passed to the CLI as `--permission-mode`. Empty leaves the CLI's own default. |
| `allow` | Tool rules that allow without a prompt, such as `Read` or `Bash(cat *)`. |
| `deny` | Tool rules that deny. |
| `ask` | Tool rules that always go to the host, even when a later allow rule or a bypass mode would allow them. |
| `ui_prompts` | When true, a residual ask waits for an answer from the page (any tab, now or later) until `prompt_timeout`. Default false, which denies at once with source `no_ui`. |
| `prompt_timeout` | How long a permission or question card waits. Default 10m. A managed `max_prompt_timeout` caps it. See Timeouts in `docs/cli-isolation.md`. |
| `allow_session_grants` | Lets a UI answer `allow_session`. Honored only from the managed policy file. |
| `claude_transport` | `mcp` (default), `stream_control`, or `none`. Empty is `mcp`. Any other value is a config error, and load uses the existing fail-closed fallback (daemon jail on, CLI backends off). |

Precedence is unchanged: managed settings, then `policy.toml`, then defaults. A missing or unparseable file still fail-closes (daemon jail on, CLI backends off). Managed policy is read when the daemon starts. The permission broker, CLI turn flags, and permission mode use that snapshot. Editing the managed file does not change a running daemon; restart it.

Always-allow modes are `always`, `always-allow`, `always_allow`, `always-approve`, `bypass`, `bypassPermissions`, `dontAsk`, and `dont-ask`. A user policy file that sets one of those, or `allow_session_grants = true`, is stripped. The daemon logs a warning and leaves the previous non-bypass mode in place. The same keys in the managed file are kept. `dontAsk` is an always-allow alias in the broker. It is not passed to Grok as `--always-approve`. On a Grok turn the broker applies a managed bypass only after Grok has asked. `acceptEdits` and `plan` are ordinary modes: Claude still receives them as `--permission-mode`. They do not auto-allow inside the broker, and Grok does not receive a permission-mode flag.

## Broker

`internal/permission.Broker` evaluates one tool call in this order. A deny stops the check. A hook allow does not skip deny or ask rules.

1. Hooks, in registration order. A hook may return `deny`, `ask`, or `allow`.
2. Managed deny rules.
3. User durable deny rules.
4. Managed ask rules. An ask forces the UI path even in a bypass mode.
5. User durable ask rules.
6. `AskUserQuestion`, matched case-sensitively. A hook deny or a deny rule still wins. Otherwise this is always a UI question: a bypass mode, an allow rule, a hook allow, and a session grant do not answer it. The wire shape and the card are in `docs/cli-isolation.md` under Interactive tools.
7. A hook allow, if one was recorded and no deny or ask fired.
8. Bypass mode, only when the resolved mode is an always-allow mode. The daemon copies that mode onto the CLI only when managed policy set it.
9. Managed allow rules.
10. User durable allow rules, and only when the concrete call still classifies as low-risk read-only. A matching glob that is a write, redirect, credential path, or shell composition does not allow.
11. An in-memory session grant for this bot, session, tool, and subject.
12. canUseTool: publish `permission_request` and wait, or deny.

Rules match the tool name, with an optional argument glob in parentheses: `Bash(ls *)`. `*` and `?` are globs. The tool name is case-insensitive. The argument text is case-sensitive. For Bash it comes from `command` or `cmd`. For Read and LS it comes from `file_path`, `filePath`, or `path`. For Grep and Glob it comes from `path`, `file_path`, or `filePath`; when that field is missing the match uses `.` (the workspace root), so `Grep(./**)` matches a Grep with no path and `Glob(./**)` matches a Glob whose only field is `pattern`. After the existing path and symlink checks pass, a workspace path is matched in every equivalent form: relative, `./x`, and an absolute path inside the workspace are the same. A path outside the workspace is left unchanged, so `Read(./**)` does not match it. The pattern is anchored to the whole string. A prefix pattern, a literal prefix plus a trailing run of `*` and `?`, does not match when the remaining suffix contains `;`, `|`, `&`, `` ` ``, `$`, `(`, `)`, `<`, `>`, or a newline.

canUseTool denies with source `no_ui` only when `ui_prompts` is off. It does not publish `permission_request` in that case. Otherwise it publishes, lists the request in `Pending`, and waits for `Decide`, whether or not a page is attached. The page shows the tool name, the arguments as sent (already redacted), a countdown to `deadline`, and posts `{"decision":"allow_once"|"deny"|"allow_session"}` to the route above. `allow_session` is offered only when `session_allowed` is true. A question (`kind: "question"`) is a different card: header, question text, options, an Other field, Submit, and Skip. Submit posts `{"decision":"answer","answers":{...}}`. Skip posts `deny`. Claude's message for that Skip is `The user did not answer the question (skipped).` A `permission_decision`, or the countdown hitting zero, disables the card and shows the decision and source. Timeout, context cancel, an unknown id, and a daemon restart deny. Pending requests live only in memory. `allow_session` is rejected and the request stays pending when managed policy did not allow session grants. A grant is stored per bot and session (or per run when the session id is empty), and per tool plus a subject. The subject is the trimmed command for Bash, the resolved path for file tools, `url` for WebFetch, and `notebook_path` for NotebookEdit. Any other tool uses the canonical JSON of its arguments. Glob and Grep also include the pattern (and Grep's `glob`) so two patterns do not share a grant. A grant for one subject does not cover a different one. It is checked after allow rules, so a later deny or ask still wins.

Each decision emits `permission_decision` and, when audit is on, one audit record: `source` (`policy`, `hook`, `ui`, `user`, `timeout`, `no_ui`, `cancel`, `cli`, or `host`), the rule that matched, tool, redacted arguments, bot, run, time, decision, and `transport`. A user-rule decision also stores `rule_id`, `classification`, `sensitivity`, and `risk`. A question adds `kind`, `answered`, and redacted `answers` on the audit record. The SSE decision carries `kind` and `answered` and omits the answer text. Arguments go through `audit.RedactValue` (the same redactor the daemon uses for tool payloads). The allow payload sent back to Claude keeps the original arguments so the tool still runs.

`transport` is the wire actually used, not a second copy of the policy string. `stream_control` is stamped for every decision on that transport, including a broker `no_ui` deny. `mcp` is stamped only when the HTTP prompt tool is attached. `none` is stamped when the turn passes `--permission-prompts none`: the policy value `none`, or `mcp` with `ui_prompts` off or with no HTTP base. `acp` is stamped for every Grok decision, including a broker `no_ui` deny and a host failure. The approval card ignores the field.

`POST /api/bots/{id}/runs/{run_id}/permissions/{req_id}` accepts `{"decision":"allow_once"|"deny"|"allow_session"}`, or `{"decision":"answer","answers":{...}}` with optional `annotations` for a question. The request must belong to that bot and run. `answer` on any other request, or `allow_once` or `allow_session` on a question, is 400 and leaves it pending. A free-text answer longer than 4 KiB is 400 and leaves the question pending. A second decision is 409. A live `lgbr_` token or MCP permission token is 403 on this route. The admin token, as a Bearer or the `lgb_auth` cookie, still decides. Other routes return 401 for a run token.

## Durable user auto-grants and analysis

The existing allow/ask/deny rules and session grants are the foundation. This layer reduces prompt toil for repeated low-risk patterns while keeping the user (and a CISO) in control.

### First pass

Durable rules are rows in `user_perm_rules`, one bot at a time, permanent until revoked. Project scope and time bounds are not implemented. Session grants stay managed-only and in memory.

A user allow is stored only when the pattern is a known low-risk read-only shape (`Bash(cat *)`, `Bash(pwd)`, `Bash(grep *)`, `Bash(rg *)`, `Read(./src/**)`). Git is not one of those shapes. Ask and deny are stricter and do not have to be read-only. At decision time the broker classifies the concrete call again and auto-allows only when that call is still low-risk read-only. Shell composition, redirects, network commands, credential paths, and writes fall through to ask or deny. Managed deny, managed ask, and managed bypass are unchanged and win over a user allow. A user deny or ask is applied before managed allow and bypass.

Accepting or revoking a rule is one transaction covering the `user_perm_rules` row, the `user_perm_rule` log event, and both rule files. The log event has the exact pattern and the risk label shown at acceptance time. The files are `DATA_DIR/cli/<bot>/user-permissions.json` (Claude `permissions.allow` / `permissions.deny`, plus `lgbAsk` because neither CLI has an ask flag) and `grok-permission-rules`. Those files are not passed as `--allowedTools` or `--allow` on the isolated bot turn. The permission host stays attached, the broker decides, and the audit / `run_tools` record includes `rule_id`, `classification`, `sensitivity`, and `risk`. Loading the native allow list into the bot turn would let the CLI allow before the host and drop that record. Copy the generated file when running the CLI outside the bot.

Suggestions are static only. There is no local-model second pass. `POST /api/bots/{id}/permission-suggestions/analyze` clusters logged `kind: "permission"` rows. The same clustering runs after 3 similar requests. Mixed or deceptive clusters are stored as refused and cannot be accepted until the pattern is edited into an eligible allow. Nothing is applied without an explicit accept. The profile page lists rules and suggestions.

### What the code does

A durable rule is one bot, one tool name, and an optional argument glob (`Bash(cat *)`, `Read(./src/**)`, `Bash(*push*)`). It lasts until it is revoked. There is no project scope and no time bound. Whitespace in a pattern is collapsed before it is stored or compared, so `Bash(cat  *)` is the same rule as `Bash(cat *)`. A newline or a NUL is rejected. The same collapse is applied when the policy file is loaded, when a suggestion is saved, and when a rule is matched, including a row that was stored before the collapse. An allow such as `Bash(cat *)` still does not auto-allow the unprefixed command `cat file`: the `--` floor is unchanged. Creating or suggesting that pattern returns `warning` and `match_form` (`cat -- file`) so the page can show the command that matches. The stored pattern is not rewritten to insert `--`. Session grants stay managed-only and in memory. A session grant is one tool plus one subject (command, path, url, notebook path, or canonical JSON arguments).

An allow is stored only when `CheckUserRule` accepts it. Ask and deny are stored when the shape is well formed, including patterns that are not read-only. At decision time `ClassifyCall` runs again. A user allow applies only when that call has `AutoAllow`. A stored pattern that would match a wider command does not widen the call.

`AutoAllow` is only a low-risk read-only call inside the bot workspace. The permission broker table in `docs/permission-broker.md` is a different classifier: `ls`, `pwd`, and `echo` are unclassified there, a hard ask, once only, and not a task grant.

- Bash, and only these binaries: `cat`, `ls`, `head`, `tail`, `wc`, `pwd`, `stat`, `file`, `grep`, `rg`, or `find`. `Bash(grep *)` and `Bash(rg *)` are accepted as allow patterns. Each later call is classified again against the per-command option allowlist.
- Read tools `read`, `grep`, `glob`, and `ls`, for a project path. Glob classifies its `pattern`, `path`, `file_path`, and `filePath` fields as paths. The literal directory before the first glob metacharacter in `pattern` is resolved, and a result outside the workspace is refused. Those checks run before a stored allow is applied. Grep classifies its `glob`, `path`, `file_path`, and `filePath` fields as paths. An absolute path, a `..` segment, or a `~` segment is refused.

A Glob allow must name a project prefix with a trailing glob (`Glob(./**)`, `Glob(./src/**)`). `Glob(**)` and a filename pattern such as `Glob(*.txt)` are refused at create: the wildcard is not a trailing glob on a project path. Store `Glob(./**)` when the clustered calls search the workspace root.

Git is never auto-allowed, including `git status`. The broker does not run the command. An allow returns the original tool input, and the CLI runs it, so a stored git allow would let the CLI invoke hooks, an external diff, textconv, or a pager. A stored allow whose pattern names git does not apply; the call falls through to a prompt. An ask rule for git can still be stored. `git diff`, `git log`, and `git show` can invoke an external diff, textconv, or pager. `gh` is a network command. It is not auto-allowed, and the suggestion pass does not offer `gh` or git as low-risk.

These are never `AutoAllow`, even when a glob matches:

- Shell composition. Unquoted `\`, `;`, `|`, `&`, `<`, `>`, `` ` ``, `$`, `{`, `}`, `*`, `?`, `[`, newline, or CR, and `$`, `` ` ``, newline, or CR inside double quotes. An unquoted brace or glob is shell expansion, including a glob that could expand into an option-like name. `Bash(ls *)` therefore does not allow `ls; rm x` or `ls > /etc/x` or `ls > notes.txt` or `ls *`. Characters inside single quotes are literal. A stored prefix rule also refuses to match when the suffix after the literal prefix contains `;`, `|`, `&`, `` ` ``, `$`, `(`, `)`, `<`, `>`, or a newline.
- Any byte outside `0x20`–`0x7E` in a Bash command, checked before the command is split.
- A file operand before `--` on a command that supports `--`. A command that does not support `--` refuses an operand that starts with `-`. Options are an allowlist per command. An option that is not listed is refused, including `rg --pre`, `rg --pre-glob`, `rg --hostname-bin`, `rg -z`, `rg --search-zip`, `file -C`, `tail -f`, `tail -F`, and `grep -f`.
- `git -C`, `--git-dir`, `--work-tree`, `--ext-diff`, `--textconv`, `--no-index`, and any `-c`, before or after the subcommand. `git --output` or `--output=` is a write.
- `find` expressions are an allowlist of known predicates. An unknown expression token is refused. `-follow`, `-L`, and `-H` are refused. `-delete`, `-exec`, `-execdir`, `-ok`, `-okdir`, `-fls`, `-fprint`, `-fprintf`, and `-fprint0` are refused.
- Network binaries: `curl`, `wget`, `ssh`, `scp`, `sftp`, `nc`, `ncat`, `netcat`, `ping`, `dig`, `nslookup`, `npm`, `npx`, `yarn`, `pnpm`, `pip`, `pip3`, `gem`, `apt`, `apt-get`, `brew`, `docker`, `kubectl`, `helm`, `aws`, `gcloud`, `az`, `rsync`, `ftp`, `telnet`, `socat`, and `gh`. Git `fetch`, `pull`, `clone`, and `ls-remote`. Tools `webfetch` and `websearch`.
- Irreversible binaries: `rm`, `rmdir`, `dd`, `mkfs`, `shred`, `sudo`, `doas`, `su`. Git `push`, `reset`, and `clean`.
- Write binaries: `tee`, `mv`, `cp`, `install`, `mkdir`, `touch`, `truncate`, `ln`, `chmod`, `chown`, `chgrp`, `sed`, `tar`. Tools `edit`, `write`, `multiedit`, and `notebookedit`.
- A path segment `.ssh`, `.aws`, `.gnupg`, `.netrc`, `.kube`, `.azure`, `.docker`, `.grok`, `credentials`, `credentials.json`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `auth.json`, `admin-token`, `policy.toml`, `.git-credentials`, `.npmrc`, `.pypirc`, `cookies`, `.env`, `.env.*`, `*.pem`, `*.key`, `state.db`, `state.db-*`, `user-permissions.json`, or `grok-permission-rules`. That includes `~/.grok/config` and a copy of those names inside the workspace.
- A path outside the bot workspace, including home and system paths. `DATA_DIR` is not a separate input; an absolute path that is not inside the workspace fails the same way. At decision time every path argument is resolved with `filepath.EvalSymlinks`. A path that resolves outside the workspace is refused, and so is a path whose parent is missing. The final component may be absent. This check runs before the tool, so a path can change before the command runs. Sandbox read limits are the real backstop for that gap.

Anything that is not one of the read-only shapes above also fails closed.

Managed deny, managed ask, and a managed bypass mode still win over a user allow. A user deny and a user ask are applied before managed allow and before bypass. The rules that become `--allowedTools`, `--disallowedTools`, `--allow`, or `--deny` are the policy rules (plus the `lgb` and `coi` spool allows). A user rule is not copied onto those flags and is not copied into the turn's `claude-settings.json` allow list. A user settings file cannot add an allow either; that merge is unchanged.

The broker runs on the Claude permission host (`mcp` and `stream_control`) and on the Grok ACP host. A durable allow auto-allows a Grok tool only when that call still classifies as low-risk read-only, the same rule Claude uses. The Grok process is not given the user pattern as `--allow` or `--deny`.

Accept and revoke are one transaction: the `user_perm_rules` row, the `user_perm_rule` log event, and both rule files. Any failure rolls all three back and returns an error; nothing half-applied is left behind. The files are `DATA_DIR/cli/<bot>/user-permissions.json` (Claude `permissions.allow` and `permissions.deny`, plus `lgbAsk`) and `grok-permission-rules` (allow and deny lines; ask lines are comments). The directory is created with a no-follow walk from `/`. A symlink in any component, including the file name, is refused and not followed. The bytes go to a sibling opened with `O_CREAT|O_EXCL|O_NOFOLLOW` and renamed into place. On macOS the walk crosses `/tmp`, `/var`, and `/etc` only when that link points under `/private`. The bot turn does not load either file. Copy them when running the CLI outside the bot.

On Linux the Grok jail bind-mounts the workspace, the bot home, and `GROK_HOME`. The two rule files sit beside `home` and `grok-home`, and they are not mounted. Grok does not need to read them. When a rule file exists as a regular file at turn start, the Grok `lgb` deny list names it, and Claude settings deny `Read` and `Edit` of that path. `DATA_DIR/cli` is still expanded around the bot home, because denying the whole directory would make Grok's own home read-only. A file created after that profile is written is absent from that turn's Grok deny list. A symlink at the rule-file name is not added to the deny list, because the deny must not follow it; the writer refuses to replace that symlink.

Suggestions are static. `gh` and git are not clustered into a low-risk card. `POST /api/bots/{id}/permission-suggestions/analyze` clusters logged `kind: "permission"` rows and keeps a card at count 1. The same clustering runs after 3 similar requests (`SuggestAfter`). An eligible card's summary is `{count} prior {pattern} requests, all classified {kind} / {sensitivity}. Suggest permanent allow? Risk: {risk} ({reason}).` A mixed cluster is `{count} prior requests look like {pattern} but at least one is a write, a redirect, or a sensitive path. Classification refused auto-allow.` A refused card cannot be accepted until the pattern or effect is changed; the same pattern with effect allow is 400. Whitespace around the pattern is ignored for that comparison. Nothing is applied without an explicit accept.

The profile page lists each rule with its effect, pattern, risk, and reason, and a Revoke button. Suggestions show an editable Pattern field, the summary, and examples. A pending card has Accept and Dismiss. A refused card has Dismiss only; Accept stays hidden until the stored status is no longer refused. Revoke and Dismiss errors are shown on the profile. A separate form posts effect and pattern (placeholder `Read(./src/**)`). Analyze posts the analyze route. There is no edit of an accepted rule other than revoke and add.

### Future work

Not implemented, and not enforced:

- Project scope.
- Time bounds.
- A second pass with a local model. If it is added, it must not be the only authority for an allow.
- Generating Claude `settings.json` permissions or Grok `sandbox.toml` allow rules from accepted patterns and loading those allows into the bot turn. That would let the CLI allow before the host and drop the broker's `rule_id` record. The files written today are for a CLI the user runs outside the bot.

## Claude transport

| | `mcp` | `stream_control` | `none` |
|---|---|---|---|
| When | Default, and the empty value. The HTTP tool is attached only when `ui_prompts` is on and the daemon has an HTTP base. Otherwise this mode behaves as `none`. | `claude_transport = "stream_control"`. Stdio is the host even when `ui_prompts` is off or there is no HTTP base. Residual asks still die in the broker as `no_ui`. | `claude_transport = "none"`, or `mcp` falling through as above. |
| Argv | `-p`, `--output-format stream-json`, `--verbose`, `--include-partial-messages`, and, when a host is attached, `--mcp-config` (a file path, not inline JSON) plus `--permission-prompt-tool mcp__lgbperm__approve`. The permission token is not an argument. | `--input-format stream-json`, `--output-format stream-json`, `--verbose`, `--permission-prompt-tool stdio`. No `-p`, no `--mcp-config`, no `--include-partial-messages`, no `--permission-prompts`. The prompt is a stdin message. Model, session, `--permission-mode`, `--allowedTools`, and `--disallowedTools` stay. | `--permission-prompts none`. No prompt tool and no MCP server. |
| Ask | HTTP `tools/call` of `approve`. | Stdin `control_request` subtype `can_use_tool`. | Claude denies. The daemon audits `permission_denied`. |
| Broker | Same order. Deny wins. The card is only for a residual ask. | Same broker, same card. | No card. |
| `transport` on the event | `mcp` when the tool is attached, otherwise `none`. | `stream_control`. | `none`. |

A denial Claude reports itself stays source `cli` while a host is attached (`mcp` or `stream_control`). With `--permission-prompts none`, source is `no_ui` when prompts are off and `policy` when prompts are on but there is no host.

### MCP

When the backend is Claude, the transport is `mcp`, `ui_prompts` is on, and the daemon knows a non-zero HTTP base, the turn gets a random token and these flags:

- `--permission-mode` from policy, when set
- `--allowedTools` / `--disallowedTools` from allow and deny rules
- `--mcp-config` pointing at `DATA_DIR/cli/<bot>/perm/<run>/mcp.json` (mode 0600; one directory per run, removed when the turn ends). The file names an HTTP server `lgbperm`. Its `url` is `{base}/api/mcp/permission` and does not include the token. Its `headersHelper` is a shell command that reads `mcp-perm.token` (mode 0600) and prints `{"Authorization":"Bearer ..."}`. Claude runs that command in a shell at connect time ([MCP dynamic headers](https://code.claude.com/docs/en/mcp)). The token is not in the JSON and not on argv. Claude honoring `headersHelper` in an `--mcp-config` file is taken from its docs; this repo's tests use a fake `claude` and have not checked it against a real Claude CLI.
- `--permission-prompt-tool mcp__lgbperm__approve`

That is Claude's default `--permission-prompts host`: residual asks go to the prompt tool. When `ui_prompts` is off, or the daemon has no HTTP base, the turn passes `--permission-prompts none` and does not attach the prompt tool. Claude denies anything that would have prompted. The daemon audits those `permission_denied` events as source `no_ui` when prompts are off, and as source `policy` when prompts are on but there is no host. A denial reported while a host is attached stays source `cli`.

Ask rules are broker-only. Claude has no matching flag, so an ask applies when Claude calls `approve`. A deny rule is also `--disallowedTools`, so Claude can refuse before the prompt tool.

`POST /api/mcp/permission` is the MCP endpoint. The credential is `Authorization: Bearer <token>`. `POST /api/mcp/permission/{token}` still accepts the same token in the path. Neither route uses the daemon admin token. The route speaks a small JSON-RPC subset: `initialize`, the `notifications/initialized` notification, `ping`, `tools/list`, and `tools/call` for `approve` with `{tool_name, input, tool_use_id}`. An allow returns text content `{"behavior":"allow","updatedInput":{...}}`. A deny returns `{"behavior":"deny","message":"..."}`. `updatedInput` is the original input object (or `{}`), except an answered `AskUserQuestion`, which sends the original input plus `answers`.

`permission_denied` system events and `result.permission_denials` are parsed as `permission_decision` and audited. Source is `cli` when a host is attached, `no_ui` when `--permission-prompts none` was set because `ui_prompts` is off, and `policy` when it was set because there is no HTTP host. They do not fail the turn. A headless prompt phrase with no host and without `--permission-prompts none` still fails closed.

The token file, the helper script, and `mcp.json` are removed when the turn ends. The in-memory bind is dropped then too. A bind address of `:0` has no stable base URL, so tests that use `httptest` set the base to the server URL.

### stream_control

The daemon keeps the CLI's stdin open and writes one JSON object per line. Writes are serialized with a mutex. After a `result` (or `end`) message it closes stdin so the CLI exits. Ordinary stream events (`assistant`, `stream_event`, `system`, `result`) are parsed as on the `-p` path and may arrive between control messages.

The framing matches PyPI `claude-agent-sdk` 0.2.167:

- `claude_agent_sdk/_internal/query.py` `initialize` sends `{"subtype":"initialize","hooks":null}` through `_send_control_request`, which uses `request_id` `req_{n}_{8 hex chars}` from `os.urandom(4).hex()`.
- The same file's `_handle_control_request` answers `can_use_tool` with `behavior` `allow` and `updatedInput`, or `behavior` `deny` and `message`. Any other subtype, including `hook_callback` and `mcp_message`, is an error. A `control_cancel_request` cancels the in-flight ask and writes no response.
- `claude_agent_sdk/_internal/transport/subprocess_cli.py` passes `--input-format stream-json` with `--output-format stream-json` and `--verbose`.
- `claude_agent_sdk/types.py` sets `permission_prompt_tool_name="stdio"` when a permission callback is routed over the control protocol (`_configure_can_use_tool`).

The first write is the initialize request. The daemon waits for a matching `control_response`. `subtype` `error`, a malformed response, or stdout ending first fails the turn closed. The user prompt is not sent.

```json
{"type":"control_request","request_id":"req_1_0123abcd","request":{"subtype":"initialize","hooks":null}}
```

Success is `{"type":"control_response","response":{"subtype":"success","request_id":"req_1_0123abcd","response":{...}}}`. An error is the same envelope with `subtype` `error` and `error` set, and no `response` field.

The prompt follows, with an empty `session_id`, which is the SDK string-prompt path in `_internal/client.py`:

```json
{"type":"user","session_id":"","message":{"role":"user","content":"<prompt>"},"parent_tool_use_id":null}
```

Claude asks with:

```json
{"type":"control_request","request_id":"X","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{},"tool_use_id":"...","permission_suggestions":[],"blocked_path":null,"decision_reason":null}}
```

That call goes through the broker. Allow echoes the original `input` bytes as `updatedInput` (not the redacted copy). An answered `AskUserQuestion` is the exception: the daemon remarshals the original input with `answers` filled in.

```json
{"type":"control_response","response":{"subtype":"success","request_id":"X","response":{"behavior":"allow","updatedInput":{}}}}
```

Deny:

```json
{"type":"control_response","response":{"subtype":"success","request_id":"X","response":{"behavior":"deny","message":"denied by policy rule Bash(rm *)"}}}
```

A different `control_request` subtype, or a request object that is not an object, gets `{"type":"control_response","response":{"subtype":"error","request_id":"X","error":"..."}}` and a deny audit. The turn keeps going. A line that is not JSON, or a control message with no `request_id`, is audited and ignored. `{"type":"control_cancel_request","request_id":"X"}` denies the pending ask with source `cancel` and writes nothing.

### Managed policy with MCP off

Managed settings win over `policy.toml`. This managed file selects Claude and answers tool checks on stdin, so the daemon does not attach the HTTP MCP server:

```json
{
  "backend": { "backend": "claude" },
  "cli": {
    "permission": {
      "ui_prompts": true,
      "claude_transport": "stream_control",
      "allow": ["Read"],
      "deny": ["Bash(rm *)"]
    }
  }
}
```

## Grok

A Grok turn is `grok agent --no-leader stdio` inside the same Linux bubblewrap jail, credential bridge, and environment scrub as before. The daemon is the ACP client. It sends `initialize` (`protocolVersion` 1), then `session/new` with `cwd` and `mcpServers` (an empty list) for a fresh turn, or `session/load` with the session id Grok returned last time. The prompt is `session/prompt`, not `-p`. `session/new` and `session/load` do not set `yoloMode` or `autoMode`. The argv does not include `--always-approve`, `--permission-mode`, `--output-format`, a session id, or a user rule.

The per-bot `GROK_HOME/config.toml` sets `disable_web_search = true`, `[ui] permission_mode = "default"`, and a catch-all `[permission] ask` list: Bash, Read, Grep, Glob, Edit, Write, WebFetch, WebSearch, MCPTool. Without that list, read-only tools run and never send `session/request_permission`. That file, and the other sealed names under `GROK_HOME`, must be the daemon's bytes or the turn is refused. `disable_web_search` is kept as defense in depth. It has no effect on Grok server-side search. The daemon does not pass `--always-approve`, and it does not copy user rules onto `--allow` or `--deny`. Managed deny rules stay on `--deny`. The `lgb` and `coi` spool allows (`Bash(lgb)`, `Bash(lgb *)`, `Bash(coi)`, `Bash(coi *)`) stay on Grok's `--allow`, because those commands are the daemon's own tools and are not a permission intercept. When the permission broker hook is armed for a Claude turn, Claude is given no `--allowedTools` at all, including those spool allows. See `docs/permission-broker.md`.

`--tools` is a global flag before `agent`. It lists only `run_terminal_command`, `read_file`, `search_replace`, `grep`, and `write`, plus `web_fetch` and `web_search` when the bot has a net grant. That flag does not stop server-side search: `grok agent stdio` ignores `--tools` and `--disallowed-tools` for tools the model runs at the provider. The loopback credential proxy strips non-function tools from every non-empty body it allows through, not only `/v1/responses` or a chat completions body. The path is the normalized path from the allow decision, so a trailing slash, another case, or an encoding that still names an allowed path does not skip the filter. A `function` tool stays. A bot without a net grant loses every non-function tool, including `web_search` and `x_search`. Policy cannot keep one. A net grant keeps only the types on the effective `server_tools` list. The default list is empty. Set it in policy:

```toml
[cli]
# Omitted means empty (strip every non-function type). An explicit []
# narrows a managed ceiling to nothing. Local policy can only narrow.
server_tools = ["web_search"]
```

Managed policy sets the ceiling. Local policy intersects it. A per-bot list intersects again. Leaving the bot field out means inherit. `POST /api/bots` accepts `server_tools`. Omit it, or send `null`, to inherit policy. `[]` allows none of those types. `PATCH /api/bots/{id}` omits the field to leave it unchanged, sends `null` to inherit again, and sends `[]` to allow none. `GET /api/bots/{id}` and `GET /api/bots/{id}/state` return the stored list (`null` inherits). The profile edits the field: "Inherit from policy" sends `null`, and an explicit list sends that array, including an empty one for none. Duplicate copies `server_tools` and does not copy grants. `create_bot` treats an omitted value or `null` as inherit and `[]` as none. `update_bot` omits the field to leave it unchanged, sends `null` to inherit, and sends `[]` for none. Each strip is audited as `cli_proxy_stripped` with the bot, the run, the path, the removed types, and the source (`managed`, `local`, `bot`, `default`, or `no_net`). A parsed body is forwarded re-encoded, never as the original bytes. A duplicate object key at any depth is `cli_proxy_refused` with reason `duplicate_key`. Invalid JSON, a non-JSON body, `tools` that is not an array, or an unsupported content encoding is `cli_proxy_refused` with reason `unparsed`. A top-level key that equals `tools` or `tool_choice` ignoring case, but is not that exact spelling, is `cli_proxy_refused` with reason `tools_key` and is not forwarded. The exact `tools` key is still filtered. The proxy reads the files when a body has a `tools` array to filter. Permission mode still uses the snapshot from daemon start. `list_dir`, `x_keyword_search`, and `x_semantic_search` are not listed. `lgb` and `coi` are shell commands, not tools, and keep the spool path above. A user message that is a slash command, after leading space and format characters, is refused before the process starts. A solidus counts as a slash.

`session/new` and `session/load` must report mode `default` before the prompt is sent. A `session/update` that changes the mode, or sets a bypass flag, including `current_mode_update`, `config_option_update`, `_x.ai/sessions/changed`, and `_x.ai/session_notification` on `_meta`, fails the turn. A top-level notification method `_x.ai/sessions/changed` or `x.ai/sessions/changed` fails the turn unless every `params.upserted` entry has `yolo` present as a JSON boolean false. A missing field, a renamed field, or a non-boolean fails closed and is audited. Monitor is classified as Bash. Task, Workflow, Scheduler, and image or video generation tools are denied. A write, an edit, or a shell target whose path resolves under `GROK_HOME` is denied. Other `session/update` notifications become the same run events the streaming parser already stores (tokens, tool calls, tool results). A legacy streaming-json line after the handshake is still parsed. A `session/request_permission` is not a headless prompt failure. Its `sessionId` must be the current session. The host maps `toolCall` onto `permission.Request` and calls the same `Broker.Evaluate` Claude uses: user rules, classification, managed precedence, session grants, the permission card, and the audit / `run_tools` row (`rule_id`, `classification`, `sensitivity`, `risk`, `transport: acp`). Bash comes from `command`. Read, Grep, Edit, and Write use `file_path` (from `target_file`, `path`, or the meta input). `list_dir` is classified as Glob if a request arrives. An unknown tool is evaluated and audited as tool `unknown` with classification `unknown`. A failed tool update that says the call was denied, and that did not ask first, is audited with source `cli_deny`.

The card is the same card Claude shows: allow once, deny, and allow for session when policy allows it. A session grant is stored by the broker under the session id Grok returned. The wire answer is still `allow-once`. A later turn loads that id, so the grant still matches. A deny is `reject-once`. The host never selects an option whose id, name, or kind contains `always`. A card timeout or a cancel is `reject-once` and is not a host failure.

A host failure fails the turn closed and writes one audit row with source `host`: the process exits before a result, the handshake or prompt cannot be completed, the session mode is not default, the user message is a slash command, the permission request is malformed or for another session, the broker returns an error, no acceptable allow-once or reject-once option remains, or the turn context ends while the protocol is still waiting. When the person denies the permission card, the tool record is stored not ok with result `denied`. A denial does not end the run. The model keeps the result and the run stays `done`, on Grok, Claude, and Ollama, including a policy deny and a user-rule deny. Only an explicit stop stores `cancelled`. A row stored earlier may still display "Stopped after denial." A timeout or a cancel still ends the run. There is no MCP host for Grok. Claude's `ErrPermissionPrompt` path is unchanged when the broker hook is off.

Hardened setups should pin the Grok binary with `sha256` on the `tools.cli` pin (`backend = "grok"`, an absolute `path`, and 64 hex digits). The version gate trusts the text `grok --version` prints and allows only 1.0.52 and 1.0.62. The pin is compared before `--version`. A mismatch refuses the turn and does not run the binary. See `docs/cli-isolation.md`.

## Stored decisions

Every broker decision, from any transport and including `permission_denials`
on a Claude result, is also written to `run_tools` as `kind: "permission"`
with the tool, redacted arguments, and `{decision, source, rule, transport}`.
Grok rows use `transport: acp`. A user-rule decision also stores `rule_id`,
`classification`, `sensitivity`, and `risk` on that row. A host failure is
`decision: deny`, `source: host`.
The reply's tool summary shows them after a reload. Each request has exactly one record: `ok` is true for
`allow`, `allow_once`, `allow_session`, and `answer`. A question record also stores `kind` and `answered`, not the answer text. A CLI-side denial report
(`permission_denied` or `result.permission_denials`) adds a record only when
the broker did not already decide that request; it is matched by
`tool_use_id`, else by tool and redacted arguments, else (for a report that
names only the tool) by tool. A second answer to an answered or timed-out
request returns 409 and records nothing. Launch isolation, which
keeps workspace and user CLI config from adding allow rules, is in
`docs/cli-isolation.md`.

## Audit and redaction

Secret-looking keys (`token`, `secret`, `password`, `api_key`, `authorization`, `credential`, `bearer`) and values are redacted before the event and the audit line, including inside nested maps, slices, and error strings. Value shapes are Anthropic keys (`sk-ant-…`, including later hyphen and underscore segments), other `sk-…` keys, xAI keys (`xai-…`), `ghp_…`, `github_pat_…`, `lgbr_` run tokens, 64-hex admin and API tokens, and bearer tokens. Booleans, numbers, and null stay their JSON types. Assistant text is redacted as it streams; a key split across deltas is held until it completes, then flushed. CLI stderr is redacted before it is published or logged. The `updatedInput` sent back to Claude, over MCP or `stream_control`, is not redacted.
