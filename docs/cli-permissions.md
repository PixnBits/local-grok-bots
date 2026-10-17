# CLI permission approvals

A headless CLI turn used to fail with `permission prompt requires a TTY or an explicit permission_mode` as soon as the CLI asked for a tool. The daemon is the permission host for Claude. `cli.permission.claude_transport` selects that host: `mcp` (the default), `stream_control`, or `none`. Grok stays on policy flags only. A raw permission prompt that is not covered by a host or by `--permission-prompts none` still fails the turn.

The stock page subscribes to the run stream with `?prompts=1` and renders `permission_request`. With `ui_prompts` on, a request waits whether or not any page is attached to that run: the bot does not have to be the open tab. It stays pending until it is answered, the run ends (`cancel`), or `prompt_timeout` passes (`timeout`, deny). `GET /api/bots/{id}/permissions` (and `GET /api/permissions` for every bot) lists open requests with the same payload as `permission_request`, so a page that opens later shows and answers them. `GET /api/bots` carries `pending_permissions` per bot, and the bot list shows a "needs approval" badge. A live run token (lgb or the MCP permission token) cannot read these lists or decide a card.

## Policy

`[cli.permission]` (and the older `[cli].permission_mode`) sets:

| Field | Meaning |
|---|---|
| `mode` | Passed to the CLI as `--permission-mode`. Empty leaves the CLI's own default. |
| `allow` | Tool rules that allow without a prompt, such as `Read` or `Bash(git status*)`. |
| `deny` | Tool rules that deny. |
| `ask` | Tool rules that always go to the host, even when a later allow rule or a bypass mode would allow them. |
| `ui_prompts` | When true, a residual ask waits for an answer from the page (any tab, now or later) until `prompt_timeout`. Default false, which denies at once with source `no_ui`. |
| `prompt_timeout` | How long a permission or question card waits. Default 10m. A managed `max_prompt_timeout` caps it. See Timeouts in `docs/cli-isolation.md`. |
| `allow_session_grants` | Lets a UI answer `allow_session`. Honored only from the managed policy file. |
| `claude_transport` | `mcp` (default), `stream_control`, or `none`. Empty is `mcp`. Any other value is a config error, and load uses the existing fail-closed fallback (daemon jail on, CLI backends off). |

Precedence is unchanged: managed settings, then `policy.toml`, then defaults. A missing or unparseable file still fail-closes (daemon jail on, CLI backends off).

Always-allow modes are `always`, `always-allow`, `always_allow`, `always-approve`, `bypass`, `bypassPermissions`, `dontAsk`, and `dont-ask`. A user policy file that sets one of those, or `allow_session_grants = true`, is stripped. The daemon logs a warning and leaves the previous non-bypass mode in place. The same keys in the managed file are kept. `dontAsk` is an always-allow alias here because the existing Grok path maps it to `--always-approve`. `acceptEdits` and `plan` are ordinary modes: they are passed through to the CLI and do not auto-allow inside the broker.

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
11. An in-memory session grant for this bot and session.
12. canUseTool: publish `permission_request` and wait, or deny.

Rules match the tool name, with an optional argument glob in parentheses: `Bash(git status*)`. `*` and `?` are globs. The tool name is case-insensitive. The argument text is case-sensitive and comes from `command`, `cmd`, `file_path`, `filePath`, or `path`. The pattern is anchored to the whole string.

canUseTool denies with source `no_ui` only when `ui_prompts` is off. It does not publish `permission_request` in that case. Otherwise it publishes, lists the request in `Pending`, and waits for `Decide`, whether or not a page is attached. The page shows the tool name, the arguments as sent (already redacted), a countdown to `deadline`, and posts `{"decision":"allow_once"|"deny"|"allow_session"}` to the route above. `allow_session` is offered only when `session_allowed` is true. A question (`kind: "question"`) is a different card: header, question text, options, an Other field, Submit, and Skip. Submit posts `{"decision":"answer","answers":{...}}`. Skip posts `deny`. Claude's message for that Skip is `The user did not answer the question (skipped).` A `permission_decision`, or the countdown hitting zero, disables the card and shows the decision and source. Timeout, context cancel, an unknown id, and a daemon restart deny. Pending requests live only in memory. `allow_session` is rejected and the request stays pending when managed policy did not allow session grants. A grant is stored per bot and session (or per run when the session id is empty) and is checked after allow rules, so a later deny or ask still wins.

Each decision emits `permission_decision` and, when audit is on, one audit record: `source` (`policy`, `hook`, `ui`, `user`, `timeout`, `no_ui`, `cancel`, or `cli`), the rule that matched, tool, redacted arguments, bot, run, time, decision, and `transport`. A user-rule decision also stores `rule_id`, `classification`, `sensitivity`, and `risk`. A question adds `kind`, `answered`, and redacted `answers` on the audit record. The SSE decision carries `kind` and `answered` and omits the answer text. Arguments go through `audit.RedactValue` (the same redactor the daemon uses for tool payloads). The allow payload sent back to Claude keeps the original arguments so the tool still runs.

`transport` is the wire actually used, not a second copy of the policy string. `stream_control` is stamped for every decision on that transport, including a broker `no_ui` deny. `mcp` is stamped only when the HTTP prompt tool is attached. `none` is stamped when the turn passes `--permission-prompts none`: the policy value `none`, or `mcp` with `ui_prompts` off or with no HTTP base. The approval card ignores the field.

`POST /api/bots/{id}/runs/{run_id}/permissions/{req_id}` accepts `{"decision":"allow_once"|"deny"|"allow_session"}`, or `{"decision":"answer","answers":{...}}` with optional `annotations` for a question. The request must belong to that bot and run. `answer` on any other request, or `allow_once` or `allow_session` on a question, is 400 and leaves it pending. A free-text answer longer than 4 KiB is 400 and leaves the question pending. A second decision is 409. A live `lgbr_` token or MCP permission token is 403 on this route. The admin token, as a Bearer or the `lgb_auth` cookie, still decides. Other routes return 401 for a run token.

## Durable user auto-grants and analysis

The existing allow/ask/deny rules and session grants are the foundation. This layer reduces prompt toil for repeated low-risk patterns while keeping the user (and a CISO) in control.

### First pass

Durable rules are rows in `user_perm_rules`, one bot at a time, permanent until revoked. Project scope and time bounds are not implemented. Session grants stay managed-only and in memory.

A user allow is stored only when the pattern is a known low-risk read-only shape (`Bash(gh pr view *)`, `Bash(git status*)`, `Read(./src/**)`). Ask and deny are stricter and do not have to be read-only. At decision time the broker classifies the concrete call again and auto-allows only when that call is still low-risk read-only. Shell composition, redirects, network commands, credential paths, and writes fall through to ask or deny. Managed deny, managed ask, and managed bypass are unchanged and win over a user allow. A user deny or ask is applied before managed allow and bypass.

Accepting or revoking a rule is a `user_perm_rule` log event with the exact pattern and the risk label shown at acceptance time. The same action writes `DATA_DIR/cli/<bot>/user-permissions.json` (Claude `permissions.allow` / `permissions.deny`, plus `lgbAsk` because neither CLI has an ask flag) and `grok-permission-rules`. Those files are not passed as `--allowedTools` or `--allow` on the isolated bot turn. The permission host stays attached, the broker decides, and the audit / `run_tools` record includes `rule_id`, `classification`, `sensitivity`, and `risk`. Loading the native allow list into the bot turn would let the CLI allow before the host and drop that record. Copy the generated file when running the CLI outside the bot.

Suggestions are static only. There is no local-model second pass. `POST /api/bots/{id}/permission-suggestions/analyze` clusters logged `kind: "permission"` rows. The same clustering runs after 3 similar requests. Mixed or deceptive clusters are stored as refused and cannot be accepted until the pattern is edited into an eligible allow. Nothing is applied without an explicit accept. The profile page lists rules and suggestions.

### What the code does

A durable rule is one bot, one tool name, and an optional argument glob (`Bash(git status*)`, `Read(./src/**)`, `Bash(*push*)`). It lasts until it is revoked. There is no project scope and no time bound. Session grants stay managed-only and in memory.

An allow is stored only when `CheckUserRule` accepts it. Ask and deny are stored when the shape is well formed, including patterns that are not read-only. At decision time `ClassifyCall` runs again. A user allow applies only when that call has `AutoAllow`. A stored pattern that would match a wider command does not widen the call.

`AutoAllow` is only a low-risk read-only call inside the bot workspace:

- Bash, and only these binaries: `git` with `status`, `log`, `diff`, `show`, `rev-parse`, `blame`, `ls-files`, `describe`, `shortlog`, or `version`; `gh` with `pr view`, `pr diff`, `pr list`, `pr checks`, `pr status`, `issue view`, `issue list`, `repo view`, `run view`, or `run list`; `cat`, `ls`, `head`, `tail`, `wc`, `pwd`, `stat`, `file`, `grep`, `rg`, or `find`.
- Read tools `read`, `grep`, `glob`, and `ls`, for a project path.

These are never `AutoAllow`, even when a glob matches:

- Shell composition. Unquoted `\`, `;`, `|`, `&`, `<`, `>`, `` ` ``, `$`, newline, or CR, and `$`, `` ` ``, newline, or CR inside double quotes. `Bash(git status*)` therefore does not allow `git status; rm x` or `git status > /etc/x` or `git status > notes.txt`. Characters inside single quotes are literal. A glob `*` is `.*` and does not match a newline; a command that contains a newline is still not auto-allowed.
- `git` `--output` or `--output=`, including `git diff --output=notes.txt`.
- `find` with `-delete`, `-exec`, `-execdir`, `-ok`, `-okdir`, `-fls`, `-fprint`, `-fprintf`, or `-fprint0`.
- Network binaries: `curl`, `wget`, `ssh`, `scp`, `sftp`, `nc`, `ncat`, `netcat`, `ping`, `dig`, `nslookup`, `npm`, `npx`, `yarn`, `pnpm`, `pip`, `pip3`, `gem`, `apt`, `apt-get`, `brew`, `docker`, `kubectl`, `helm`, `aws`, `gcloud`, `az`, `rsync`, `ftp`, `telnet`, `socat`. Git `fetch`, `pull`, `clone`, and `ls-remote`. Tools `webfetch` and `websearch`.
- Irreversible binaries: `rm`, `rmdir`, `dd`, `mkfs`, `shred`, `sudo`, `doas`, `su`. Git `push`, `reset`, and `clean`.
- Write binaries: `tee`, `mv`, `cp`, `install`, `mkdir`, `touch`, `truncate`, `ln`, `chmod`, `chown`, `chgrp`, `sed`, `tar`. Tools `edit`, `write`, `multiedit`, and `notebookedit`.
- A path segment `.ssh`, `.aws`, `.gnupg`, `.netrc`, `.kube`, `.azure`, `.docker`, `.grok`, `credentials`, `credentials.json`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `auth.json`, `admin-token`, `policy.toml`, `.git-credentials`, `.npmrc`, `.pypirc`, `cookies`, `.env`, `.env.*`, `*.pem`, `*.key`, `state.db`, `state.db-*`, `user-permissions.json`, or `grok-permission-rules`. That includes `~/.grok/config` and a copy of those names inside the workspace.
- A path outside the bot workspace, including home and system paths. `DATA_DIR` is not a separate input; an absolute path that is not inside the workspace fails the same way.

Anything that is not one of the read-only shapes above also fails closed.

Managed deny, managed ask, and a managed bypass mode still win over a user allow. A user deny and a user ask are applied before managed allow and before bypass. The rules that become `--allowedTools`, `--disallowedTools`, `--allow`, or `--deny` are the policy rules (plus the `lgb` and `coi` spool allows). A user rule is not copied onto those flags and is not copied into the turn's `claude-settings.json` allow list. A user settings file cannot add an allow either; that merge is unchanged.

The broker runs on the Claude permission host (`mcp` and `stream_control`). Grok stays on policy flags. A Grok tool call is not sent through this broker, so a durable allow does not auto-allow it. A Grok permission prompt still fails the turn.

Accept and revoke write a `user_perm_rule` log event with the pattern and the risk label. The same action writes `DATA_DIR/cli/<bot>/user-permissions.json` (Claude `permissions.allow` and `permissions.deny`, plus `lgbAsk`) and `grok-permission-rules` (allow and deny lines; ask lines are comments). The directory is created with a no-follow walk from `/`. A symlink in any component, including the file name, is refused and not followed. The bytes go to a sibling opened with `O_CREAT|O_EXCL|O_NOFOLLOW` and renamed into place. On macOS the walk crosses `/tmp`, `/var`, and `/etc` only when that link points under `/private`. The bot turn does not load either file. Copy them when running the CLI outside the bot.

On Linux the Grok jail bind-mounts the workspace, the bot home, and `GROK_HOME`. The two rule files sit beside `home` and `grok-home`, and they are not mounted. Grok does not need to read them. When a rule file exists as a regular file at turn start, the Grok `lgb` deny list names it, and Claude settings deny `Read` and `Edit` of that path. `DATA_DIR/cli` is still expanded around the bot home, because denying the whole directory would make Grok's own home read-only. A file created after that profile is written is absent from that turn's Grok deny list. A symlink at the rule-file name is not added to the deny list, because the deny must not follow it; the writer refuses to replace that symlink.

Suggestions are static. `POST /api/bots/{id}/permission-suggestions/analyze` clusters logged `kind: "permission"` rows and keeps a card at count 1. The same clustering runs after 3 similar requests (`SuggestAfter`). An eligible card's summary is `{count} prior {pattern} requests, all classified {kind} / {sensitivity}. Suggest permanent allow? Risk: {risk} ({reason}).` A mixed cluster is `{count} prior requests look like {pattern} but at least one is a write, a redirect, or a sensitive path. Classification refused auto-allow.` A refused card cannot be accepted until the pattern or effect is changed; the same pattern with effect allow is 400. Nothing is applied without an explicit accept.

The profile page lists each rule with its effect, pattern, risk, and reason, and a Revoke button. Suggestions show an editable pattern, the summary, and examples, with Accept and Dismiss. A separate form posts effect and pattern. Analyze posts the analyze route. There is no edit of an accepted rule other than revoke and add.

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

`grok agent stdio` speaks ACP. A full client would implement `initialize`, `authenticate`, `session/new`, `session/prompt`, and `session/request_permission`, then pick the allow or reject option id from that request. That client is not in this branch.

Grok stays on `grok -p` with policy flags:

- `--allow` and `--deny` from the allow and deny rules
- `--permission-mode` for a non-bypass mode
- `--always-approve` only when managed policy set a bypass mode, and not together with `--permission-mode`

A headless permission prompt is still a deny: the turn fails with `ErrPermissionPrompt`. There is no MCP host and no UI round trip for Grok.

## Stored decisions

Every broker decision, from any transport and including `permission_denials`
on a Claude result, is also written to `run_tools` as `kind: "permission"`
with the tool, redacted arguments, and `{decision, source, rule, transport}`.
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
