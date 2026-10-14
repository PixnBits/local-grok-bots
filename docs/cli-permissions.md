# CLI permission approvals

A headless CLI turn used to fail with `permission prompt requires a TTY or an explicit permission_mode` as soon as the CLI asked for a tool. The daemon is now the permission host for Claude. Grok stays on policy flags only. A raw permission prompt with no host still fails the turn.

The stock web page does not render these prompts. It subscribes to the run stream and ignores events it does not know. Turning `ui_prompts` on while that page is open counts as a connected UI and holds the tool until the prompt times out.

## Policy

`[cli.permission]` (and the older `[cli].permission_mode`) sets:

| Field | Meaning |
|---|---|
| `mode` | Passed to the CLI as `--permission-mode`. Empty leaves the CLI's own default. |
| `allow` | Tool rules that allow without a prompt, such as `Read` or `Bash(git status*)`. |
| `deny` | Tool rules that deny. |
| `ask` | Tool rules that always go to the host, even when a later allow rule or a bypass mode would allow them. |
| `ui_prompts` | When true, a connected UI may answer a residual ask. Default false. |
| `prompt_timeout` | How long the host waits. Default 60s. A non-positive value is 60s. |
| `allow_session_grants` | Lets a UI answer `allow_session`. Honored only from the managed policy file. |

Precedence is unchanged: managed settings, then `policy.toml`, then defaults. A missing or unparseable file still fail-closes (daemon jail on, CLI backends off).

Always-allow modes are `always`, `always-allow`, `always_allow`, `always-approve`, `bypass`, `bypassPermissions`, `dontAsk`, and `dont-ask`. A user policy file that sets one of those, or `allow_session_grants = true`, is stripped. The daemon logs a warning and leaves the previous non-bypass mode in place. The same keys in the managed file are kept. `dontAsk` is an always-allow alias here because the existing Grok path maps it to `--always-approve`. `acceptEdits` and `plan` are ordinary modes: they are passed through to the CLI and do not auto-allow inside the broker.

## Broker

`internal/permission.Broker` evaluates one tool call in this order. A deny stops the check. A hook allow does not skip deny or ask rules.

1. Hooks, in registration order. A hook may return `deny`, `ask`, or `allow`.
2. Deny rules.
3. Ask rules. An ask forces the UI path even in a bypass mode.
4. A hook allow, if one was recorded and no deny or ask fired.
5. Bypass mode, only when the resolved mode is an always-allow mode. The daemon copies that mode onto the CLI only when managed policy set it.
6. Allow rules.
7. An in-memory session grant for this bot and session.
8. canUseTool: publish `permission_request` and wait, or deny.

Rules match the tool name, with an optional argument glob in parentheses: `Bash(git status*)`. `*` and `?` are globs. The tool name is case-insensitive. The argument text is case-sensitive and comes from `command`, `cmd`, `file_path`, `filePath`, or `path`. The pattern is anchored to the whole string.

canUseTool denies with source `no_ui` when `ui_prompts` is off or no SSE subscriber is on that run. It does not publish `permission_request` in that case. Otherwise it publishes and waits for `Decide`. Timeout, context cancel, an unknown id, and a daemon restart deny. Pending requests live only in memory. `allow_session` is rejected and the request stays pending when managed policy did not allow session grants. A grant is stored per bot and session (or per run when the session id is empty) and is checked after allow rules, so a later deny or ask still wins.

Each decision emits `permission_decision` and, when audit is on, one audit record: `source` (`policy`, `hook`, `ui`, `timeout`, `no_ui`, `cancel`, or `cli`), the rule that matched, tool, redacted arguments, bot, run, time, and decision. Arguments go through `audit.RedactValue` (the same redactor the daemon uses for tool payloads). The allow payload sent back to Claude keeps the original arguments so the tool still runs.

`POST /api/bots/{id}/runs/{run_id}/permissions/{req_id}` with `{"decision":"allow_once"|"deny"|"allow_session"}` calls `Decide`. The request must belong to that bot and run. Bearer auth still applies to this route.

## Claude

When the backend is Claude, `ui_prompts` is on, and the daemon knows a non-zero HTTP base, the turn gets a random token and these flags:

- `--permission-mode` from policy, when set
- `--allowedTools` / `--disallowedTools` from allow and deny rules
- `--mcp-config` with an inline HTTP MCP server named `lgbperm`
- `--permission-prompt-tool mcp__lgbperm__approve`

Ask rules are broker-only. Claude has no matching flag, so an ask applies when Claude calls `approve`. A deny rule is also `--disallowedTools`, so Claude can refuse before the prompt tool.

`POST /api/mcp/permission/{token}` is the MCP endpoint. The token is the credential; the route does not use the daemon Bearer token. It speaks a small JSON-RPC subset: `initialize`, the `notifications/initialized` notification, `ping`, `tools/list`, and `tools/call` for `approve` with `{tool_name, input, tool_use_id}`. An allow returns text content `{"behavior":"allow","updatedInput":{...}}`. A deny returns `{"behavior":"deny","message":"..."}`. `updatedInput` is the original input object (or `{}`).

`permission_denied` system events and `result.permission_denials` are parsed as `permission_decision` with source `cli` and audited. They do not fail the turn. A headless prompt phrase with no host still fails closed.

The token is dropped when the turn ends. A bind address of `:0` has no stable base URL, so tests that use `httptest` set the base to the server URL.

## Grok

`grok agent stdio` speaks ACP. A full client would implement `initialize`, `authenticate`, `session/new`, `session/prompt`, and `session/request_permission`, then pick the allow or reject option id from that request. That client is not in this branch.

Grok stays on `grok -p` with policy flags:

- `--allow` and `--deny` from the allow and deny rules
- `--permission-mode` for a non-bypass mode
- `--always-approve` only when managed policy set a bypass mode, and not together with `--permission-mode`

A headless permission prompt is still a deny: the turn fails with `ErrPermissionPrompt`. There is no MCP host and no UI round trip for Grok.

## Audit and redaction

Secret-looking keys (`token`, `secret`, `password`, `api_key`, `authorization`, `credential`, `bearer`) and values (`sk-…`, `ghp_…`, `github_pat_…`, bearer tokens) are redacted before the event and the audit line. The MCP `updatedInput` is not redacted.
