# CLI permission host

Headless CLI turns currently die with `ErrPermissionPrompt` when the CLI asks for approval. This plan adds a daemon-side permission host. A raw prompt with no host still fails closed.

## Decisions

- Tool checks run in this order: hooks, deny rules, ask rules, permission mode, allow rules (including in-memory session grants), then canUseTool. A deny from a hook or a deny rule stops the call. An ask rule still prompts when the mode would otherwise allow.
- Bypass and always-allow modes, and `allow_session_grants`, apply only when the managed policy sets them. The user policy file cannot enable them.
- canUseTool publishes `permission_request` and waits only when `ui_prompts` is on and an SSE subscriber is present. Timeout, cancel, a missing UI, an unknown id, and a daemon restart deny. Pending requests are memory only.
- Claude is given `--mcp-config`, `--permission-prompt-tool mcp__lgbperm__approve`, `--allowedTools`, `--disallowedTools`, and `--permission-mode`. The daemon answers the MCP `approve` tool on `POST /api/mcp/permission/{token}`.
- The UI answers with `POST /api/bots/{id}/runs/{run_id}/permissions/{req_id}`. The id must belong to that bot and run. `allow_session` is rejected unless managed policy allows it.
- Grok stays on `grok -p`. Flags are `--allow`, `--deny`, `--permission-mode`, and `--always-approve` only for a managed bypass mode. ACP `session/request_permission` is documented as a gap, not implemented.
- `permission_denied` stream events and `result.permission_denials` are audited as `permission_decision` with source `cli`. They do not fail the turn.
- Args in events and audit records go through one shared redactor (`audit.RedactValue`).

## Out of scope

- Web UI controls that render the prompt and post a decision.
- A Grok ACP client (`initialize`, `authenticate`, `session/new`, `session/prompt`).
- Changing the main branch, systemd units, or ports 8080 and 8090.

## Tests

- User policy strips bypass mode and session grants; managed policy keeps them.
- Broker order, timeout deny, absent UI deny, session grant refused, audit redaction.
- MCP initialize / tools/list / tools/call, then the decide endpoint.
- A re-exec fake `claude` calls that MCP tool and the HTTP decide endpoint finishes the turn.
