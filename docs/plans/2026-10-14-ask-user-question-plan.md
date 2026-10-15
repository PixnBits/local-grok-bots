# AskUserQuestion

Claude sends the built-in `AskUserQuestion` tool through `canUseTool`. The allow/deny card cannot collect an answer. The host must return `behavior: allow` with `updatedInput` equal to the original input plus `answers`.

Wire shape: `@anthropic-ai/claude-agent-sdk` 0.3.300 `sdk-tools.d.ts` (`AskUserQuestionInput`, `AskUserQuestionOutput`). Answer keys are the full question text. Multi-select values are labels joined by `", "`. Free text ("Other") is the typed string. A deny tells Claude `The user did not answer the question (<reason>).`

## Decisions

- Tool match is case-sensitive and is only `AskUserQuestion`. Hooks, then deny rules, still win. Nothing else auto-allows it (not bypass, allow rules, hook allow, or a session grant).
- Malformed input is a deny plus one audit record. No card.
- `POST .../permissions/{id}` accepts `{"decision":"answer","answers":{...}}` and optional `annotations`. `allow_once` on a question, or `answer` on any other request, is 400. A second decision is 409. A live lgb token or MCP permission token is 403 on this route only. The admin token (Bearer or cookie) still decides.
- Both transports send the same allow or deny body. Answer values in the audit are redacted. The payload back to Claude is not.
- ExitPlanMode stays a normal allow/deny card and shows `input.plan` when it is a string. MCP elicitation is not implemented (error response, no form). `requiresUserInteraction` is not on the wire, so it stays a normal tool check. Grok headless prompts still fail the turn.

## Tests

- Broker: deny wins, bypass does not allow, malformed denies, answer validation, timeout message, redacted audit.
- Fake CLI, mcp and stream_control: one label, multi-select, free text, timeout deny, second answer 409, run token 403. Exact `updatedInput` JSON.
- Web: question card uses `textContent`, posts `answer`, Skip posts `deny`.
