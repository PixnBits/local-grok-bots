# Permission UI and fail-closed prompts

The broker already decides tool calls. This slice renders those decisions in the stock page and stops treating every stream client as someone who can answer.

## Decisions

- The run stream URL gains `prompts=1` only from a page that can post a decision. The broker's UI check counts those subscribers. Any other subscriber leaves the run with no UI, so canUseTool denies at once with source `no_ui` and does not publish `permission_request`.
- The card shows the tool name and the arguments exactly as the server sent them. It posts `allow_once`, `deny`, or `allow_session` (the last only when `session_allowed` is true). A `permission_decision`, or the deadline hitting zero, disables the card and shows the decision and source. Untrusted fields use `textContent`.
- Claude gets the MCP prompt tool only when `ui_prompts` is on and the daemon has an HTTP base. Otherwise the turn passes `--permission-prompts none` and does not attach the prompt tool. Residual denials are audited as `no_ui` when prompts are off, and as `policy` when prompts are on but there is no host. A denial while a host is attached stays source `cli`.

## Out of scope

- Pushing, `main`, systemd units, and ports 8080 and 8090.
- A Grok ACP client.

## Tests

- A plain stream subscriber is not a prompt UI. `prompts=1` is, and disconnect clears it. An older stream fails closed as `no_ui`.
- `--permission-prompts none` is set, and the prompt tool is not, when `ui_prompts` is off or the HTTP base is empty. The audit source is `no_ui` or `policy`.
- The page source handles `permission_request` and `permission_decision` and does not write untrusted values with `innerHTML`.
