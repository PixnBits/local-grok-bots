# E2E broker fixes

Goal: a classifier cannot lower an unclassified command, the advisory source matches the final level, a task approval still allows one identical retry after the next user message, and the queue/rules page matches the visual pass.

Wrong if a model reply of low or medium replaces unclassified, a path-critical command keeps a "raised to low" source, a task approval dies on the next user message, critical or compound becomes a bot rule, or card titles show model text.

## Backend

- `classifierRaises`: unclassified ranks with medium. Only a strictly higher friction level replaces the table level. Used by `LocalClassifier.Escalate` and `inspectSnap`.
- Path rules run before that choice. Source is "local model raised this to {level}" only when that level is the final level.
- Approve with task, bot, or global also stores the once-token (after a rule save, which clears tokens).

## Web

- Title from `critical_reason` or a plain tool title. Advisory text stays in the Advisory block. Table source copy names the level.
- Hide `#approvals-banner` when it has no text.
- Notification pre-prompt stacks: icon and title, body, buttons.
- Rules title stays a heading; programmatic focus draws no box.
- Task text collapses whitespace when rendered and when stored.
- Queue subtitle and Rules link. Risk rows say All bots, with the tool kind under the match.
