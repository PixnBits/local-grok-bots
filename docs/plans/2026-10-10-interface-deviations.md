# Interface deviations

Target is `docs/PRD.md` and `docs/specs.md`. README is the starting point.

## Decisions

- `description` replaces `instructions` in the store and the API. Writes still accept `instructions` when `description` is absent.
- `label` is display only. `description` is the standing prompt.
- `mark` is `{shape, color}` with shapes circle, square, diamond, triangle, hex and a `#rrggbb` color. It has no behavior.
- `pinned` and `hidden` are roster flags on the bot so a refresh reloads them. Hide and pin do not change `status` and do not change timer `enabled`.
- Duplicate copies the profile (name, label, description, mark, model) and routines. It does not copy the thread or memory.
- An inbound DM stays on the `dm:` thread. The receiving user thread also gets a system message `Message from {name}`.
- The run loop emits SSE `status` (`working`, or the tool name). The page clears the animation on `done` or `error`.
- Bot-level pause stays off the conversation. Routine pause is the profile toggle.

## Out

Computer-use, channels, templates, documents, links, notifications, voice, and any change to the workspace jail.
