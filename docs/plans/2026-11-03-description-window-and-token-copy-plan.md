# Description window and token copy

## Goal

`descriptionWarnings` must not panic when a tool-like name sits near the end of a description, including on `GET /api/bots`. Token warning sentences match the new copy. Missing and mode sentences stay as they are.

Wrong if a match with `use ` or `tool` nearby stops warning, if production code recovers from the panic, if `internal/github` gains a reason string, or if deploy, cmd, web, proxy, netbridge, cache, or audit code changes.

See `docs/solutions/description-warning-window-bounds.md` for the window clamp.

## Decisions

- The window end is `idx + len(strings.ToLower(name)) + 40`, clamped to the lowered description. The start is clamped to 0. A start past the end skips that name.
- Size copy uses the `Lstat` size already stored on the warning stat. `0` and an unknown size say the file is empty. A size above `0` says it is too big.
- Other token reasons keep their reason strings. Only the sentence changes.

## Tests

- Table of descriptions that used to panic, with a recover per row. `use ` or `tool` next to the name still warns.
- List, get, state, and description patch for a snake-case description, a camelCase description, and a plain one.
- Exact token sentences, including both size cases. Owner text includes `sudo chown`. Denied text does not say `chown` or `root`. An empty file and a 5000-byte `0600` file take the two size sentences.
