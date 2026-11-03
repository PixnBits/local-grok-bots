# Bot-page warning fields

## Goal

Bot warnings from `/api/bots` and `/api/bots/{id}/state` are objects with a field, text, and an optional link. The profile shows each one under the setting it describes. Copy and the token-owner check match the design review.

Wrong if proxy, netbridge, cache, or audit behaviour changes, if `web/` gains an `http://` or `https://` literal, if a config warning says saving still works, or if a file owned by someone else is reported as a mode or permission problem.

## Decisions

- `store.Warning` is `{field, text, link?}`. Fields are `description`, `net_allow`, `github_allow`, and `github_token`. An empty list is omitted.
- The broad-host link is `{href, label}` from the API. The page renders an anchor only when the parsed host is `github.com` and the path starts with `/PixnBits/local-grok-bots/`.
- Description warnings keep their sentences. The profile adds " Saving still works." only for those. Config warnings and the state sheet do not.
- Token owner is checked from `Lstat` before open, using the existing uid seams. `tokenCheck` still replaces that decision. The daemon account name is looked up once.
- Nav warning counts and a single token banner on the bot list are out of scope.

## Tests

- Field and exact sentence for one missing repo, several missing repos, an empty ceiling, and each token reason.
- Other-owner mode `0644` yields the owner reason. The owner warning names `chown`.
- Broad-host link object, and no saving sentence on config warnings.
- Page ids, `role="note"`, the hidden "Warning:" prefix, link attributes, accent link colour, and the 44px rule.
