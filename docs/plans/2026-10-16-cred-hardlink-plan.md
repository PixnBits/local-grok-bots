# Grok CLI login stays on the host

Date: 2026-10-16. Branch `fix/cred-hardlink-and-deps`.

## Decision

The Grok CLI backend no longer hardlinks, symlinks, or copies `~/.grok/auth.json` into a bot home. The bot home gets a placeholder login file and `XAI_API_KEY` is the placeholder. A daemon reverse proxy on `127.0.0.1` reads the bearer from the user file and injects it. Path and header rules match the COI proxy. The user file is not refreshed or rewritten.

Loopback TCP is the endpoint because the chat client speaks HTTP, and a sandboxed tool with `restrict_network` cannot connect to a unix socket (that is why `lgb` uses a spool). The CLI process itself is not in a daemon network namespace. A read-only bind inside the CLI sandbox is the fallback only if a live turn cannot reach the proxy.

The user's `auth.json` is on the Grok deny list. Stale hardlinks, symlinks to the real file, and files that contain its key or refresh token are removed on startup and when a bot is deleted. A delete waits out an in-progress placeholder write so the turn cannot put the file back.

The loopback proxy injects the host bearer only when the request presents a per-run secret admitted for that bot turn. That secret is `XAI_API_KEY` and the key in the placeholder `auth.json`. The well-known placeholder is not admitted. A miss, a path outside the allowlist, or a header outside the forward list is rejected. A rejected request does not read the host bearer for injection. The secret is dropped when the turn ends.

## Tests

- After `PrepareIsolation`, the real file's link count is 1 and the bot file is not a symlink or the same inode.
- Startup scrub removes a planted hardlink, symlink, and content copy, and leaves a placeholder.
- Bot delete leaves no `auth.json` under that bot's cli home.
- The proxy listens on `127.0.0.1`, rejects a non-allowlisted path, and replaces only an admitted per-run bearer. A missing, shared, or revoked bearer is 403 and does not reach upstream.

## Out

Pushing. Installing packages. Changing `~/.grok`. Printing secret values.
