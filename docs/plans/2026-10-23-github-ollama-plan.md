# GitHub PRs from Ollama bots

Spec: docs/github.md. Review overrides win where they differ.

## Decisions

- Token file is root-owned, mode 0600, not a symlink, at most 4096 bytes, one line. The daemon reads it on the host. A bad owner, mode, or read fails closed. Tests replace the file inspect with an unexported hook. A non-root daemon is out of scope.
- `github_allow` empty or omitted allows no repositories. It does not inherit the policy list.
- Managed `[github].repos` is the ceiling. Local policy only narrows it (intersection). A bad `[github]` value disables GitHub and warns.
- Every `git push` and `create_pr` shows the approval card. `Request.ForceAsk` is honored ahead of hook allow, bypass, managed allow, durable user allow, and session grant. Deny rules still deny. `ui_prompts` off denies.
- Default-branch pushes, force (`+` refspec, `--force`, `--force-with-lease`, `--force-if-includes`, `-f`), tags, and branch deletes are hard-denied before `Evaluate`.
- The token is never mounted, never placed in the jail environment or argv, and never written to logs, tool results, events, or audit.

## Units

- U1 Policy `[github]` and `policy.toml.sample`.
- U2 Store `github` grant, `github_allow` column, profile checkbox and field.
- U3 Host reverse proxy (COI style) for `github.com` and `api.github.com`, allowlisted paths only.
- U4 Splice proxy refuses those hosts. Clone and fetch of allowlisted repos use the injecting proxy.
- U5 `edit_file`, `delete_file`, and `read_file` / `write_file` on the safedir walk. `CheckWrite` stays.
- U6 Commit author from policy, charset-checked before the wrapper script is generated.
- U7 Live push socket, host-side rebuild, hard denies, `ForceAsk`, host push.
- U8 `create_pr` and `pr_status`. API base URL overridable in tests.
- U9 Prompt and tool text.
- U10 Audit every allow and deny. Update docs/github.md.

## Out of scope

Non-root daemon, other forges, Grok and Claude backends, voice, deploys, ports 8080/8090/8095, pushing this branch.
