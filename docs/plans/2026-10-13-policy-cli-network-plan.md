# CLI network policy

The open CLI network from the CISO pass is now a Policy setting. The default stays open, so a daemon with no policy file keeps today's Ollama and CLI behavior.

## Decisions

- One `Policy` is loaded at startup. CLI launch, the shell net grant, and build binds read it. They do not keep a second copy of those rules.
- Precedence is the policy file, then environment, then defaults. `POLICY_FILE` names the file. When that variable is unset, `DATA_DIR/policy.yaml` is used if it exists. A missing default file is fine. A named file that cannot be read, or a file the parser rejects, fails startup.
- Defaults match the current product: `grok` and `claude` are allowed, `cli_network` is `open`, allowlists are empty, `force_local_only` is false. An explicit empty backend list allows no CLI backends.
- `cli_network=proxy` reuses the shell proxy: Linux adds `--unshare-net` and the `LD_PRELOAD` socket; macOS allows only that socket in Seatbelt. `none` drops the network and does not start a proxy. `open` keeps today's jail. A libc program that the interposer misses, or a binary that uses raw sockets, cannot open a direct connection. That fails closed.
- The child still starts from a cleared environment. The jail sets `PATH`, `HOME`, and the locale names. `env_allowlist` may add other variables that are set. `XAI_API_KEY`, `ANTHROPIC_API_KEY`, `SSH_AUTH_SOCK`, and the loader variables cannot be added.
- A bot with the `net` grant and no `net_allow` uses `default_net_allow`. A bot list wins. The store cannot tell an explicit empty list from an unset one, so a non-empty default applies to every net-granted bot that has no hosts. Removing the grant is how that bot loses egress.
- `force_local_only` refuses a non-loopback Ollama URL at startup and refuses CLI backends on a turn.
- `GET /api/policy` returns the loaded policy. It is authenticated like the other routes. Startup logs the same JSON. Values of allowlisted variables are not logged.

## Airgap

```yaml
force_local_only: true
cli_network: none
allow_cli_backends: []
cli_net_allow: []
default_net_allow: []
env_allowlist: []
```

`force_local_only` already disables CLI backends. `cli_network: none` is the setting when CLI backends stay enabled and must not reach the network.

## Out

A policy language, microVMs, MCP, and a second network path beside the existing proxy.
