# Audit log

`audit_log` is empty by default. The daemon then writes no audit lines. The existing store log and the human-readable startup lines stay as they are.

Set `POLICY_AUDIT_LOG` or `audit_log` in the policy file to one of:

- `stderr`, one JSON object per line on the daemon's standard error
- `syslog`, the local syslog daemon, tag `local-grok-bots`
- an absolute file path, created mode `0600` and appended

A relative path, or a sink that cannot be opened, fails startup. The file wins over the environment.

Each line is one JSON object. `ts` is UTC RFC3339. String fields are redacted: a proxy URL loses its userinfo, and `XAI_API_KEY`, `ANTHROPIC_API_KEY`, `SSH_AUTH_SOCK`, `AUTHORIZATION`, and `PROXY_AUTHORIZATION` assignments are replaced with `redacted`. Prompts are not written.

| event | fields |
| --- | --- |
| `cli_start` | `pid`, `backend`, `session_id`, `cli_network` |
| `cli_stop` | the same fields, plus `result` of `ok`, `error`, or `interrupted` |
| `net_decision` | `action` `allow` or `deny`, `grant`, `host`, `port` when known, `detail` |
| `grant` | `action` `allow` or `deny`, `grant`, `detail`. This is a grant that is not a network decision, such as git. A `cli_ro_bind` grant has `detail` `<path> read-only`. |
| `dlp` | `action` `deny`, `detail` a short reason such as `dlp: blocked by pattern`. The prompt is not included. |

`cli_network` is `open`, `proxy`, `explicit-proxy`, or `none`. A network allow lists the destination host, not a corporate proxy password. `detail` may say `via host:port` or `direct`.
