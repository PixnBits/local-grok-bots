# Policy control and residual risk

The startup Policy is the switch for CLI network, environment, grants, pins, audit, and the prompt check. Defaults still match a single-user machine: `cli_network` is `open`, `grok` and `claude` are allowed, and pins, audit, and the prompt check are off. An airgap file is in the README. This note is what that file changes, and what stays operator-owned.

## Policy-controlled

- `allow_cli_backends` chooses `grok` and `claude`. An explicit empty list allows none. A backend outside the list fails the turn and does not fall through to Ollama.
- `force_local_only` refuses a non-loopback Ollama URL at startup and disables every CLI backend.
- `cli_network` is `open`, `proxy`, `explicit-proxy`, or `none`. `proxy` and `explicit-proxy` send CLI TCP through the existing allowlist proxy. `none` shares no network and starts no proxy. `open` and `none` ignore corporate proxy URLs.
- `cli_net_allow` is the destination host list for those proxy modes. An empty list denies every host. The match is the exact host. A wildcard entry matches only that literal name.
- `http_proxy`, `https_proxy`, and `no_proxy` apply when the mode is `explicit-proxy`, and when the mode is `proxy` and a URL is set. `explicit-proxy` with no URL fails startup. The URL is not copied into the CLI. A password is redacted in the startup log and `GET /api/policy`.
- `env_allowlist` copies extra variables that are set. `XAI_API_KEY`, `ANTHROPIC_API_KEY`, `SSH_AUTH_SOCK`, `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, and the loader variables cannot be added.
- `default_net_allow` fills a shell `net` grant that has no hosts of its own. A bot list wins.
- `build_binds` are the extra read-only paths for the shell `build` grant. A relative path fails startup.
- `cli_pins` checks the resolved CLI binary before exec. No pin checks nothing. A path or SHA-256 miss fails the turn without running the binary.
- `audit_log` copies CLI start and stop, network allow and deny, other grant decisions, and a DLP denial to stderr, syslog, or a file. Empty writes nothing. The schema is `docs/audit.md`.
- `dlp_patterns`, `dlp_file`, and `dlp_command` check a CLI prompt before the process starts. A rejection fails the turn. `dlp_scan_tools` also checks tool-result text before the next CLI round. All of this is off by default.

The shell jail is unchanged: missing grant, missing `bwrap` or `sandbox-exec`, and a denied host still fail closed. The daemon still refuses to run as root.

## Residual

- `open` does not consult `cli_net_allow`. A CLI on the default policy can reach any host its binary chooses, including search, plugin, and update hosts.
- The allowlist is a host, not a host and port. Port 22 still requires the `ssh` grant and the SSH allowlist. Other ports to an allowed host are permitted.
- The corporate proxy is on the CLI dial path. A shell `net` grant still dials the destination directly.
- The interposer sees libc connects. A raw socket is not rewritten. `--unshare-net` on Linux and the Seatbelt profile on macOS still deny that connect.
- A version-only `cli_pins` entry runs `<binary> --version` outside the jail, with `PATH` only. A SHA-256 pin does not execute the file.
- The prompt check does not cover an Ollama turn. A pattern has no separate time limit. The cap is 256 bytes for the pattern and 1MiB for the text. The command runs outside the jail with `PATH` only. Tool output is checked after the local tool has already run. A blank prompt is skipped.
- Audit lines do not include the prompt. A denial is a short reason code. The sink is off until `audit_log` is set.
- The proxy password remains in the daemon process. Logs and `GET /api/policy` show it redacted.
- CLI login files under `~/.grok` and `~/.claude` are the credential. They are mounted into the CLI jail. Policy does not remove them.
- The store cannot tell an explicit empty shell allowlist from an unset one. A non-empty `default_net_allow` applies to every `net` bot that has no hosts. Removing the grant is how that bot loses egress.
- Linux CLI turns need unprivileged user namespaces and the distro `bubblewrap`. The jail always passes `--unshare-user` and never `--disable-userns`. An EDR that blocks user namespaces, `bwrap`, or `LD_PRELOAD` makes the turn fail closed. On macOS, an EDR that blocks `sandbox-exec` or `DYLD_INSERT_LIBRARIES` does the same. The response is to allow those mechanisms. The jail stays.
- `grok --sandbox workspace` can start another sandbox inside this one. A kernel that blocks nested user namespaces makes that inner sandbox fail. This jail is the boundary the daemon enforces.
- The daemon does not hash the Ollama model blob. `OLLAMA_MODEL` is a name. A pull of a bare name uses `registry.ollama.ai`.
- The process shares the host kernel. There is no microVM.
