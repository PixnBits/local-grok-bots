# Sandbox model

The target for how bots run code. The current jail (unshare + chroot, workspace only, fails closed) is the right default. This document is how we add capability without a policy language or a microVM.

## Why this shape

Major coding agents (Claude Code, Codex, Cursor, Grok Build) converged on the same local pattern: OS-level isolation (bubblewrap on Linux, Seatbelt on macOS, Landlock/seccomp) plus a network proxy with an empty-by-default allowlist. Writes stay in the workspace. Credentials stay outside the sandbox. Stronger isolation (Firecracker microVMs, gVisor, Docker Sandboxes) is reserved for untrusted third-party code or multi-tenant hosts. Containers share the host kernel and have a weaker boundary.

The 2026 sandbox-escape research (Pillar Security, CSA) is the relevant caution. In almost every case the agent stayed inside the box. It wrote a file — a hook config, a git setting, a task definition — that a trusted process *outside* the sandbox later executed. The boundary held; the trust handoff did not. Network allowlists and “no standing secrets inside the jail” reduce blast radius from prompt injection. Capability tokens are cleaner than RBAC for agents because the action is dynamic, but a full capability system is more machinery than this daemon needs.

## The model

One base jail. A short list of named grants on the bot (or on a run). No policy language and no microVM. A fixed Policy, loaded from `DATA_DIR/policy.yaml` or the environment, sets the CLI network mode, the default shell allowlist, the extra CLI environment, and the build binds. It is not a language: unknown keys fail startup.

The base is the current workspace jail. On Linux it is bubblewrap when `bwrap` is installed, and otherwise unshare. Bubblewrap is what Claude Code and Codex use on Linux. It handles `--unshare-net` and selective binds cleanly, and it avoids the AppArmor friction raw unshare hit on this machine. On macOS the same grants run under `sandbox-exec`. Seatbelt cannot bind-mount, so the shell's working directory is the host workspace path rather than `/work`. MicroVMs stay out. That was the AegisClaw path; the overhead is not justified for a single-user desktop.

Grants are explicit. The daemon checks the grant before the tool runs. Missing grant means fail closed, logged.

| Grant | What it enables | How it stays safe |
|---|---|---|
| Base (default) | Workspace files + shell | Current jail. No network. |
| `net` | Domain allowlist | Proxy outside the jail. Empty list means no egress, unless Policy `default_net_allow` supplies hosts. A bot list wins. |
| `git` | Clone, commit, push | Dedicated worktree inside the workspace. Never mount `~/.ssh` or host git config. Push via a short-lived token injected by the daemon, or surface the diff for review. |
| `ssh` | Reach specific hosts | Dedicated key or proxy. Never the user's full agent. Log every connection. |
| `build` | Toolchains, tests, binaries | Extra read-only binds for compilers if needed. Output stays in the workspace. |
| `browser` (later) | Visual / headless | Separate grant. Headless Chromium in the jail or a disposable profile. Full take-control stays the deferred computer-use path. |

Credentials never live inside the jail. For git and SSH the daemon mediates or injects; the process sees a placeholder or nothing. Block writes to `.git/hooks`, host shell rc files, and any path the daemon itself will later treat as executable config. Those are the trust-handoff vectors.

Every grant use and every denial is a log event. Surface irreversible actions (push, SSH, package install) in the thread the same way inbound DMs appear, so they are visible without opening the log.

## What this enables

A coding bot can clone, build, test, and (when granted) push or reach a host. Every other bot stays in the locked-down workspace. The log remains the place to verify what actually happened.

## CLI network

CLI turns are outside the shell grant list. Their network mode is `cli_network` on the Policy: `open` (the default), `proxy`, `explicit-proxy`, or `none`. `proxy`, `explicit-proxy`, and `none` take the network away from the process. `proxy` and `explicit-proxy` put back only the existing allowlist proxy, with `cli_net_allow` as the host list. An empty list denies every host. The interposer is the same `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` path the shell uses. A connect it does not see fails closed.

`explicit-proxy`, and `proxy` when a URL is set, dials allowed destinations through the corporate proxy named by `http_proxy` / `https_proxy` (or `HTTP_PROXY` / `HTTPS_PROXY`). `no_proxy` skips that hop for matching hosts. The allowlist is still the real destination, so the corporate proxy host does not need to be listed. The proxy URL is not copied into the CLI child. A password in the URL is used for `Proxy-Authorization` and is redacted in the startup log and `GET /api/policy`. Each allow and deny is a log event. `open` and `none` do not use these URLs. `explicit-proxy` with no URL fails startup. `force_local_only` refuses a non-loopback Ollama URL and disables CLI backends.

The airgap file is in the README. `GET /api/policy` returns the loaded value.

## CLI binary pins

`cli_pins` is optional. With no pin, the daemon execs whatever `grok` or `claude` is on `PATH`, as it does today. A pin names an absolute path, a SHA-256 of the file, a version token, or any combination. The path and hash are checked before the binary runs. The hash is of the file after symlinks are resolved. A version pin runs `<binary> --version` with a cleared environment and accepts the token only as a whole word. That command is the one case where a version-only pin executes the binary outside the jail, so prefer a hash. A mismatch fails the turn. The log event is `cli_pin` with `ok` or the reason. The expected hash and path are in the policy. The version command's output is not.

`audit_log` can copy CLI process start and stop, network allow and deny, and other grant decisions to stderr, syslog, or a file. The schema and redaction rules are in `docs/audit.md`. Empty leaves that sink off. The store log is unchanged.

## Content check

`dlp_patterns`, `dlp_file`, and `dlp_command` are off unless one of them is set. Before a CLI turn is sent, the daemon checks the prompt. A match or a non-zero scanner exit fails that turn and does not start the CLI. The store event is `dlp_denied`. When `audit_log` is set, the audit event is `dlp` with action `deny`. The reason is a short code: `dlp: blocked by pattern`, `dlp: blocked by scanner`, `dlp: scanner failed`, `dlp: rules unreadable`, or `dlp: content too large`. The prompt is not written.

`dlp_patterns` entries are Go regular expressions, at most 256 bytes. In the policy file the list is comma-separated, so a pattern that contains a comma belongs in `POLICY_DLP_PATTERNS` (separated by `;`) or as a `re:` line in the blocklist. `dlp_file` is an absolute path, at most 64KiB, re-read on each check. Blank lines and `#` comments are skipped. Other lines are case-insensitive literals. A line that starts with `re:` is a regular expression. A missing file, a bad `re:` line, or text longer than 1MiB fails the turn.

`dlp_command` is an absolute executable with no arguments and no shell. It receives the text on stdin and `PATH` only, so `XAI_API_KEY` and `SSH_AUTH_SOCK` are not copied. Exit 0 allows the turn. Any other exit rejects it. The command has 5 seconds. A timeout or a failure to start fails the turn. Stderr is discarded, so a scanner that prints the prompt does not put that text in the daemon log. Point this at an external scanner with `dlp_command: /absolute/path/to/scanner`. The scanner should record its own reason code and should not echo the prompt.

`dlp_scan_tools: true` runs the same check on the tool-result text after the local tool has run and before the next CLI round. The default is false. A blank prompt is not sent to the check. The fields appear on `GET /api/policy`. They are rules and paths, not a copy of the prompt.

## Airgap

The README file is the local-only setting: `force_local_only: true`, `cli_network: none`, and empty backend, allow, and env lists. `force_local_only` disables CLI backends and refuses a non-loopback `OLLAMA_URL`. `cli_network: none` is the setting when a CLI stays enabled and must not dial out. `cli_network: proxy` with `cli_net_allow: []` starts the proxy and denies every destination. The daemon's own model call is the loopback Ollama URL. It does not pull a model.

## CLI read-only binds

`cli_ro_binds` is empty by default, which leaves the CLI jail mounts unchanged. Each entry is an extra path the CLI can read. The shell `build_binds` list is a different grant and is not changed.

On Linux the jail applies `--ro-bind` with the same path as source and destination, after the fixed system mounts and immediately before the writable workspace mount. Parent directories inside the jail are created with `--dir`. The mount is not writable. The workspace and the CLI login directories stay read-write.

Seatbelt on macOS cannot bind-mount one path onto another. The same list is a `file-read*` allow at the host path, and it is not added to the write list. A path the profile cannot quote fails startup. The daemon still writes that allow into the profile.

A path must be absolute and must exist when the daemon starts. A missing path, a relative path, an empty entry, a duplicate, or a broken symlink fails startup. The file list is comma-separated, so a path that contains a comma belongs in `POLICY_CLI_RO_BINDS`. The same refusal rules as a shell bind apply: `.ssh`, shell startup files, `.netrc`, `.pgpass`, and git config. A path that overlaps `DATA_DIR/workspace`, `~/.grok`, `~/.claude`, or `~/.claude.json` also fails, including a parent of those paths and the target of a symlink. The home directory itself overlaps `~/.grok`. A path that is exactly `/usr`, `/bin`, `/lib`, `/lib64`, `/etc`, `/tmp`, `/proc`, `/dev`, `/lgb-home`, or `/lgb-proxy` fails because it is already a jail mount. A child of `/usr` is allowed. The stored value is the cleaned path the operator wrote.

Each applied path is a store event `grant_use` with grant `cli_ro_bind` and detail `<path> read-only`, written when that CLI process's jail is built. When `audit_log` is set, the audit event is `grant`. `GET /api/policy` returns the paths. An empty list writes no event.

Existence is checked at startup. On Linux, removing the path later makes the next turn fail when bubblewrap cannot mount it. On macOS the allow remains in the profile. A path that is already visible through a system mount, such as a directory under `/usr`, is still listed and still logged.

## Destinations when a CLI stays enabled

`open` does not filter hosts. `proxy` and `explicit-proxy` allow a host only when `cli_net_allow` contains that exact name. A wildcard is stored as that literal and matches no other host. Port 22 still needs the `ssh` grant. Any other port to an allowed host is permitted. A denied host is an audit `net_decision` when `audit_log` is set, which is how an operator learns the next host to add.

The CLI child does not receive `HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY`. Those names cannot be added to `env_allowlist`. Corporate egress is `explicit-proxy` (or `proxy` with a URL): the allowlist still names the real destination, and the daemon dials that destination with HTTP CONNECT through the corporate proxy. `no_proxy` skips that hop. A TLS-inspecting proxy must present a CA the CLI already trusts. The Linux jail bind-mounts `/etc/ssl` read-only when that directory exists. The daemon does not install a CA. A shell `net` grant dials directly and does not use this upstream.

Grok, from the xAI API reference and the accounts FAQ:

| Host | When |
| --- | --- |
| `api.x.ai` | Inference. A regional pin is `<region>.api.x.ai`. |
| `accounts.x.ai`, `console.x.ai` | Account sign-in. |

xAI does not publish one firewall table for every host the Grok CLI may contact. Search, plugins, and updates add hosts. Confirm a denied host in the audit log before locking the list.

Claude Code, from [the enterprise network page](https://code.claude.com/docs/en/network-config) as of 2026-10-13. Re-read that page before freezing an allowlist. A stored login still refreshes tokens, so a headless turn needs the three core hosts. Browser sign-in also uses `claude.com`, which happens when an operator runs `claude auth login` on the host.

| Host | When |
| --- | --- |
| `api.anthropic.com` | API requests, the WebFetch domain check, feature flags, telemetry |
| `claude.ai` | claude.ai account authentication |
| `platform.claude.com` | Console auth, and OAuth refresh for both account types |
| `claude.com` | Browser sign-in and some documentation fetches |
| `mcp-proxy.anthropic.com` | claude.ai MCP connectors, on by default |
| `downloads.claude.ai` | Native installer and update checks |
| `storage.googleapis.com` | Plugin metadata, and older native updates |
| `registry.npmjs.org` | npm or bun installs, plugin packages, `npx` MCP servers |
| `github.com`, `raw.githubusercontent.com` | Plugin marketplaces and the changelog feed |
| `code.claude.com` | Built-in documentation lookups |
| `http-intake.logs.us5.datadoghq.com`, `browser-intake-us5-datadoghq.com` | Optional telemetry. `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` disables both |
| `bridge.claudeusercontent.com` | Claude in Chrome |
| `formulae.brew.sh` | Homebrew update checks |

`*.frame.claudeusercontent.com` is the artifact host pattern on that page. This allowlist cannot express the wildcard, so each concrete host has to be listed, or the artifact tool has to stay off. Amazon Bedrock, Google Cloud, and Microsoft Foundry move model traffic to those providers. The WebFetch domain check still calls `api.anthropic.com` unless Claude's own `skipWebFetchPreflight` is set. That setting lives in Claude's config, not in this Policy.

Ollama pulls of a bare name use `registry.ollama.ai`. Copy the model onto the host, or pull it from an internal registry, before the daemon starts. Runtime inference stays on the loopback Ollama URL.

## User namespaces and EDR

Linux CLI turns fail closed without the distro `bubblewrap` package. The jail always passes `--unshare-user`, `--unshare-pid`, and `--die-with-parent`. `--unshare-net` is added for `proxy`, `explicit-proxy`, and `none`. The daemon does not pass `--disable-userns`. Install `bubblewrap` from the distribution. A home-built `bwrap` can be blocked by AppArmor, and a kernel with `apparmor_restrict_unprivileged_userns=1` can deny a raw `unshare` of `/proc/self/uid_map` while the packaged `bwrap` still works. The Ollama shell uses `bwrap` when it is installed and otherwise `unshare`. If both fail, that shell fails closed and the daemon still serves.

An EDR that blocks unprivileged user namespaces, `bwrap`, or `LD_PRELOAD` makes a Linux CLI turn fail closed. An EDR that blocks `sandbox-exec` or `DYLD_INSERT_LIBRARIES` makes a macOS turn fail closed. Allow those mechanisms for this service. Do not remove the jail, do not add `--disable-userns`, and do not resign the `grok` or `claude` binary. The preload is how a proxied connect reaches the allowlist. A connect it does not see is denied by the network namespace or by Seatbelt.

`grok --sandbox workspace` can start a second sandbox inside this jail. A kernel that blocks nested user namespaces makes that inner sandbox fail. This jail remains the boundary the daemon enforces.

## Supply chain

`go.sum` is part of the repo. Build with the checksum database left on (`GOSUMDB` unset, or `sum.golang.org`). When the build host cannot reach the public proxy, set `GOPROXY` to the internal module proxy and run `go mod verify` after the download. Turning the checksum database off skips that check.

Install `bubblewrap` from the distro packages. Install `grok` and `claude` from the vendor or an internal mirror, then set `cli_pins` to the absolute path and the SHA-256 of the resolved file. A version-only pin runs `--version` outside the jail, so prefer the hash. The default is no pin, which keeps a current install working.

`OLLAMA_MODEL` selects a model already on the local Ollama. This daemon does not hash that blob. An airgapped host should have no route to `registry.ollama.ai`, and the model files should be in place before startup.

Leave `XAI_API_KEY`, `ANTHROPIC_API_KEY`, and `SSH_AUTH_SOCK` out of the unit. Login stays in the daemon user's `~/.grok` or `~/.claude`.

What is policy-controlled, and what remains, is `docs/plans/2026-10-13-enterprise-residual.md`.

## Out

- Per-bot microVMs.
- A general policy language or capability-token system.
- Mounting host credentials into the jail.
- Full computer-use or a virtual display. Headless browser is a later grant; take-control is not.
