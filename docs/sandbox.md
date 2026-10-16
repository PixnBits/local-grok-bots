# Sandbox model

The target for how bots run code. The current jail (unshare + chroot, workspace only, fails closed) is the right default for Ollama mode. This document is how we add capability without a policy language or a microVM.

## Why this shape

Major coding agents (Claude Code, Codex, Cursor, Grok Build) converged on the same local pattern: OS-level isolation (bubblewrap on Linux, Seatbelt on macOS, Landlock/seccomp) plus a network proxy with an empty-by-default allowlist. Writes stay in the workspace. Credentials stay outside the sandbox. Stronger isolation (Firecracker microVMs, gVisor, Docker Sandboxes) is reserved for untrusted third-party code or multi-tenant hosts. Containers share the host kernel and have a weaker boundary.

The 2026 sandbox-escape research (Pillar Security, CSA) is the relevant caution. In almost every case the agent stayed inside the box. It wrote a file — a hook config, a git setting, a task definition — that a trusted process *outside* the sandbox later executed. The boundary held; the trust handoff did not. Network allowlists and “no standing secrets inside the jail” reduce blast radius from prompt injection. Capability tokens are cleaner than RBAC for agents because the action is dynamic, but a full capability system is more machinery than this daemon needs.

## The model (Ollama mode)

One base jail. A short list of named grants on the bot (or on a run). No policy language. No microVM.

The base is the current workspace jail, upgraded to bubblewrap when the sandbox code is touched. Bubblewrap is what Claude Code and Codex use on Linux. It handles `--unshare-net` and selective binds cleanly, and it avoids the AppArmor friction raw unshare hit on this machine. MicroVMs stay out. That was the AegisClaw path; the overhead is not justified for a single-user desktop.

Grants are explicit. The daemon checks the grant before the tool runs. Missing grant means fail closed, logged.

| Grant | What it enables | How it stays safe |
|---|---|---|
| Base (default) | Workspace files + shell | Current jail. No network. |
| `net` | Domain allowlist | Proxy outside the jail. Empty list means no egress. |
| `git` | Clone, commit, push | Dedicated worktree inside the workspace. Never mount `~/.ssh` or host git config. Push via a short-lived token injected by the daemon, or surface the diff for review. |
| `ssh` | Reach specific hosts | Dedicated key or proxy. Never the user's full agent. Log every connection. |
| `build` | Toolchains, tests, binaries | Extra read-only binds for compilers if needed. Output stays in the workspace. |
| `browser` (later) | Visual / headless | Separate grant. Headless Chromium in the jail or a disposable profile. Full take-control stays the deferred computer-use path. |

Credentials never live inside the jail. For git and SSH the daemon mediates or injects; the process sees a placeholder or nothing. Block writes to `.git/hooks`, host shell rc files, and any path the daemon itself will later treat as executable config. Those are the trust-handoff vectors.

Every grant use and every denial is a log event. Surface irreversible actions (push, SSH, package install) in the thread the same way inbound DMs appear, so they are visible without opening the log.

## What this enables

A coding bot can clone, build, test, and (when granted) push or reach a host. Every other bot stays in the locked-down workspace. The log remains the place to verify what actually happened.

## CLI backend mode

When the policy selects `backend = claude` or `backend = grok`, the daemon's workspace jail is off. The daemon does not wrap the CLI process in bubblewrap or Seatbelt. The CLI's own sandbox (Seatbelt on macOS, bubblewrap on Linux/WSL2) plus any InfoSec-managed settings (domain allowlists, credential deny/mask, `allowManagedDomainsOnly`, `failIfUnavailable`, etc.) are the isolation boundary.

The daemon is a thin orchestrator: it spawns or resumes the CLI headless, injects timer prompts via a narrow append-only channel that the CLI's own tools read, and relays the CLI's streaming output to the web portal. It never executes shell commands or file operations on the bot's behalf. Sensitive-path restrictions (SSH keys, `.env` files, etc.) are enforced by the CLI's existing policy, not re-implemented by the daemon.

Nested jails are avoided. The daemon does not attempt to re-jail a CLI that already has its own sandbox.

The host CLI broker later in this document is a different path. There the daemon's bubblewrap or Seatbelt jail is the only sandbox. The inner CLI is not given a second sandbox profile.

## COIs (connectors) and credential brokering

User-configured connectors (COIs) — for example a Grok COI that can edit a project, or any authenticated HTTP/MCP/CLI integration — must be callable from a bot without ever placing credentials inside the sandbox. The LLM, Ollama process, or any code it runs must not be able to read, log, or exfiltrate those credentials for other purposes.

This follows the same principle already used for git and SSH: the daemon mediates. Credentials stay on the host. The sandbox sees either a structured tool call or a narrow call site.

### Primary path: first-class daemon tools

In Ollama mode most tools (files, memory, timers, DMs, bot management) already execute outside the jail. Only `run_shell` is sandboxed. COIs use the same pattern.

- The user adds a COI (name, type, credential reference, allowed operations/scopes) via the web UI or API.
- The daemon injects the corresponding tool schema into the Ollama tools list for bots that have been granted that COI. The tool list can change between runs; it is not compiled in.
- On a tool call the daemon holds the real credential (from an OS keyring or an encrypted host-side store), performs the upstream call, and returns the result. The sandbox process never sees the secret.
- Example: `coi_grok_edit` or a generic `coi_call` with structured arguments. The daemon applies patches or returns diffs inside the workspace.

This is the cleanest path for CISO review: no network required inside the jail for these actions, full audit, least privilege via per-bot grants, fail-closed by default.

### Secondary path: in-sandbox call site

When generated code, a shell script, or a tool running inside the jail must invoke a COI:

- **Unix-domain socket** (preferred on Linux). The daemon listens on a host socket and bind-mounts it into the workspace at a fixed path such as `/work/.lgb/coi.sock` (bwrap `--bind`). A small helper or `curl --unix-socket` / `nc` talks to it. The daemon authenticates the request (bot identity, granted COI, allowlisted operation), injects credentials, and proxies. Socket permissions are 0600 and owned by the daemon user.
- **File-based IPC** (more portable when sockets are restricted). The sandbox writes a JSON request into a watched subdirectory (`/work/.lgb/requests/<id>.json`); the daemon responds with a result file. Short TTL, every exchange logged. Same pattern used by some credential proxies for Seatbelt/bwrap constraints.

Either call site is a thin stub. The real COI client (Grok CLI wrapper, MCP client, HTTP client, etc.) runs only on the host.

### Tertiary path: credential-injecting egress proxy

Extends the existing `net` grant proxy. For pure HTTP COIs the sandbox uses a placeholder token or omits the Authorization header. The proxy (outside the jail) matches allowlisted hosts, paths, and methods and injects the real credential on the way out. Requests that do not match a binding are blocked or forwarded without credentials. This reuses the preload that redirects non-loopback TCP connects to the daemon proxy socket.

### Dynamic configuration

COIs are not compiled in.

- Stored in SQLite (new table or extension of existing state): name, type (`http` | `cli` | `mcp` | `custom`), credential_ref, allowed operations/scopes, optional rate limits or resource filters.
- Per-bot grants (or an allowlist on the bot profile) control which COIs a bot can see, matching the existing capability-grant model.
- Web UI (bot profile or a dedicated COIs page) + API for add/remove/update on the fly. The daemon reloads tool schemas for the next run without a restart.
- Credentials live only on the host: OS keyring where practical, or an age-encrypted / mode-0600 file outside the workspace, referenced by name. Never mounted into the jail, never present in the sandbox environment.

### Security properties

- Credentials never enter the sandbox address space, filesystem, or environment.
- Least privilege: explicit per-bot grants + operation/host/path allowlists. Missing grant fails closed and is logged.
- Full audit: every COI call and denial is a log event with bot ID, operation, redacted arguments, and status.
- Short-lived or narrowly scoped tokens preferred when the upstream supports them.
- Trust-handoff vectors remain blocked (no `.git/hooks`, no host shell rc, no executable config the daemon later trusts).
- Dynamic but user-controlled; the agent cannot self-grant or invent new COIs.
- Small TCB: only the daemon holds credentials and performs the real call.
- Optional surface in the thread for high-impact actions, consistent with irreversible grants today.

Internal LGB COIs (timers, etc.) already follow the daemon-mediated pattern. User-defined COIs reuse the same mechanism.

### Host CLI broker (`tools.cli` / `.lgb/bin/coi`)

The first slice is a host CLI invoked from the bot jail through the lgb spool. The jail gets only a placeholder. The real file stays in `credential_home` on the host and is read by the daemon proxy. With managed `allow_jail_credentials` opt-in, a copy is staged into the jail. The inner CLI is still untrusted relative to those credentials, so the daemon runs it in its own OS sandbox:

- Linux: bubblewrap (`bwrap`) with `--unshare-user`, `--unshare-pid`, `--unshare-uts`, `--unshare-ipc`, `--unshare-net`, and `--new-session`. Missing or failed `bwrap` denies the call and audits `coi_sandbox_unavailable`. There is no unshare fallback. Host `/run` and `/var/run` are not mounted. With the network namespace empty, the jail has no `resolv.conf` bind; the host proxy resolves DNS.
- macOS: `sandbox-exec` with a generated Seatbelt profile. Missing `sandbox-exec` is the same denial. The profile denies network-outbound except localhost and, when a proxy is in use, the proxy unix socket. It also denies read and write of `<workspace>/.lgb`. That profile is untested on macOS; it still compiles.
- Only the bot workspace is writable. System directories (`/usr`, `/bin`, `/lib`, `/etc`, …) are read-only. The resolved CLI **file** is bound read-only. The daemon does not bind `~/.grok`, the credential home, or any other host home. A tmpfs covers `<workspace>/.lgb`, so the bot spool is not visible to the inner CLI.
- `credential_home` is not mounted. The private HOME is a 0700 directory under `<data>/coi/homes` (not the host temp dir), deleted after the call. Startup removes stale `coi-home-*` directories there and any leftover ones directly under the host temp dir. Inside the Linux jail that HOME is a bind over tmpfs at `/tmp/coi-home`.
- The jail does not receive real credential bytes. `proxy_hosts` (hostnames only, no scheme, port, or path) turns on the egress proxy. The first host is the TLS upstream. The jail gets a placeholder file (`coi-placeholder-token`, and for an entry named `grok` a synthetic `auth.json` whose expiry is far in the future). The daemon binary is bound read-only and started as `--coi-forward`. That process listens on `127.0.0.1:<port>` inside the jail, splices the TCP connection to a unix socket, then execs the CLI. The socket lives in a 0700 directory under `<data>/coi/proxy`, mode 0600, and its filename does not end in `.sock`. Linux bind-mounts it at `/coi-proxy.sock`. That is the only socket path mounted into the jail.
- Grok is pointed at `http://127.0.0.1:<port>/v1` via `GROK_CLI_CHAT_PROXY_BASE_URL`, `GROK_XAI_API_BASE_URL`, and `XAI_API_BASE_URL`. The forwarder also sets `XAI_API_KEY` to the placeholder. Grok 1.0.52 does not treat a synthetic `auth.json` as a session; it does send `Authorization: Bearer` from that variable. Other CLIs get `COI_FORWARD_URL` with no path prefix. The host proxy is a reverse proxy: it opens TLS to the first allowlisted host and forwards the path only when that path is under `proxy_path_prefixes`. An omitted list means `/v1`, the prefix Grok uses on `cli-chat-proxy.grok.com`. Any other path, including `..`, an encoded dot or slash, or an empty segment, is 403 and is not sent upstream. On an allowed path it replaces `Authorization` with the bearer from the credential file. It does not log bodies or headers. An HTTP CONNECT proxy cannot inject that header, because the CLI's TLS would hide it, so CONNECT is not used. The CLI must accept an `http://` base URL.
- The host reads the Grok login file (`key` as the bearer, `refresh_token` when present). If `expires_at` is within 90 seconds, the host POSTs `grant_type=refresh_token` to `https://auth.x.ai/oauth2/token` and writes the new access token back to that file, mode 0600. A successful refresh can rotate the refresh token. Refreshing a copy of the user's login file can desync the real one. If refresh fails and the access token is still valid, the call continues. If it is expired and refresh fails, the call is denied.
- If the proxy cannot be prepared, the call is denied and audited as `coi_proxy_unavailable`. The daemon does not fall back to copying secrets. The preflight runs before the hourly slot is taken.
- Without `proxy_hosts`, listed `credential_files` are still placeholders. Copying the real files requires managed `allow_jail_credentials = true`. The daemon then logs `coi_jail_credentials`. Local policy cannot turn that flag on. It can turn a managed flag off. `credential_files` together with `fixed_args` `--always-approve`, without the proxy and without that opt-in, is denied before the hourly slot.
- Child `PATH` is pinned to system directories (`/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin` as they exist). Workspace and credential-home directories are never on `PATH`.
- Bot argv cannot pass `--always-approve` or `--sandbox` (blocked like `login` / `config`). Policy `fixed_args` and `fixed_env` are prepended by the daemon and are not taken from the bot. The daemon does not prepend `--sandbox` and does not write `sandbox.toml`. Grok's own sandbox is not a second layer on this path. Flags not listed in `value_flags` are boolean, so they cannot swallow the next word; blocked-word checks apply to values and to `--flag=value`.
- Path allowlist checks remain as defense in depth. They are TOCTOU against a process that can still `open` after `stat`; the sandbox is the filesystem boundary.
- Output redaction (`audit.RedactText`, credential-home paths, secret values scanned from the home) is a backstop for logs and replies. It is not the control that keeps credentials out of the bot jail or the inner CLI filesystem.

#### Grok pins used by the daemon

Grok has no `--setting-sources` / `--strict-mcp-config` equivalent. For a `tools.cli` entry named `grok` the daemon:

- Sets `GROK_HOME` to the private HOME `.grok`, `GROK_DISABLE_AUTOUPDATER=1`, and every `GROK_CLAUDE_*_ENABLED`, `GROK_CURSOR_*_ENABLED`, `GROK_CODEX_*_ENABLED`, plus `GROK_MANAGED_MCPS_ENABLED`, to `false`.
- Drops `GROK_CONFIG`, `GROK_CONFIG_PATH`, and `GROK_SANDBOX`. It never passes `--trust` and never writes `sandbox.toml`.
- For chat, set `proxy_hosts` to the host the CLI actually calls. The observed default chat base is `cli-chat-proxy.grok.com`. `api.x.ai` is a separate API host. One reverse proxy has one upstream: the first `proxy_hosts` entry. Extra names are accepted by the allowlist check but are not separate upstreams.

`--always-approve` stays blocked on bot argv. Headless edits need daemon `fixed_args = ["--always-approve"]` (`--permission-mode acceptEdits` returned text but did not write the file). With `proxy_hosts` set, that flag does not put the login file in the jail. Without `proxy_hosts`, the same flag requires managed `allow_jail_credentials`.

`sandbox_bin` (absolute) is a test/ops hook that replaces `bwrap` / `sandbox-exec`. An invalid path denies the call as `coi_sandbox_unavailable`.

The hourly cap is stored in SQLite (`coi_cap`) so a restart cannot reset the window. A store error fails closed. Long COI calls run on a bounded worker set in the spool drain (limit 4) so other `lgb` tools are not blocked behind them.

## Out

- Per-bot microVMs.
- A general policy language or capability-token system.
- Mounting host credentials into the jail.
- Full computer-use or a virtual display. Headless browser is a later grant; take-control is not.
- Re-implementing CLI sandbox policy when a CLI backend is selected.
