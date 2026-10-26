# Sandbox model

The target for how bots run code. The current jail (unshare + chroot, workspace only, fails closed) is the right default for Ollama mode. This document is how we add capability without a policy language or a microVM. Host packages and the log event for each missing tool are in [Host dependencies](host-dependencies.md).

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

Every grant use and every denial the daemon itself observes is a log event. Surface irreversible actions (push, SSH, package install) in the thread the same way inbound DMs appear, so they are visible without opening the log. A package-install line written by the jail is only an untrusted notice.

### Shell jail binds and events

`run_shell` uses bubblewrap when `bwrap` is installed, and otherwise `unshare` with a chroot (user, mount, and network namespaces). A `build` grant mounts `SANDBOX_BUILD_BINDS` read-only when bubblewrap is used. The daemon opens the bind with `openat2` (`O_PATH`, `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS`). Bubblewrap mounts that file descriptor with `--ro-bind-fd` and does not fall back to a path bind. The unshare fallback cannot mount the descriptor: bind-mounting `/proc/self/fd/N` from the new user namespace fails, and mounting the path would race. It refuses each build bind with a daemon-generated `sandbox_block` whose detail is `refused bind <path>: unsupported without bwrap`, and it does not mount the path. The rest of the shell still runs.

The opened inode is refused when it is a protected path, an ancestor of a protected path (up to but not including `/`), or `DATA_DIR` (the daemon puts `DATA_DIR`, raw and resolved, on the protected list). At startup the daemon records a baseline of those inodes. The baseline stays for the life of the process. SIGHUP does not replace it. A successful `AUTH_TOKENS_FILE` reload adds paths that were not already recorded. A failed reload leaves the snapshot unchanged. Required paths must exist when they are recorded: `DATA_DIR`, the admin token file when the daemon has created it, `POLICY_PATH` when it is set and the policy loaded, `AUTH_TOKENS_FILE` when it is set, the `[github]` `token_file` when it is set, the sandbox SSH key when that file already exists, and each configured `credential_home`. A missing required path, or a missing ancestor of it, trips the snapshot (`protected path missing: <path>`). Optional paths may be absent, including `state.db-wal`, `state.db-shm`, the secret directories under `DATA_DIR`, and the audit log. A missing optional path records the nearest existing ancestor directory and does not trip. An unconfigured path is not listed. The first time a recorded directory is missing, is no longer a directory, or has a new device or inode, the trip sticks until restart: one audit row `protect_snapshot_tripped`, one log line, and every build bind refused with `protected path changed (restart required)` or `protected path missing (restart required)`. Replacing a protected directory needs a restart. A regular file changing does not trip. An empty snapshot refuses every build bind. These checks fail closed against a rename race. They do not stop every same-uid process on the host. A same-uid attacker outside the jail is out of scope beyond these fail-closed checks. Directories on bind paths should not be writable by other users. An empty protected list refuses every build bind.

Lines the jail writes to `/lgb/events/log` are untrusted. The wrappers that write that file run as the bot, so the bot can append the same lines. The daemon pins the events directory when the jail is prepared and reads `log` from that directory descriptor, so a symlink the bot puts at `/lgb/events` is not followed. A missing log, a symlink, or any other read failure is one daemon event, `jail_report_truncated` with detail `events unavailable`. The daemon records each line as `jail_report` with `untrusted: true` and `reported` set to the kind the line claimed (`sandbox_block`, `grant_use`, `grant_denied`). Those rows are not `sandbox_block`, `grant_use`, or `grant_denied`, they are not audited as those actions, and they do not start an approval or a decision. A user-visible notice from a jail line is informational text prefixed so it does not start a turn. The same notice text is posted once per turn, with a count when it was repeated. A dropped-line count is reported once per turn, on the first notice, or as one summary when that turn has no notice. `sandbox_block` and build `grant_use` come only from the daemon. The events file is mode `0600`, owned by the daemon, or by the jail uid when a root daemon drops to the overflow uid. The read is capped at 64 KiB and 64 lines, and each detail is printable ASCII of at most 256 bytes. Overflow is one daemon-generated `jail_report_truncated` event. `sandbox_block` detail is capped the same way.

## What this enables

A coding bot can clone, build, test, and (when granted) push or reach a host. Every other bot stays in the locked-down workspace. The log remains the place to verify what actually happened.

## CLI backend mode

When the policy selects `backend = claude` or `backend = grok`, the Ollama workspace jail is off. Claude on Linux needs `bwrap` and `socat` ([Host dependencies](host-dependencies.md)). A Grok turn does not link the host login into the bot home ([Grok CLI login live check](cred-hardlink-check.md)).

On Linux, a Grok turn is started in the daemon's bubblewrap jail with a private pid namespace, a fresh `/proc`, an empty network namespace (`--unshare-net`), and a new session (`--new-session`). That hides other same-user processes, including the daemon and other bots (`/proc/<pid>/environ` and `/proc/<pid>/fd`). It also hides host abstract sockets, host loopback listeners, and the LAN. The credential proxy is a unix socket, mode 0600, in a 0700 directory, with a filename that does not end in `.sock`. The jail bind-mounts it at `/cli-proxy.sock`. The daemon binary is the entry process (`--coi-forward`). It listens on `127.0.0.1` inside the jail, splices that TCP connection to the socket, keeps the per-run placeholder (`--keep-key`), and points Grok at `http://127.0.0.1:<port>/bots/<bot>/runs/<run>/v1`. A bot with the `net` grant also gets an HTTP CONNECT and forward proxy bind-mounted at `/cli-egress.sock`. That proxy dials only the bot's exact domain allowlist, and only on ports 443 and 80 unless `[cli.isolation] net_ports` says otherwise. Local policy can only narrow that list. A managed policy can set a different list, and local policy still only narrows the managed list. An empty list allows no port. The proxy resolves a name once and dials that IP, so a later lookup cannot swap the address. It refuses loopback, private, link-local, multicast, unspecified, and this-network addresses, shared CGNAT space (RFC 6598), the benchmarking range (RFC 2544), the well-known NAT64 prefix (RFC 6052), and 6to4 (RFC 3056). An IPv4-mapped IPv6 address is unmapped and checked as IPv4. A name that resolves to any forbidden address is refused. An empty allowlist denies every request. Each decision is audited as `cli_egress_request` with the bot, the run, the host, the port, allow or deny, and a reason. The record has no header and no body. A CONNECT is allowed only when the next flight is one complete TLS ClientHello whose SNI equals the CONNECT host. A missing SNI, a different SNI, or a flight that is not that record is denied (`sni-missing` or `sni-mismatch`). That is a deliberate check, not an accepted domain-fronting gap: a visible SNI that does not match the CONNECT host is refused. Encrypted Client Hello is the accepted residual. Only the outer name is compared, and an inner name is not visible. `DATA_DIR/cli-proxy` and `DATA_DIR/cli-egress` are on the CLI deny list. The forwarder sets `HTTP_PROXY` and `HTTPS_PROXY` to the in-jail listener and sets `NO_PROXY` so the credential origin is not sent through the egress proxy. A bot without the net grant is not given those variables and has no egress. If the bridge cannot be prepared, the turn is refused and audited as `cli_bridge_unavailable`. Workspace, the bot home, and `GROK_HOME` are bound; system directories are read-only. Host `/run` is not mounted. Nested Grok bubblewrap cannot create a user namespace when the kernel restricts unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns`). Remounting `/proc` with `hidepid` needs root. The working boundary is therefore the daemon jail; Grok's `--sandbox` flag is omitted inside it. The custom `lgb` profile is still written. On macOS, Grok keeps `--sandbox lgb` and Seatbelt; there is no daemon pid namespace and `restrict_network` is not enforced.

Claude is unchanged: the daemon does not wrap it. Claude's own sandbox plus managed settings remain the boundary.

The daemon is a thin orchestrator: it spawns or resumes the CLI headless, injects timer prompts via a narrow append-only channel that the CLI's own tools read, and relays the CLI's streaming output to the web portal. It never executes shell commands or file operations on the bot's behalf. Sensitive-path restrictions (SSH keys, `.env` files, etc.) are enforced by the CLI's existing policy, not re-implemented by the daemon.

Durable low-risk auto-grants and the static suggestion pass live in the permission broker (see `docs/cli-permissions.md`). They do not change the sandbox. The broker decides Claude permission-host requests and Grok ACP permission requests, and writes `user-permissions.json` and `grok-permission-rules` beside the bot CLI state. Those files are not mounted into the Linux Grok jail and are not passed as allow flags. A user allow auto-allows a Grok tool only when the call still classifies as low-risk read-only. The jail is unchanged.

The host CLI broker later in this document is a different path. There the daemon's bubblewrap or Seatbelt jail is the only sandbox. The inner CLI is not given a second sandbox profile.

### Remaining isolation limits

- The credential proxy still admits one placeholder per bot and run. The Linux jail reaches that proxy through the unix socket, not through the host TCP listener.
- Filesystem binds include `/usr`, `/bin`, `/lib`, `/etc`, the workspace, and the bot home. Other bots' state under `DATA_DIR/cli` is not bound, but a process that can already see a host path outside those binds is outside this jail.
- Grok's own sandbox is not a second layer on Linux. Tool subprocesses inherit the daemon jail, not a nested Grok profile.
- On macOS, `/proc` is not the exposure. `Unsetenv` after startup does not rewrite original process memory. `KERN_PROCARGS2` exposes the startup environment, including secrets that were present when the process started, to other processes with the same user id. Seatbelt is the process boundary. Darwin does not re-exec.
- Unix-socket COI egress is authenticated by the socket. It is audited as `coi_proxy_request` (bot, run, path, status). It does not use the loopback per-run gate.
- A Grok-backend bot with the `net` grant can reach allowlisted hosts through the egress proxy, on an allowed port, when the CONNECT SNI matches. The host proxy resolves DNS once and dials that IP. A bot without that grant has no egress from the Linux jail.

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

- Linux: bubblewrap (`bwrap`) with `--unshare-user`, `--unshare-pid`, `--unshare-uts`, `--unshare-ipc`, `--unshare-net`, and `--new-session`. The supervisor is pid 1 in that pid namespace, so it is started with `PATH` only. The command, including the forwarder, receives its environment through `--setenv` after `--clearenv`. Missing or failed `bwrap` denies the call and audits `coi_sandbox_unavailable`. There is no unshare fallback. Host `/run` and `/var/run` are not mounted. With the network namespace empty, the jail has no `resolv.conf` bind; the host proxy resolves DNS.
- macOS: `sandbox-exec` with a generated Seatbelt profile. Missing `sandbox-exec` is the same denial. The profile denies network-outbound except localhost and, when a proxy is in use, the proxy unix socket. It also denies read and write of the run spool directory. That profile is untested on macOS; it still compiles.
- Only the bot workspace is writable. System directories (`/usr`, `/bin`, `/lib`, `/etc`, …) are read-only. The resolved CLI **file** is bound read-only. The daemon does not bind `~/.grok`, the credential home, or any other host home. A tmpfs covers the run spool directory when that directory is still the one the run opened, so the bot spool is not visible to the inner CLI.
- `credential_home` is not mounted. The private HOME is a 0700 directory under `<data>/coi/homes` (not the host temp dir), deleted after the call. Startup removes stale `coi-home-*` directories under that homes directory only. Inside the Linux jail that HOME is a bind over tmpfs at `/tmp/coi-home`.
- The jail does not receive real credential bytes. `proxy_hosts` (hostnames only, no scheme, port, or path) turns on the egress proxy. The first host is the TLS upstream. The jail gets a placeholder file (`coi-placeholder-token`, and for an entry named `grok` a synthetic `auth.json` whose expiry is far in the future). The daemon binary is bound read-only and started as `--coi-forward`. That process listens on `127.0.0.1:<port>` inside the jail, splices the TCP connection to a unix socket, then execs the CLI. The socket lives in a 0700 directory under `<data>/coi/proxy`, mode 0600, and its filename does not end in `.sock`. Linux bind-mounts it at `/coi-proxy.sock`. That is the only socket path mounted into the jail.
- Grok is pointed at `http://127.0.0.1:<port>/v1` via `GROK_CLI_CHAT_PROXY_BASE_URL`, `GROK_XAI_API_BASE_URL`, and `XAI_API_BASE_URL`. The forwarder also sets `XAI_API_KEY` to the placeholder. Grok 1.0.52 does not treat a synthetic `auth.json` as a session; it does send `Authorization: Bearer` from that variable. Other CLIs get `COI_FORWARD_URL` with no path prefix. The host proxy is a reverse proxy: it opens TLS to the first allowlisted host and forwards the path only when that path is under `proxy_path_prefixes`. An omitted list means `/v1`, the prefix Grok uses on `cli-chat-proxy.grok.com`. Any other path, including `..`, an encoded dot or slash, or an empty segment, is 403 and is not sent upstream. A query string with a parent segment or an encoded slash is rejected the same way. Path prefixes are matched with their stored case. On an allowed path it forwards only a fixed set of request headers (content type, length, accept, user agent, and the CLI's non-credential `x-grok-*` request headers), then sets `Authorization` to the bearer from the credential file. It does not log bodies or headers. An HTTP CONNECT proxy cannot inject that header, because the CLI's TLS would hide it, so CONNECT is not used. The CLI must accept an `http://` base URL.
- The loopback listener used by the Grok CLI backend admits one placeholder per bot and run and records each request as `cli_proxy_request` (bot, run, path, status). A 403 is marked `auth=none` and those rows are rate-limited. The count of 403 rows omitted since the previous 403 row is included on the next allowed 403. The Linux Grok jail does not dial this TCP listener. It uses the same proxy through a unix socket and `--coi-forward --keep-key`. A net grant uses a separate allowlisting HTTP proxy. The unix-socket egress used by the jailed COI forwarder does not use that gate. Each of its requests is recorded as `coi_proxy_request` (bot, run, path, status) with the same 403 rule.
- The host reads the Grok login file (`key` as the bearer, `refresh_token` when present). If `expires_at` is within 90 seconds, the host POSTs `grant_type=refresh_token` to `https://auth.x.ai/oauth2/token` and writes the new access token back to that file, mode 0600. A successful refresh can rotate the refresh token. Refreshing a copy of the user's login file can desync the real one. If refresh fails and the access token is still valid, the call continues. If it is expired and refresh fails, the call is denied.
- If the proxy cannot be prepared, the call is denied and audited as `coi_proxy_unavailable`. The daemon does not fall back to copying secrets. The preflight runs before the hourly slot is taken.
- Without `proxy_hosts`, listed `credential_files` are still placeholders. Copying the real files requires managed `allow_jail_credentials = true`. The daemon then logs `coi_jail_credentials`. Local policy cannot turn that flag on. It can turn a managed flag off. `credential_files` together with `fixed_args` `--always-approve`, without the proxy and without that opt-in, is denied before the hourly slot.
- Child `PATH` is pinned to system directories (`/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin` as they exist). Workspace and credential-home directories are never on `PATH`.
- Bot argv cannot pass `--always-approve` or `--sandbox` (blocked like `login` / `config`). Policy `fixed_args` and `fixed_env` are prepended by the daemon and are not taken from the bot. The daemon does not prepend `--sandbox` and does not write `sandbox.toml`. Grok's own sandbox is not a second layer on this path. Flags not listed in `value_flags` are boolean, so they cannot swallow the next word; blocked-word checks apply to values and to `--flag=value`.
- Every broker argument value is resolved from the workspace, including a name with no slash. A parent segment, or a target outside the workspace or inside a credential home or the COI data directory, is rejected. Those checks remain defense in depth. They are TOCTOU against a process that can still `open` after `stat`; the sandbox is the filesystem boundary.
- Output redaction (`audit.RedactText`, credential-home paths, secret values scanned from the home) is a backstop for logs and replies. It is not the control that keeps credentials out of the bot jail or the inner CLI filesystem.

#### Grok pins used by the daemon

Grok has no `--setting-sources` / `--strict-mcp-config` equivalent. For a `tools.cli` entry named `grok` the daemon:

- Sets `GROK_HOME` to the private HOME `.grok`, `GROK_DISABLE_AUTOUPDATER=1`, and every `GROK_CLAUDE_*_ENABLED`, `GROK_CURSOR_*_ENABLED`, `GROK_CODEX_*_ENABLED`, plus `GROK_MANAGED_MCPS_ENABLED`, to `false`.
- Drops `GROK_CONFIG`, `GROK_CONFIG_PATH`, and `GROK_SANDBOX`. It never passes `--trust` and never writes `sandbox.toml`.
- For chat, set `proxy_hosts` to the host the CLI actually calls. The observed default chat base is `cli-chat-proxy.grok.com`. `api.x.ai` is a separate API host. One reverse proxy has one upstream: the first `proxy_hosts` entry. Extra names are accepted by the allowlist check but are not separate upstreams.

`--always-approve` stays blocked on bot argv. Headless edits need daemon `fixed_args = ["--always-approve"]` (`--permission-mode acceptEdits` returned text but did not write the file). With `proxy_hosts` set, that flag does not put the login file in the jail. Without `proxy_hosts`, the same flag requires managed `allow_jail_credentials`.

`sandbox_bin` (absolute) is a test/ops hook that replaces `bwrap` / `sandbox-exec`. An invalid path denies the call as `coi_sandbox_unavailable`.

The hourly cap is stored in SQLite (`coi_cap`) so a restart cannot reset the window. A store error fails closed. Long COI calls run on a bounded worker set in the spool drain (limit 4) so other `lgb` tools are not blocked behind them.

A `[[tools.cli]]` entry is unusable without a non-empty `allowed_args` list and a positive `max_output`. Zero `timeout`, `max_output`, or `max_calls_per_hour` denies every call. An omitted `allowed_args` list is deny-by-default (`no arguments allowed`).

## Out

- Per-bot microVMs.
- A general policy language or capability-token system.
- Mounting host credentials into the jail.
- Full computer-use or a virtual display. Headless browser is a later grant; take-control is not.
- Re-implementing CLI sandbox policy when a CLI backend is selected.
