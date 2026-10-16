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

## Out

- Per-bot microVMs.
- A general policy language or capability-token system.
- Mounting host credentials into the jail.
- Full computer-use or a virtual display. Headless browser is a later grant; take-control is not.
- Re-implementing CLI sandbox policy when a CLI backend is selected.
