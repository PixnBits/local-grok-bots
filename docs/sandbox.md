# Sandbox model

The target for how bots run code. The current jail (unshare + chroot, workspace only, fails closed) is the right default. This document is how we add capability without a policy language or a microVM.

## Why this shape

Major coding agents (Claude Code, Codex, Cursor, Grok Build) converged on the same local pattern: OS-level isolation (bubblewrap on Linux, Seatbelt on macOS, Landlock/seccomp) plus a network proxy with an empty-by-default allowlist. Writes stay in the workspace. Credentials stay outside the sandbox. Stronger isolation (Firecracker microVMs, gVisor, Docker Sandboxes) is reserved for untrusted third-party code or multi-tenant hosts. Containers share the host kernel and have a weaker boundary.

The 2026 sandbox-escape research (Pillar Security, CSA) is the relevant caution. In almost every case the agent stayed inside the box. It wrote a file — a hook config, a git setting, a task definition — that a trusted process *outside* the sandbox later executed. The boundary held; the trust handoff did not. Network allowlists and “no standing secrets inside the jail” reduce blast radius from prompt injection. Capability tokens are cleaner than RBAC for agents because the action is dynamic, but a full capability system is more machinery than this daemon needs.

## The model

One base jail. A short list of named grants on the bot (or on a run). No policy language. No microVM.

The base is the current workspace jail. On Linux it is bubblewrap when `bwrap` is installed, and otherwise unshare. Bubblewrap is what Claude Code and Codex use on Linux. It handles `--unshare-net` and selective binds cleanly, and it avoids the AppArmor friction raw unshare hit on this machine. On macOS the same grants run under `sandbox-exec`. Seatbelt cannot bind-mount, so the shell's working directory is the host workspace path rather than `/work`. MicroVMs stay out. That was the AegisClaw path; the overhead is not justified for a single-user desktop.

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

## Out

- Per-bot microVMs.
- A general policy language or capability-token system.
- Mounting host credentials into the jail.
- Full computer-use or a virtual display. Headless browser is a later grant; take-control is not.
