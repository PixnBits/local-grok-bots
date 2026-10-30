# Host dependencies

Packages the daemon looks up on the host. The daemon does not install them. This tree has no whisper, ffmpeg, or other voice binary.

Bot log kinds are rows in the daemon log. Audit events are the same name written to the audit sink when that sink is on. A kind that is only a bot log is not an audit event.

## Linux (Ubuntu / Debian)

```bash
sudo apt install bubblewrap socat util-linux gcc
```

`bubblewrap` provides `bwrap`. `socat` provides `socat`. `util-linux` provides `unshare` and is already installed on a normal Ubuntu system. `gcc` compiles the `run_shell` network preload. `git` and `ssh`, when present on `PATH`, are wrapped inside the Ollama shell jail. A missing `git` or `ssh` binary does not fail the shell closed.

| Tool | Used by | Missing |
|---|---|---|
| `bwrap` and `socat` | Claude CLI sandbox, before launch. Both must be on `PATH`. | The turn is refused. Bot log and audit event `cli_sandbox_unavailable`. A managed policy can set `[cli.isolation] claude_sandbox = "off"`. A local policy cannot. |
| `bwrap` | Grok CLI's own sandbox for the custom `lgb` profile. The daemon does not look up `bwrap` first. | Grok refuses to start. If that error text contains `sandbox` and the turn produced no assistant text, the bot log and audit event are `cli_sandbox_unavailable`. |
| `bwrap` | Host CLI broker (`tools.cli` / `coi`). No `unshare` fallback. | The call is denied before the hourly slot. Bot log and audit event `coi_sandbox_unavailable`. An invalid `sandbox_bin` is the same event. |
| `bwrap`, else `unshare` | Ollama `run_shell`. | If both are missing, the tool returns `shell sandbox unavailable`. The daemon keeps serving. Bot log kinds `tool_start` and `tool_end` (`ok` false). There is no separate sandbox audit event. |
| `gcc` | `run_shell` `net` and `ssh` grants. The preload redirects connects to the daemon proxy. | The shell still runs, with no network. Bot log kind `grant_denied`, detail `network proxy unavailable`, for each of those grants. |
| Claude Code `>= 2.1.295` | The permission-broker hook. The launch reads `onFailure`. | An older release, or a version that cannot be read, refuses the turn before the CLI starts. |
| `lgb-permhook` | The Claude PreToolUse hook when `broker` is `hook`. Build it with `deploy/build.sh`. An empty `hook_path` uses the copy beside the daemon binary. | The turn is refused before the CLI starts, and startup warns that the hook cannot be used. |

## macOS

The jails use the built-in `/usr/bin/sandbox-exec`. Apple still ships it. There is no Homebrew package to install in its place. The Claude `bwrap` / `socat` check does not run on macOS. The connect proxy needs `LD_PRELOAD`, which this path does not use, so a `net` or `ssh` grant does not open the network.

| Tool | Used by | Missing |
|---|---|---|
| `/usr/bin/sandbox-exec` | Ollama `run_shell`. | The tool returns `shell sandbox unavailable`. The daemon keeps serving. Bot log kinds `tool_start` and `tool_end` (`ok` false). There is no separate sandbox audit event. |
| `/usr/bin/sandbox-exec` | Host CLI broker. | The call is denied before the hourly slot. Bot log and audit event `coi_sandbox_unavailable`. |

A Grok turn with no `net` grant still runs. macOS does not enforce `restrict_network`. The bot log and audit event are `cli_network_unrestricted`. That event is a warning, not a refusal.

On macOS, when `sandbox-exec` is present, a `net` or `ssh` grant is denied inside the shell. Bot log kind `grant_denied`, detail `network unavailable in the macOS sandbox`.
