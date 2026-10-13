# Set up local-grok-bots with Claude Code

Follow this from a checkout of this repo, as the user who will run the daemon. Stop at each "Ask" line and wait for that person.

Prompt you can paste: `Follow docs/setup/claude.md and stop whenever it says to ask me.`

This installs a personal daemon. Login stays in this user's `~/.claude` and, when present, `~/.claude.json`. The daemon does not pass `ANTHROPIC_API_KEY` through. New bots use Claude Code.

## Rules

- Run the daemon as this user. It refuses to start as root.
- Keep `BIND_ADDR` on `127.0.0.1`. Do not port-forward it.
- Leave `ANTHROPIC_API_KEY` and `XAI_API_KEY` out of the service. Do not print, copy, or commit credential files.
- Write the unit or plist under the user's config directory. Leave `deploy/` in the repo unchanged.
- On Linux, install the user service. Use the system unit in the README only when the person asked for a dedicated `local-grok-bots` account.
- On macOS, install a LaunchAgent. A LaunchDaemon runs as root, and the daemon will exit.
- Ask before `sudo`, before enabling or replacing a service, and before choosing a non-loopback address. When this user has no sudo, or does not want to enter a password, do not run `sudo` at all. Follow "Without sudo".

## Without sudo

The per-user install does not need root.

- When `go` is missing or older than 1.24, install a newer Go under `$HOME/.local/go`, as in step 1. Leave any system Go in place.
- The daemon binary stays in `$HOME/.local/bin`.
- On Linux, the systemd user unit does not need sudo. On macOS, the LaunchAgent does not need sudo.
- Skip `loginctl enable-linger`. It asks for an administrator. The daemon then runs after this user logs in, or in the foreground.
- Skip the system unit in the README. `useradd`, `/usr/local/bin`, and `/etc/systemd/system` need root.

Linux CLI turns need `bwrap` from the distro package `bubblewrap`. Installing that package needs an administrator. When `bwrap` is missing and this user has no sudo, build and start the daemon anyway. Tell them CLI turns fail closed until an administrator installs `bubblewrap`. Leave the jail in place. Do not download a `bwrap` binary, and do not build a private copy. A home-built copy can still be blocked by AppArmor.

Ollama `run_shell` can use `unshare` when `command -v unshare` prints a path. When that fails too, the kernel is blocking unprivileged user namespaces. An administrator has to allow them.

When `systemctl --user` cannot connect, start the foreground process in step 4. One process owns port 8080. Stop it before enabling the service.

## 1. Check the machine

Run these and keep the answers:

```bash
id -u
uname -s
go env GOVERSION
command -v go
command -v claude
```

Stop when any of these is true:

- `id -u` prints `0`. Ask for a normal user account.
- `go env GOVERSION` is missing or older than `go1.24`. Install Go under `$HOME/.local/go` as below, then check again. Stop if it is still older than `go1.24`.
- `command -v claude` prints nothing. Ask the person to install Claude Code as this user, without sudo. A global install into a root-owned prefix needs privileges this user may not have. Start again after `command -v claude` prints a path.

On Linux, CLI turns need `command -v bwrap` to print a path. When it is missing and this user can use sudo, ask, then install the distro package named `bubblewrap` and check again. When this user has no sudo, follow "Without sudo" and keep going. The daemon looks up `bwrap` on its own `PATH`, so the service `PATH` below also needs `dirname "$(command -v bwrap)"` when that directory is not already listed.

On macOS, `command -v sandbox-exec` must print a path. It ships at `/usr/bin/sandbox-exec`. When it is missing, stop. Do not substitute a Linux VM or Docker.

Record `cli_dir=$(dirname "$(command -v claude)")`. The daemon looks up `claude` on its own `PATH`. A user service does not load `.bashrc`.

### Go without sudo

Ask the person to download a Go 1.24 or newer archive from https://go.dev/dl/ for this `uname -s` and `uname -m`. `x86_64` uses `amd64`. `aarch64` and `arm64` use `arm64`. Do not pipe an installer into a shell.

The archive contains a top-level `go` directory. Extract it into the home directory:

```bash
mkdir -p "$HOME/.local"
tar -C "$HOME/.local" -xzf /path/to/the-archive.tar.gz
export PATH="$HOME/.local/go/bin:$PATH"
```

`go env GOVERSION` must then print `go1.24` or newer. This Go builds the daemon. It is not on the bot shell PATH. The jail does not add home directories. A bot that runs `go` by name needs Go on a system prefix such as `/usr/local/go`, which an administrator installs.

## 2. Confirm login

```bash
claude auth status
```

Exit 0 means this user has a stored login. Use the `authMethod` field and ignore the rest of the output. Do not print tokens, email addresses, or file contents.

- Exit 0 and `authMethod` is `claude.ai`, `oauth_token`, or another stored login: continue.
- Exit 1, `authMethod` is `none`, or the subcommand is not recognized: stop and ask the person to run `claude auth login` in a terminal. Continue after they say it finished.
- `authMethod` is `api_key` and the only credential is `ANTHROPIC_API_KEY` in the shell: stop. The daemon clears that variable. Ask the person to run `claude auth login` so the credential is stored under `~/.claude`.

Do not open credential files. Do not put the key in the service.

## 3. Build

From the repo root:

```bash
mkdir -p "$HOME/.local/bin"
go build -o "$HOME/.local/bin/local-grok-bots" ./cmd/local-grok-bots
```

The binary is `"$HOME/.local/bin/local-grok-bots"`.

## 4. Install the service

### Linux

```bash
mkdir -p "$HOME/.local/share/local-grok-bots" "$HOME/.config/systemd/user"
chmod 700 "$HOME/.local/share/local-grok-bots"
```

If `$HOME/.config/systemd/user/local-grok-bots.service` already exists, stop and show it. Ask before replacing it.

Write that path with this unit. `PATH` starts with the `cli_dir` from step 1, then the standard directories. Skip a duplicate of `cli_dir` when it is already one of those directories. Do not put `$HOME` on `PATH`.

```ini
[Unit]
Description=Local Grok Bots
After=network-online.target

[Service]
Type=simple
ExecStart=%h/.local/bin/local-grok-bots
WorkingDirectory=%h/.local/share/local-grok-bots
Environment=HOME=%h
Environment=DATA_DIR=%h/.local/share/local-grok-bots
Environment=BIND_ADDR=127.0.0.1:8080
Environment=OLLAMA_URL=http://127.0.0.1:11434
Environment=OLLAMA_MODEL=llama3.2
Environment=CLI_BACKEND=claude
Environment=PATH=CLI_DIR:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
```

Leave `ProtectHome` unset so the service can read `~/.claude`.

Ask, then enable it:

```bash
systemctl --user daemon-reload
systemctl --user enable --now local-grok-bots
```

The service starts at login. Ask before `loginctl enable-linger`. Skip linger when this user has no sudo.

When `systemctl --user` cannot connect to the user bus, do not start it with sudo. Run the daemon in the foreground. Replace `CLI_DIR` with `cli_dir`, and prepend the `bwrap` directory when it is not already listed:

```bash
mkdir -p "$HOME/.local/share/local-grok-bots"
chmod 700 "$HOME/.local/share/local-grok-bots"
PATH="CLI_DIR:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
HOME="$HOME" \
DATA_DIR="$HOME/.local/share/local-grok-bots" \
BIND_ADDR=127.0.0.1:8080 \
OLLAMA_URL=http://127.0.0.1:11434 \
OLLAMA_MODEL=llama3.2 \
CLI_BACKEND=claude \
"$HOME/.local/bin/local-grok-bots"
```

The process logs to that terminal and stops when the process stops. Do not also enable the service while it is running.

### macOS

```bash
mkdir -p "$HOME/Library/Application Support/local-grok-bots" "$HOME/Library/Logs" "$HOME/Library/LaunchAgents"
chmod 700 "$HOME/Library/Application Support/local-grok-bots"
```

If `$HOME/Library/LaunchAgents/com.local-grok-bots.plist` already exists, stop and show it. Ask before replacing it.

```bash
sed "s|__HOME__|$HOME|g" deploy/com.local-grok-bots.plist > "$HOME/Library/LaunchAgents/com.local-grok-bots.plist"
```

Edit only that installed copy. Set the `ProgramArguments` string to `$HOME/.local/bin/local-grok-bots`. Inside the existing `EnvironmentVariables` dict, add:

```xml
<key>CLI_BACKEND</key>
<string>claude</string>
<key>PATH</key>
<string>CLI_DIR:/usr/local/bin:/usr/bin:/bin</string>
```

`PATH` starts with `cli_dir`. When `/opt/homebrew/bin` exists, put `/opt/homebrew/bin:/opt/homebrew/sbin` after `cli_dir`.

Ask, then load it:

```bash
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.local-grok-bots.plist"
```

When bootstrap says the service is already loaded, stop and ask. Do not `bootout` a running agent unless the person asked.

When this user cannot load a LaunchAgent, run the foreground command below. A rejected plist is a different failure. Fix the installed copy and run bootstrap again.

```bash
mkdir -p "$HOME/Library/Application Support/local-grok-bots"
chmod 700 "$HOME/Library/Application Support/local-grok-bots"
PATH="CLI_DIR:/usr/local/bin:/usr/bin:/bin" \
HOME="$HOME" \
DATA_DIR="$HOME/Library/Application Support/local-grok-bots" \
BIND_ADDR=127.0.0.1:8080 \
OLLAMA_URL=http://127.0.0.1:11434 \
OLLAMA_MODEL=llama3.2 \
CLI_BACKEND=claude \
"$HOME/.local/bin/local-grok-bots"
```

Add `/opt/homebrew/bin:/opt/homebrew/sbin` after `CLI_DIR` when those directories exist. Replace `CLI_DIR` with `cli_dir`. Do not also load the LaunchAgent while this process is running.

## 5. Check that it serves

```bash
curl -fsS http://127.0.0.1:8080/api/health
```

A working daemon returns JSON with `"status":"ok"`.

When curl cannot connect, read the log and stop. A foreground process logs to its terminal.

- Linux service: `journalctl --user -u local-grok-bots -n 50 --no-pager`
- macOS LaunchAgent: `"$HOME/Library/Logs/local-grok-bots.log"`

`refusing to run as root` means the service user is wrong. Fix the unit. Do not weaken the check.

When port 8080 is taken, ask before changing `BIND_ADDR`. An address other than loopback needs `AUTH_TOKEN` in the installed unit. Ask the person for the token. Do not invent one, and do not write it into the repo.

## 6. Hand back the page

Tell the person to open http://127.0.0.1:8080 and create the bot from the page. New bots use Claude Code because `CLI_BACKEND=claude`. A bot cannot create bots, send DMs, or set timers.

Ollama is optional. CLI bots do not call it. To also run Ollama bots, set `OLLAMA_MODEL` in the installed unit, or in the foreground environment, to a name that `ollama list` shows. Restart the daemon after that.

## 7. Policy and optional controls

The daemon loads a central Policy at startup. Defaults leave the single-user path unchanged: CLI network stays open, both backends are allowed, and pins, audit, and the prompt check are off.

For an airgapped or restricted machine, create `DATA_DIR/policy.yaml` (or set `POLICY_FILE`) before the next restart. The README has the full table of `POLICY_*` variables and a ready-to-copy airgap example:

```yaml
force_local_only: true
cli_network: none
allow_cli_backends: []
cli_net_allow: []
default_net_allow: []
env_allowlist: []
```

Other optional controls (all off unless set):

- Binary pins (`cli_pins` / `POLICY_CLI_PINS`) — fail closed if the resolved `claude` binary does not match the path, SHA-256, or version.
- Structured audit log (`audit_log` / `POLICY_AUDIT_LOG`) — JSON lines for CLI start/stop, network decisions, and grant events.
- Prompt check (`dlp_patterns`, `dlp_file`, `dlp_command`) — reject a CLI turn before the process starts.

`GET /api/policy` returns the loaded value. Details, required destinations, EDR notes, and residual risk are in `docs/sandbox.md` and `docs/plans/2026-10-13-enterprise-residual.md`. Ask before writing a policy file if the person has not asked for one.

## Done when

- Health returns `"status":"ok"`.
- The daemon process is this user, as the user service, the LaunchAgent, or the foreground process.
- When a unit or plist is installed, it sets `CLI_BACKEND=claude`, and its `PATH` includes `cli_dir`.
- `deploy/` in the repo is unchanged.
- The person has the page URL.
- When `bwrap` is missing, the person has been told that CLI turns fail closed until an administrator installs `bubblewrap`.
- The person knows the Policy exists and where the airgap example and full knobs live, even if no policy file was written.
