# Set up local-grok-bots with the Grok CLI

Follow this from a checkout of this repo, as the user who will run the daemon. Stop at each "Ask" line and wait for that person.

Prompt you can paste: `Follow docs/setup/grok.md and stop whenever it says to ask me.`

This installs a personal daemon. Login stays in this user's `~/.grok`. The daemon does not pass `XAI_API_KEY` through to a bot turn. New bots use the Grok CLI.

## Rules

- Run the daemon as this user. It refuses to start as root.
- Keep `BIND_ADDR` on `127.0.0.1`. Do not port-forward it.
- Leave `XAI_API_KEY` and `ANTHROPIC_API_KEY` out of the service. Do not print, copy, or commit credential files.
- Write the unit or plist under the user's config directory. Leave `deploy/` in the repo unchanged.
- On Linux, install the user service. Use the system unit in the README only when the person asked for a dedicated `local-grok-bots` account.
- On macOS, install a LaunchAgent. A LaunchDaemon runs as root, and the daemon will exit.
- Ask before `sudo`, before enabling or replacing a service, and before choosing a non-loopback address.

## 1. Check the machine

Run these and keep the answers:

```bash
id -u
uname -s
go env GOVERSION
command -v go
command -v grok
```

Stop when any of these is true:

- `id -u` prints `0`. Ask for a normal user account.
- `go env GOVERSION` is missing or older than `go1.24`. Send the person to https://go.dev/dl/ and stop. Do not pipe an installer into a shell.
- `command -v grok` prints nothing. Ask the person to install the Grok CLI from https://x.ai/cli, then start again.

On Linux, `command -v bwrap` must print a path. CLI turns fail closed without it. When it is missing, ask, then install the distro package named `bubblewrap` and check again. The daemon looks up `bwrap` on its own `PATH`, so the service `PATH` below also needs `dirname "$(command -v bwrap)"` when that directory is not already listed.

On macOS, `command -v sandbox-exec` must print a path. It ships at `/usr/bin/sandbox-exec`. When it is missing, stop. Do not substitute a Linux VM or Docker.

Record `cli_dir=$(dirname "$(command -v grok)")`. The daemon looks up `grok` on its own `PATH`. A user service does not load `.bashrc`.

## 2. Confirm login

Ask the person to confirm that `grok login` has already finished in this user's account. When it has not, stop and ask them to run `grok login` in a terminal. Continue after they say it finished.

Do not run login unattended. Do not open files under `~/.grok` to look for a token. A key that exists only in the shell is not visible to a bot turn.

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
Environment=CLI_BACKEND=grok
Environment=PATH=CLI_DIR:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
```

Leave `ProtectHome` unset so the service can read `~/.grok`.

Ask, then enable it:

```bash
systemctl --user daemon-reload
systemctl --user enable --now local-grok-bots
```

The service starts at login. Ask before `loginctl enable-linger`. Linger is a separate choice.

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
<string>grok</string>
<key>PATH</key>
<string>CLI_DIR:/usr/local/bin:/usr/bin:/bin</string>
```

`PATH` starts with `cli_dir`. When `/opt/homebrew/bin` exists, put `/opt/homebrew/bin:/opt/homebrew/sbin` after `cli_dir`.

Ask, then load it:

```bash
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.local-grok-bots.plist"
```

When bootstrap says the service is already loaded, stop and ask. Do not `bootout` a running agent unless the person asked.

## 5. Check that it serves

```bash
curl -fsS http://127.0.0.1:8080/api/health
```

A working daemon returns JSON with `"status":"ok"`.

When curl cannot connect, read the log and stop:

- Linux: `journalctl --user -u local-grok-bots -n 50 --no-pager`
- macOS: `"$HOME/Library/Logs/local-grok-bots.log"`

`refusing to run as root` means the service user is wrong. Fix the unit. Do not weaken the check.

When port 8080 is taken, ask before changing `BIND_ADDR`. An address other than loopback needs `AUTH_TOKEN` in the installed unit. Ask the person for the token. Do not invent one, and do not write it into the repo.

## 6. Hand back the page

Tell the person to open http://127.0.0.1:8080 and create the bot from the page. New bots use Grok because `CLI_BACKEND=grok`. A bot cannot create bots, send DMs, or set timers.

Ollama is optional. CLI bots do not call it. To also run Ollama bots, set `OLLAMA_MODEL` in the installed unit to a name that `ollama list` shows, then restart the service.

## Done when

- Health returns `"status":"ok"`.
- The daemon process is this user.
- The installed unit or plist sets `CLI_BACKEND=grok`, and its `PATH` includes `cli_dir`.
- `deploy/` in the repo is unchanged.
- The person has the page URL.
