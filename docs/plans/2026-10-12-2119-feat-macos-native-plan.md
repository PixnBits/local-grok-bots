# Native macOS

The daemon, confined CLI turns, and the workspace shell jail run on macOS. Linux stays on bubblewrap, then unshare. A LaunchAgent plist sits next to the systemd unit.

Session-settled: same product, chosen over "page only" and "fail closed until a later jail".

## Decisions

- The macOS jail is `sandbox-exec` (Seatbelt). It is deprecated and still the mechanism Codex and Claude Code use. Missing `sandbox-exec`, the turn fails closed. The deprecation warning is stripped from captured stderr.
- macOS cannot bind-mount. The shell's working directory and `HOME` are the workspace directory, not `/work`. The CLI's `HOME` is the user home so `~/.grok` and `~/.claude` persist. The profile allows writes only under those login directories, `.claude.json`, the workspace, and a private temp directory.
- The shell still has no network of its own. libc `connect` goes through the existing proxy via a `DYLD_INSERT_LIBRARIES` interposer. Seatbelt allows only that proxy socket. Platform binaries ignore the interposer and strip `DYLD_*`; the launcher copies and ad-hoc signs `/bin/sh` and the libc tools it needs so the interposer stays loaded. A connect the interposer does not see is denied.
- Grants, the git and ssh wrappers, hook and rc rollback, and build binds keep their current meaning. Wrappers use `$LGB_ROOT` so Linux can keep mounting that tree at `/lgb`.
- `PATH` may include `/opt/homebrew/bin` and `/opt/homebrew/sbin` when those directories exist. Home directories are still not added.
- The LaunchAgent runs as the logged-in user. The daemon still refuses root. CLI login stays in that user's home. `osascript` notifications already exist.

## Out

- A Linux VM, Docker, or a rewrite of the unshare jail.
- Remapping the workspace to the literal path `/work` on macOS.
- App Sandbox entitlements or a signed helper.
- Replacing Seatbelt when Apple removes `sandbox-exec`.

## Units

### U1. Seatbelt profile

Pure profile text. Deny by default. Read-only system prefixes. Write only the paths the caller lists. Network is either open (CLI) or a unix socket (shell proxy).

### U2. Workspace shell on macOS

`Run` launches `sandbox-exec` on darwin and bubblewrap or unshare on linux. Same grant events.

### U3. CLI confinement on macOS

A CLI turn runs under `sandbox-exec` with a cleared environment, network open, and the login directories as the only home writes.

### U4. LaunchAgent and docs

`deploy/com.local-grok-bots.plist`. README and `docs/specs.md` describe both platforms.

## Tests

- Profile text denies the default, writes the workspace, does not write the rest of the home, and does not open the network unless asked.
- Linux `go test ./...` stays green, including the `/work` jail checks.
- `GOOS=darwin go test -c` compiles every package.
- On a Mac, the existing jail tests run against `sandbox-exec`: host files and `/etc/passwd` stay unreadable, `..` and host temp writes fail, the net allowlist still dials only through the proxy.
