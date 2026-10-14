# CLI enterprise controls (carry-forward)

These controls from `experiment/cli-sessions-from-846d81` (`docs/sandbox.md`, `docs/audit.md`, and the Process section of `docs/specs.md`) remain useful in the middle-ground design where the daemon does not re-jail the CLI. They are independent of any outer jail and can be driven from policy.toml (or managed settings).

Precedence remains: managed settings > policy.toml > built-in defaults. Missing or unparseable policy falls back to the strictest backend choice (daemon jail ON, CLI backends OFF) and logs loudly.

## Binary pins (`cli_pins`)

Optional supply-chain check of the exact `claude` or `grok` binary before exec. A pin can name an absolute path, a SHA-256 of the resolved file, a version token, or any combination. Prefer path + hash. A version-only pin runs `--version` with a cleared environment. A mismatch fails the turn. No pin keeps the current launch (whatever is on PATH).

## DLP / prompt scan

Optional checks of the prompt before a CLI turn starts. A match or non-zero scanner exit fails the turn and does not start the CLI.

- `dlp_patterns`: Go regular expressions (or literals).
- `dlp_file`: absolute path to a rules file (literals or `re:` lines).
- `dlp_command`: absolute executable, no arguments, text on stdin, `PATH` only. Exit 0 allows; any other exit rejects. 5-second timeout.

Default is off. Prompts are not written to logs.

## Audit log for CLI events

Optional `audit_log` sink (`stderr`, `syslog`, or absolute file path). When set, the daemon emits JSON lines for:

- `cli_start`: pid, backend, session_id, cli_network (if applicable)
- `cli_stop`: same fields plus result (`ok` / `error` / `interrupted`)

Redaction applies (proxy userinfo, API keys, etc.). Empty leaves the sink off. The store log is unchanged.

## Turn timeout

Optional `turn_timeout` (seconds or Go duration). When set, a CLI turn ends at that deadline in addition to the idle kill and daemon shutdown. Default empty keeps the existing behavior (idle/shutdown govern; shell stays 30s; Ollama stays 10m). Ceiling 24h. The event is `turn_timeout` when the deadline fires.

## Backend allow-list

Policy can list the backends that are permitted. A backend not on the list fails the turn. Default allows `ollama`, `claude`, and `grok` so existing installs keep working.

## Ollama model allow-list

Optional companion to the backend allow-list. Under `[ollama]`, a `models` list restricts which model names the daemon will request from the local Ollama. A model not on the list fails the turn. Empty (default) allows any model the local Ollama serves. Useful when the enterprise wants to limit which weights can run, independent of the CLI path.

Example:
```toml
[ollama]
host = "http://127.0.0.1:11434"
model = "llama3.1"
models = ["llama3.1", "qwen2.5-coder:7b", "gemma2"]
```

A bot-level model override is still checked against the same list. The list is names only; it does not pull or hash model blobs.

## Fail-closed

If the chosen CLI binary is missing, or its own sandbox cannot start, the turn fails. The daemon still serves. This is unchanged from the prior experiment and remains the rule when daemon jail is off.

## What is intentionally not carried forward

Outer-jail network modes, extra read-only binds, resource limits, and the shell grant model stay on the Ollama path only. They are not required when the CLI's own sandbox is the boundary.
