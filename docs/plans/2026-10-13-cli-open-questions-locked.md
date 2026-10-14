# Locked decisions: stream format, history, injection

These three open questions from the experiment README are closed for the middle-ground design.

## 1. Headless output format

The daemon requires the streaming structured format:

- Claude: `--output-format stream-json` (with `--include-partial-messages` when available)
- Grok: `--output-format streaming-json`

The runner parses the stream for:

- text deltas → SSE `token` events
- tool-use blocks → SSE `tool_call` / `tool_result` (arguments redacted)
- final result object → stored reply

If the stream ends without a final result (process killed, truncated, or crash), the daemon uses whatever text was already captured and marks the run `error` / `interrupted`. It does not scrape unstructured stdout. Batch JSON is not the primary path; it may be used only as a fallback when a CLI build does not emit the streaming format.

## 3. Session history projection

The daemon store is the source of truth for the web thread.

- Live stream events (tokens, tool calls, final reply) are written to the daemon's SQLite thread as they arrive.
- The CLI's on-disk transcript (`~/.claude/projects/...` JSONL or `~/.grok/sessions/`) is secondary. The daemon does not parse it for backfill or display.
- On daemon restart, the web thread shows what was already persisted. A resume after restart continues the CLI session, but historical messages that were never captured into the daemon store are not reconstructed from the CLI files.

This avoids version-fragile JSONL parsing and keeps the web UI independent of CLI internal formats.

## 4. Timer injection channel

Timer injection is resume-with-prompt only.

When a timer fires, the daemon spawns (or resumes) the CLI with the routine prompt prefixed `[scheduled]`. No append-only file, Unix socket, or other side channel is required or implemented. The resume invocation is the injection. This keeps the daemon thin and avoids extra doors into the CLI's sandbox.

## Permission mode

`permission_mode` is a policy setting. Its value is supplied by managed settings or by the local policy file after the InfoSec conversation. The daemon does not invent a default. An empty or missing value fails the CLI turn (fail-closed). Unattended timers are possible only when InfoSec has approved a mode that allows them.

## Status

The three questions above are locked. Permission mode is a configurable policy field, not an open design question.
