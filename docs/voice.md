# Voice (daemon)

`POST /api/stt` transcribes audio with a local whisper.cpp binary. It is off
until policy sets `[voice] enabled = true`. The route uses the same
authentication as the other `/api` routes. `GET /api/health` stays open.
There is no remote speech service. A missing binary, a missing model, or an
unset pair returns 503 and does not call anything else.

The request body is raw PCM: 16 kHz, mono, signed 16-bit little-endian.
`Content-Type` is `application/octet-stream`.
A success response is JSON `{"text":"..."}`. The transcript is the response
body only. It is not written to the log or the audit sink.

| Result | When |
| --- | --- |
| 401 | A token is configured and the request has none |
| 403 | Voice is disabled, or a configured binary or model path failed its file check. An audit row is still written |
| 415 | `Content-Type` is not `application/octet-stream` |
| 403 | `Sec-Fetch-Site` is present and is not `same-origin` or `none`, or `Origin` is present and is not this request's scheme and host. An audit row is written. The message is `forbidden` |
| 413 | The body exceeds `max_body_bytes`, or the PCM is longer than `max_audio_seconds` |
| 400 | The body is shorter than one sample, or its length is odd |
| 429 | That user is over `max_requests_per_hour`. The message is `speech recognition rate limit exceeded` |
| 429 | A transcription is already running and the 2 second wait elapsed. The message is `speech recognition is busy` |
| 408 | The body was not fully read before the read deadline (30 seconds), or the request context ended while waiting to read it |
| 408 | The request context ended while waiting for the transcription slot (the client went away, or the 60 second limit elapsed). Whisper is not started. The status is 408 Request Timeout |
| 503 | Whisper is unset, or the binary or model file is missing. The message is `speech recognition is not available` |
| 502 | The local binary ran and failed. The message is `speech recognition failed` |

The request must send `Content-Type: application/octet-stream`. The body is
read only after the enabled, content-type, site, and rate-limit checks. At
most two bodies are read at once. The read itself has a 30 second deadline.

The rate limit is a rolling hour, keyed by the token name (`default` for
`AUTH_TOKEN`). It is checked before the body is read. The hour counts a
request only when it is accepted: a success, a 502, or a 503. A 400, 403,
413, 415, busy 429, or 408 does not count. The rate-limit 429 itself is the
check failing, so it does not count either. A limit of zero or less denies
the request. Audio longer than the cap is rejected before whisper runs.

One transcription runs at a time. A second request waits up to 2 seconds
for that slot, then returns 429. If the request context ends while it is
still waiting, the response is 408 Request Timeout and whisper is not
started. 499 is not used.

When voice is enabled, `bin` and `model` (or `WHISPER_BIN` and
`WHISPER_MODEL`, whichever pair is in effect) are checked at startup and
again when policy is reloaded. Each path must be a regular file, not a
symlink, owned by root or the daemon user, and not group- or other-writable.
The parent directory has the same owner and mode rules and must not be a
symlink. If a check fails, voice is off for requests, `/api/stt` returns 403,
and a warning names the setting (`voice.bin`, `voice.model`, `WHISPER_BIN`,
or `WHISPER_MODEL`). A missing file stays 503. Both files and their parent
directories are included in the protected-path snapshot. Error responses do
not include server paths. A missing binary or model is logged on the daemon
log only.

## Policy

Precedence matches the rest of the daemon: managed settings, then
`policy.toml`, then the built-in default. `[voice]` keys:

| Key | Default | Hard range |
| --- | --- | --- |
| `enabled` | false | boolean |
| `bin` | unset | absolute path, with `model` |
| `model` | unset | absolute path, with `bin` |
| `max_audio_seconds` | 240 | 1 to 86400 |
| `max_body_bytes` | 8388608 (8 MiB) | 1 to 67108864 (64 MiB) |
| `max_requests_per_hour` | 60 | 1 to 100000 |

`bin` and `model` are one setting. One without the other, a relative path,
or an empty string makes the file unparseable. Environment `WHISPER_BIN` and
`WHISPER_MODEL` are the same pair. When policy sets either path, both
environment values are replaced and a warning names the override.

Managed policy may set ceilings in `[managed]`:

- `max_voice_audio_seconds`
- `max_voice_body_bytes`
- `max_voice_requests_per_hour`

A ceiling in `policy.toml` is ignored after its range is checked, with a
warning that only managed policy can set it. A `[voice]` value above a
managed ceiling is lowered to that ceiling and warned, for example
`voice.max_audio_seconds 600 lowered to managed max_voice_audio_seconds 30`.
A value already within the ceiling is not warned. Zero means no ceiling was
set. The effective limit is the `[voice]` value, or the default, then the
ceiling when the ceiling is greater than zero.

Unknown keys, the wrong type, zero, a negative number, or a value above the
hard range fail-close the file that contains them. The daemon keeps serving
with CLI backends off, the same way as any other unparseable policy. A
managed value that differs from a non-empty environment variable refuses
startup when `conflict_policy` is `refuse`.

## Audit

Every request that passes authentication writes a log row of kind `stt` and,
when an audit sink is configured, an audit record with `action` `stt`. The
fields are `who`, `bytes`, `code`, and `duration_ms` when the whole body was
read. `duration_ms` is omitted when the body was not fully read, including a
body rejected for size. The transcript, the PCM, and whisper's own output
are not fields.

## TLS

HTTPS is optional and uses the listener that `BIND_ADDR` or `[daemon] bind`
already opened. The daemon calls `ServeTLS` on that listener. It does not
open a second one.

`TLS_CERT` and `TLS_KEY` are a pair of PEM files. `TLS_KEY` is a file path.
`TLS_SELF_SIGNED=1` writes `DATA_DIR/tls/cert.pem` and `DATA_DIR/tls/key.pem`
as mode 0600, owned by the daemon user. The write uses a new file in that
directory and then renames it into place. An existing pair is reused only
when both paths are regular files, the certificate parses, and it has at
least 30 days left. A shorter or unparseable certificate is written again.
Reused files are tightened to 0600. Symlinks are not reused. A cert without
a key, or a key without a cert, refuses startup. A supplied `tls_key` or
`TLS_KEY` that is a symlink, or that is group- or other-readable, refuses
startup and the error names that setting. Self-signed mode is not combined
with a cert pair. The certificate names are `localhost`, `127.0.0.1`, and
`::1`, plus the bind address when that address is one specific IP. The
process prints `listening on` only after this TLS setup has succeeded.

`[daemon]` may set `tls_cert`, `tls_key`, and `tls_self_signed`. Any one of
those keys replaces the whole TLS setting: the unset siblings become empty
or false. Policy wins over the environment and warns. Managed policy that
disagrees with a non-empty `TLS_CERT`, `TLS_KEY`, or `TLS_SELF_SIGNED`
refuses startup. Operator-supplied cert files are not chmodded. Only the
generated or reused self-signed files are mode 0600.

## Permission callback

Claude's MCP permission tool needs a plain HTTP origin. When the main
listener is HTTPS, that origin is a separate loopback listener. The listener
starts only when the effective backend is Claude, `claude_transport` is
`mcp` (the default), and at least one bot is stored. An empty transport
counts as `mcp`. Ollama, Grok, `stream_control`, and `none` do not listen.
With no such bot, nothing listens and no other feature uses the port.

The address is `PERM_CALLBACK_ADDR`, or `[daemon] perm_callback_addr`, or
`127.0.0.1:0`. Policy replaces the environment. The host must be `127.0.0.1`
or `::1`. An IPv4-mapped IPv6 address is read as its IPv4 form, so
`::ffff:127.0.0.1` is accepted and other mapped addresses are not. The port
is a number from 0 through 65535. Other addresses, including the rest of
`127.0.0.0/8`, `localhost`, `0.0.0.0`, and `::`, are rejected. After the
socket is bound, an address outside that rule closes it and the error is
returned. Creating or deleting a bot starts or stops the listener. Reloading
a policy file does the same when the effective backend or transport changes.
A bind failure at startup, when a matching bot already exists, refuses
startup. A bind failure while creating a bot is logged as
`perm_callback_error` and the bot is still created.

The callback accepts only `POST /api/mcp/permission` and
`POST /api/mcp/permission/{token}`. Other paths and methods are 404. While
the main listener is plain HTTP, MCP keeps using that listener's origin.
While it is HTTPS, MCP uses the callback origin, which is empty until the
listener is up.
